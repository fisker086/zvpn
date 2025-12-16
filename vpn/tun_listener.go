package vpn

import (
	"log"
	"net"
	"strings"
)

// listenTUNDevice listens for packets on the TUN device and forwards them to the appropriate client
func (s *VPNServer) listenTUNDevice(tunDevice *TUNDevice) {
	// Use packet pool to reduce GC pressure
	buf := GetPacketBuffer()
	defer PutPacketBuffer(buf)

	// Get server VPN IP (prefer TUN device IP for multi-server support)
	var serverVPNIP net.IP
	_, ipNet, _ := net.ParseCIDR(s.config.VPN.Network)
	if s.tunDevice != nil {
		if tunIP, err := s.tunDevice.GetIP(); err == nil {
			serverVPNIP = tunIP
		}
	}
	if serverVPNIP == nil {
		// Fallback to configured gateway IP
		serverVPNIP = make(net.IP, len(ipNet.IP))
		copy(serverVPNIP, ipNet.IP)
		serverVPNIP[len(serverVPNIP)-1] = 1
	}
	serverVPNIPStr := serverVPNIP.String()

	log.Printf("TUN device listener started, server VPN IP: %s, VPN network: %s",
		serverVPNIPStr, s.config.VPN.Network)

	// 优化说明：
	// TUN设备工作原理：从TUN读取的数据包是内核路由后的结果
	// - VPN客户端发送的数据包写入TUN后，内核会路由
	// - 如果目标是VPN内部，内核会路由回TUN（我们能读取到）
	// - 如果目标是外部，内核会直接通过eth0发送（不会从TUN读取到）

	log.Printf("TUN: Starting to read from TUN device (server VPN IP: %s)", serverVPNIPStr)
	for {
		// Read packet from TUN device (packets routed by kernel to TUN)
		// This is a blocking read - it will wait until a packet is available
		n, err := tunDevice.Read(buf)
		if err != nil {
			log.Printf("TUN: Error reading from TUN device: %v", err)
			continue
		}

		// Always log when we read something from TUN (for debugging)
		if n > 0 {
			log.Printf("TUN: Read %d bytes from TUN device", n)
		}

		if n < 20 { // Skip invalid packets
			// Log errors always (not sampled)
			previewLen := n
			if previewLen > 16 {
				previewLen = 16
			}
			LogPacketAlways("TUN: Received packet too small (%d bytes), skipping. First %d bytes: %x", n, previewLen, buf[:previewLen])
			continue
		}

		// Log packet info with sampling (reduced logging for performance)
		previewLen := n
		if previewLen > 32 {
			previewLen = 32
		}
		LogPacket("TUN: Read %d bytes from TUN device, first %d bytes: %x", n, previewLen, buf[:previewLen])

		// Check if it's an IPv4 packet
		ipVersion := buf[0] >> 4
		if ipVersion != 4 {
			LogPacket("TUN: Received non-IPv4 packet (version: %d, size: %d bytes), skipping", ipVersion, n)
			continue
		}

		// Extract source and destination IPs
		if n < 20 {
			LogPacketAlways("TUN: Packet too small for IP header (%d bytes), skipping. First %d bytes: %x", n, n, buf[:n])
			continue
		}
		srcIP := net.IP(buf[12:16])
		dstIP := net.IP(buf[16:20])
		protocol := buf[9]

		// Always log ICMP packets for debugging
		if protocol == 1 { // ICMP
			log.Printf("TUN: Read %d bytes (ICMP) from TUN device - src=%s, dst=%s",
				n, srcIP.String(), dstIP.String())
		} else {
			// Log packet details with sampling for other protocols
			LogPacket("TUN: Read %d bytes from TUN device - src=%s, dst=%s, protocol=%d",
				n, srcIP.String(), dstIP.String(), protocol)
		}

		// Case 1: Packet TO the server's VPN IP (VPN client -> server OR external -> server)
		if dstIP.Equal(serverVPNIP) {
			// All packets to server VPN IP should be processed by kernel
			// This includes packets from VPN clients AND packets from external sources (e.g., container pinging 10.8.0.1)
			// The kernel will recognize 10.8.0.1 as a local IP and generate appropriate responses
			if ipNet.Contains(srcIP) {
				// VPN客户端访问服务器 - 所有协议（ICMP、TCP、UDP、HTTP等）都由内核处理
				// 包写入TUN后，内核会处理并生成响应（如ICMP echo reply、TCP SYN-ACK等）
				// 响应会再次从TUN读取到（Case 2），然后转发回客户端
				if protocol == 1 { // ICMP - always log for debugging
					log.Printf("TUN: Received ICMP packet from VPN client %s to server %s, writing to TUN for kernel processing",
						srcIP.String(), dstIP.String())
				} else {
					LogPacket("TUN: Received packet from VPN client %s to server %s (protocol: %d), writing back to TUN for kernel processing",
						srcIP.String(), dstIP.String(), protocol)
				}
			} else {
				// External source (e.g., container) accessing server VPN IP
				// Write back to TUN so kernel can process and generate response
				if protocol == 1 { // ICMP - always log for debugging
					log.Printf("TUN: Received ICMP packet from external source %s to server %s, writing to TUN for kernel processing",
						srcIP.String(), dstIP.String())
				} else {
					LogPacket("TUN: Received packet from external source %s to server %s (protocol: %d), writing to TUN for kernel processing",
						srcIP.String(), dstIP.String(), protocol)
				}
			}
			if _, err := tunDevice.Write(buf[:n]); err != nil {
				LogPacketAlways("TUN: Failed to write packet back to TUN for server processing: %v", err)
			} else {
				if protocol == 1 { // ICMP - always log for debugging
					log.Printf("TUN: Successfully wrote ICMP packet to TUN, waiting for kernel to generate response")
				} else {
					LogPacket("TUN: Successfully wrote packet back to TUN, waiting for kernel to generate response")
				}
				// 成功写回，等待内核处理
				// 内核会生成响应，响应会再次从TUN读取到
			}
			continue
		}

		// Case 2: Packet FROM server VPN IP TO VPN client (server response)
		if srcIP.Equal(serverVPNIP) && ipNet.Contains(dstIP) {
			// 服务器响应VPN客户端 - 通过VPN隧道转发（不写回，避免循环）
			if protocol == 1 { // ICMP - always log for debugging
				log.Printf("TUN: ICMP response from server %s to VPN client %s, forwarding via tunnel",
					srcIP.String(), dstIP.String())
			} else {
				LogPacket("TUN: Response from server %s to VPN client %s (protocol: %d), forwarding via tunnel",
					srcIP.String(), dstIP.String(), protocol)
			}
			if err := s.ForwardPacketToClient(dstIP, buf[:n]); err != nil {
				// Check if error is due to client disconnection (expected)
				errMsg := err.Error()
				if strings.Contains(errMsg, "no client found") ||
					strings.Contains(errMsg, "not connected") ||
					strings.Contains(errMsg, "is closing") ||
					strings.Contains(errMsg, "write channel closed") {
					// Client disconnected - this is expected, don't log as error
					// Only log at debug level for ICMP packets
					if protocol == 1 {
						LogPacket("TUN: Client %s disconnected, skipping ICMP packet forwarding", dstIP.String())
					}
				} else {
					// Other errors should be logged
					LogPacketAlways("Failed to forward server response to VPN client %s: %v", dstIP.String(), err)
				}
			} else {
				if protocol == 1 { // ICMP - always log for debugging
					log.Printf("TUN: Successfully forwarded ICMP response to VPN client %s", dstIP.String())
				}
			}
			continue
		}

		// Case 3: Packet between VPN clients (client-to-client)
		if ipNet.Contains(srcIP) && ipNet.Contains(dstIP) {
			// VPN客户端间通信 - 直接转发（最优路径，不经过eth0和eBPF）
			// 不写回TUN，避免循环和性能损失
			if protocol == 1 { // ICMP - always log for debugging
				log.Printf("TUN: Case 3 - ICMP packet between VPN clients: %s -> %s, forwarding via tunnel",
					srcIP.String(), dstIP.String())
			}
			if err := s.ForwardPacketToClient(dstIP, buf[:n]); err != nil {
				// Check if error is due to client disconnection (expected)
				if strings.Contains(err.Error(), "no client found") ||
					strings.Contains(err.Error(), "not connected") ||
					strings.Contains(err.Error(), "is closing") ||
					strings.Contains(err.Error(), "write channel closed") {
					// Client disconnected - this is expected, don't log as error
					if protocol == 1 { // ICMP - always log for debugging
						log.Printf("TUN: Case 3 - Client %s disconnected, skipping ICMP packet forwarding", dstIP.String())
					} else {
						LogPacket("TUN: Client %s disconnected, skipping packet forwarding", dstIP.String())
					}
				} else {
					// Other errors should be logged
					if protocol == 1 { // ICMP - always log for debugging
						log.Printf("TUN: Case 3 - Failed to forward ICMP packet from VPN client %s to %s: %v",
							srcIP.String(), dstIP.String(), err)
					} else {
						LogPacketAlways("Failed to forward packet from VPN client %s to %s: %v",
							srcIP.String(), dstIP.String(), err)
					}
				}
			} else {
				if protocol == 1 { // ICMP - always log for debugging
					log.Printf("TUN: Case 3 - Successfully forwarded ICMP packet from VPN client %s to %s",
						srcIP.String(), dstIP.String())
				}
			}
			continue
		}

		// Case 4: External packet TO VPN client (external -> VPN client)
		if !ipNet.Contains(srcIP) && ipNet.Contains(dstIP) {
			// 外部访问VPN客户端 - 通过VPN隧道转发（不写回）
			if err := s.ForwardPacketToClient(dstIP, buf[:n]); err != nil {
				// Check if error is due to client disconnection (expected)
				if strings.Contains(err.Error(), "no client found") ||
					strings.Contains(err.Error(), "not connected") ||
					strings.Contains(err.Error(), "is closing") ||
					strings.Contains(err.Error(), "write channel closed") {
					// Client disconnected - this is expected, don't log as error
					LogPacket("TUN: Client %s disconnected, skipping packet forwarding", dstIP.String())
				} else {
					// Other errors should be logged
					LogPacketAlways("Failed to forward external packet to VPN client %s: %v", dstIP.String(), err)
				}
			}
			continue
		}

		// Case 5: Packet from VPN client to external network
		// 注意：正常情况下不应该从TUN读取到，因为内核会直接通过eth0发送
		// 但如果路由配置有问题可能会读取到，需要写回让内核重新路由
		if ipNet.Contains(srcIP) && !ipNet.Contains(dstIP) {
			LogPacketAlways("Warning: VPN client %s accessing external %s via TUN (should route via eth0)",
				srcIP.String(), dstIP.String())
			// 写回TUN让内核重新路由（这种情况应该很少发生）
			if _, err := tunDevice.Write(buf[:n]); err != nil {
				LogPacketAlways("Failed to write packet back to TUN for external routing: %v", err)
			}
			continue
		}

		// Unknown case - log for debugging (always log unknown cases)
		LogPacketAlways("TUN: Unhandled packet: src=%s, dst=%s, protocol=%d",
			srcIP.String(), dstIP.String(), protocol)
	}
}

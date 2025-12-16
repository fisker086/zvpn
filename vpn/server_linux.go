//go:build linux

package vpn

import (
	"log"
	"net"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// ============================================================================
// Batch TUN Device Listener (Linux only)
// ============================================================================

// getBatchListener returns the batch listener function for Linux
func getBatchListener() func(*VPNServer, *TUNDevice) {
	return func(s *VPNServer, tunDevice *TUNDevice) {
		s.listenTUNDeviceBatch(tunDevice)
	}
}

// listenTUNDeviceBatch listens for packets on TUN device with batch processing
// This is an optimized version that uses epoll for better performance
func (s *VPNServer) listenTUNDeviceBatch(tunDevice *TUNDevice) {
	// Get server VPN IP from config
	_, ipNet, _ := net.ParseCIDR(s.config.VPN.Network)
	serverVPNIP := make(net.IP, len(ipNet.IP))
	copy(serverVPNIP, ipNet.IP)
	serverVPNIP[len(serverVPNIP)-1] = 1

	log.Printf("TUN device batch listener started (optimized), server VPN IP: %s, VPN network: %s",
		serverVPNIP.String(), s.config.VPN.Network)

	// Create epoll instance for efficient I/O
	epfd, err := unix.EpollCreate1(0)
	if err != nil {
		log.Printf("Warning: Failed to create epoll instance: %v, falling back to regular listener", err)
		s.listenTUNDevice(tunDevice)
		return
	}
	defer unix.Close(epfd)

	// Add TUN device to epoll
	tunFd := int(tunDevice.file.Fd())
	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(tunFd),
	}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, tunFd, &event); err != nil {
		log.Printf("Warning: Failed to add TUN device to epoll: %v, falling back to regular listener", err)
		s.listenTUNDevice(tunDevice)
		return
	}

	// Worker pool for parallel packet processing
	const numWorkers = 4
	packetChan := make(chan []byte, 100) // Buffered channel for packets
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for packet := range packetChan {
				s.processPacketFromTUN(packet, serverVPNIP, ipNet, tunDevice)
			}
		}(i)
	}

	// Batch read loop
	events := make([]unix.EpollEvent, 10)
	buf := GetPacketBuffer()
	defer PutPacketBuffer(buf)

	for {
		// Wait for events (with timeout for graceful shutdown)
		n, err := unix.EpollWait(epfd, events, 100) // 100ms timeout
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			log.Printf("TUN: EpollWait error: %v", err)
			break
		}

		// Process events
		for i := 0; i < n; i++ {
			if events[i].Fd == int32(tunFd) {
				// Read packet from TUN device
				readBuf := GetPacketBuffer()
				readN, err := tunDevice.Read(readBuf)
				if err != nil {
					PutPacketBuffer(readBuf)
					LogPacketAlways("TUN: Error reading from TUN device: %v", err)
					continue
				}

				if readN < 20 {
					PutPacketBuffer(readBuf)
					continue
				}

				// Copy packet data and send to worker
				packet := make([]byte, readN)
				copy(packet, readBuf[:readN])
				PutPacketBuffer(readBuf)

				// Send to worker pool (non-blocking)
				select {
				case packetChan <- packet:
				default:
					// Channel full, drop packet (shouldn't happen with proper sizing)
					LogPacketAlways("TUN: Packet channel full, dropping packet")
				}
			}
		}
	}

	// Close channel and wait for workers
	close(packetChan)
	wg.Wait()
	log.Printf("TUN device batch listener stopped")
}

// processPacketFromTUN processes a single packet from TUN device
// This is extracted from listenTUNDevice for reuse in batch processing
func (s *VPNServer) processPacketFromTUN(packet []byte, serverVPNIP net.IP, ipNet *net.IPNet, tunDevice *TUNDevice) {
	s.processPacket(packet, serverVPNIP, ipNet, tunDevice, "TUN")
}

// ============================================================================
// AF_XDP Zero-Copy Listener (Linux only)
// ============================================================================

// getAFXDPListener returns the AF_XDP listener function for Linux
func getAFXDPListener() func(*VPNServer, *XDPSocket) {
	return func(s *VPNServer, xdpSocket *XDPSocket) {
		s.listenAFXDP(xdpSocket)
	}
}

// listenAFXDP listens for packets from AF_XDP socket (zero-copy mode)
func (s *VPNServer) listenAFXDP(xdpSocket *XDPSocket) {
	// Get server VPN IP from config
	_, ipNet, _ := net.ParseCIDR(s.config.VPN.Network)
	serverVPNIP := make(net.IP, len(ipNet.IP))
	copy(serverVPNIP, ipNet.IP)
	serverVPNIP[len(serverVPNIP)-1] = 1

	LogPacketAlways("AF_XDP listener started (zero-copy mode), server VPN IP: %s, VPN network: %s",
		serverVPNIP.String(), s.config.VPN.Network)

	// Use epoll for efficient I/O
	epfd, err := unix.EpollCreate1(0)
	if err != nil {
		LogPacketAlways("AF_XDP: Failed to create epoll: %v, using polling mode", err)
		s.listenAFXDPPolling(xdpSocket, ipNet, serverVPNIP)
		return
	}
	defer unix.Close(epfd)

	// Add AF_XDP socket to epoll
	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(xdpSocket.fd),
	}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, xdpSocket.fd, &event); err != nil {
		LogPacketAlways("AF_XDP: Failed to add socket to epoll: %v, using polling mode", err)
		s.listenAFXDPPolling(xdpSocket, ipNet, serverVPNIP)
		return
	}

	events := make([]unix.EpollEvent, 128)
	buf := GetPacketBuffer()
	defer PutPacketBuffer(buf)

	for {
		numEvents, err := unix.EpollWait(epfd, events, -1)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			LogPacketAlways("AF_XDP: EpollWait error: %v", err)
			break
		}

		for i := 0; i < numEvents; i++ {
			if events[i].Fd == int32(xdpSocket.fd) {
				// Read packets from AF_XDP socket
				for {
					n, err := xdpSocket.Read(buf)
					if err != nil {
						if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
							break // No more packets
						}
						LogPacketAlways("AF_XDP: Error reading packet: %v", err)
						break
					}

					if n > 0 {
						s.processPacketFromAFXDP(buf[:n], ipNet, serverVPNIP)
					} else {
						break
					}
				}
			}
		}
	}

	LogPacketAlways("AF_XDP listener stopped")
}

// listenAFXDPPolling listens using polling (fallback when epoll fails)
func (s *VPNServer) listenAFXDPPolling(xdpSocket *XDPSocket, ipNet *net.IPNet, serverVPNIP net.IP) {
	buf := GetPacketBuffer()
	defer PutPacketBuffer(buf)

	for {
		n, err := xdpSocket.Read(buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			LogPacketAlways("AF_XDP: Error reading packet: %v", err)
			break
		}

		if n > 0 {
			s.processPacketFromAFXDP(buf[:n], ipNet, serverVPNIP)
		}
	}
}

// processPacketFromAFXDP processes a packet received from AF_XDP socket
func (s *VPNServer) processPacketFromAFXDP(buf []byte, ipNet *net.IPNet, serverVPNIP net.IP) {
	// AF_XDP doesn't have a TUNDevice to write back to, so pass nil
	s.processPacket(buf, serverVPNIP, ipNet, nil, "AF_XDP")
}

// ============================================================================
// Common Packet Processing Logic
// ============================================================================

// packetSource represents where the packet came from
type packetSource interface {
	Write([]byte) (int, error)
}

// processPacket is the unified packet processing function used by both TUN and AF_XDP
func (s *VPNServer) processPacket(packet []byte, serverVPNIP net.IP, ipNet *net.IPNet, source packetSource, sourceName string) {
	n := len(packet)
	if n < 20 {
		return
	}

	// Check if it's an IPv4 packet
	ipVersion := packet[0] >> 4
	if ipVersion != 4 {
		return
	}

	// Extract source and destination IPs
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])
	protocol := packet[9]

	// Case 1: Packet TO the server's VPN IP
	if dstIP.Equal(serverVPNIP) {
		if source != nil {
			// Write back to source (TUN device) for kernel processing
			if ipNet.Contains(srcIP) {
				LogPacket("%s: Received packet from VPN client %s to server %s, writing to %s for kernel processing",
					sourceName, srcIP.String(), dstIP.String(), sourceName)
			} else {
				LogPacket("%s: Received packet from external source %s to server %s, writing to %s for kernel processing",
					sourceName, srcIP.String(), dstIP.String(), sourceName)
			}
			if _, err := source.Write(packet); err != nil {
				LogPacketAlways("%s: Failed to write packet back to %s for server processing: %v", sourceName, sourceName, err)
			}
		} else {
			// AF_XDP: write to TUN if available
			if s.tunDevice != nil {
				LogPacket("%s: External packet to server %s from %s, writing to TUN for kernel processing",
					sourceName, dstIP.String(), srcIP.String())
				if _, err := s.tunDevice.Write(packet); err != nil {
					LogPacketAlways("%s: Failed to write packet to TUN: %v", sourceName, err)
				}
			}
		}
		return
	}

	// Case 2: Packet FROM server VPN IP TO VPN client (server response)
	if srcIP.Equal(serverVPNIP) && ipNet.Contains(dstIP) {
		LogPacket("%s: Response from server %s to VPN client %s, forwarding via tunnel",
			sourceName, srcIP.String(), dstIP.String())
		if err := s.ForwardPacketToClient(dstIP, packet); err != nil {
			s.handleForwardError(err, dstIP, sourceName)
		}
		return
	}

	// Case 3: Packet between VPN clients (client-to-client)
	if ipNet.Contains(srcIP) && ipNet.Contains(dstIP) {
		LogPacket("%s: VPN client-to-client packet %s -> %s, forwarding",
			sourceName, srcIP.String(), dstIP.String())
		if err := s.ForwardPacketToClient(dstIP, packet); err != nil {
			s.handleForwardError(err, dstIP, sourceName)
		}
		return
	}

	// Case 4: External packet TO VPN client (external -> VPN client)
	if !ipNet.Contains(srcIP) && ipNet.Contains(dstIP) {
		LogPacket("%s: External packet to VPN client %s from %s, forwarding via tunnel",
			sourceName, dstIP.String(), srcIP.String())
		if err := s.ForwardPacketToClient(dstIP, packet); err != nil {
			s.handleForwardError(err, dstIP, sourceName)
		}
		return
	}

	// Case 5: Packet from VPN client to external network
	if ipNet.Contains(srcIP) && !ipNet.Contains(dstIP) {
		if source != nil {
			// TUN: write back for kernel routing
			LogPacketAlways("%s: Warning: VPN client %s accessing external %s via %s (should route via eth0)",
				sourceName, srcIP.String(), dstIP.String(), sourceName)
			if _, err := source.Write(packet); err != nil {
				LogPacketAlways("%s: Failed to write packet back to %s for external routing: %v", sourceName, sourceName, err)
			}
		} else {
			// AF_XDP: this shouldn't happen, log and ignore
			LogPacketAlways("%s: Warning: VPN client %s to external %s via %s (should come through OpenConnect)",
				sourceName, srcIP.String(), dstIP.String(), sourceName)
		}
		return
	}

	// Unknown case
	LogPacketAlways("%s: Unhandled packet: src=%s, dst=%s, protocol=%d",
		sourceName, srcIP.String(), dstIP.String(), protocol)
}

// handleForwardError handles errors from ForwardPacketToClient
func (s *VPNServer) handleForwardError(err error, dstIP net.IP, sourceName string) {
	errMsg := err.Error()
	if strings.Contains(errMsg, "no client found") ||
		strings.Contains(errMsg, "not connected") ||
		strings.Contains(errMsg, "is closing") ||
		strings.Contains(errMsg, "write channel closed") {
		// Client disconnected - this is expected, don't log as error
		LogPacket("%s: Client %s disconnected, skipping packet forwarding", sourceName, dstIP.String())
	} else {
		// Other errors should be logged
		LogPacketAlways("%s: Failed to forward packet to VPN client %s: %v", sourceName, dstIP.String(), err)
	}
}

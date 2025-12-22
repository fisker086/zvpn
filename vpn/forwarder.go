package vpn

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
)

// PacketForwarder handles packet forwarding between VPN clients and target networks
type PacketForwarder struct {
	rawConn     *net.IPConn
	clients     map[uint]*net.IPAddr // VPN IP -> Client connection address
	clientsLock sync.RWMutex
	enabled     bool
}

// NewPacketForwarder creates a new packet forwarder
func NewPacketForwarder() (*PacketForwarder, error) {
	// Create raw IP socket for packet forwarding
	// Note: Requires root privileges on Linux
	conn, err := net.ListenPacket("ip4:ip", "0.0.0.0")
	if err != nil {
		// If raw socket fails, use regular forwarding (requires root)
		log.Printf("Warning: Failed to create raw socket: %v", err)
		log.Printf("Packet forwarding will use user-space mode")
		return &PacketForwarder{
			enabled: false,
			clients: make(map[uint]*net.IPAddr),
		}, nil
	}

	ipConn, ok := conn.(*net.IPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("failed to cast to IPConn")
	}

	return &PacketForwarder{
		rawConn: ipConn,
		clients: make(map[uint]*net.IPAddr),
		enabled: true,
	}, nil
}

// RegisterClient registers a VPN client for packet forwarding
func (pf *PacketForwarder) RegisterClient(userID uint, vpnIP net.IP, clientAddr *net.IPAddr) {
	pf.clientsLock.Lock()
	defer pf.clientsLock.Unlock()
	pf.clients[userID] = clientAddr
}

// UnregisterClient unregisters a VPN client
func (pf *PacketForwarder) UnregisterClient(userID uint) {
	pf.clientsLock.Lock()
	defer pf.clientsLock.Unlock()
	delete(pf.clients, userID)
}

// IsEnabled returns whether the packet forwarder is enabled
func (pf *PacketForwarder) IsEnabled() bool {
	return pf.enabled
}

// ForwardToNetwork forwards a packet from VPN client to target network
func (pf *PacketForwarder) ForwardToNetwork(packet []byte, dstIP net.IP) error {
	if !pf.enabled || pf.rawConn == nil {
		// Fallback: use system routing (requires proper network setup)
		return fmt.Errorf("raw socket forwarding not available")
	}

	// Parse IP header to get destination
	if len(packet) < 20 {
		return fmt.Errorf("packet too short")
	}

	// Create destination address
	dstAddr := &net.IPAddr{IP: dstIP}

	// Write packet to raw socket
	// The kernel will route it based on routing table
	_, err := pf.rawConn.WriteToIP(packet, dstAddr)
	if err != nil {
		return fmt.Errorf("failed to forward packet: %w", err)
	}

	return nil
}

// ForwardToClient forwards a packet from network to VPN client
func (pf *PacketForwarder) ForwardToClient(userID uint, packet []byte, clientConn net.Conn) error {
	// Validate packet length
	if len(packet) < 20 {
		return fmt.Errorf("packet too short")
	}

	// Check if this packet is for a registered VPN client
	pf.clientsLock.RLock()
	_, exists := pf.clients[userID]
	pf.clientsLock.RUnlock()

	if !exists {
		return fmt.Errorf("client not registered")
	}

	// Forward packet to client via SSL connection using CSTP format
	// Per OpenConnect spec draft-mavrogiannopoulos-openconnect-02:
	// Byte 0-2: 'S', 'T', 'F' (fixed)
	// Byte 3: 0x01 (fixed)
	// Byte 4-5: Length (BIG-ENDIAN) - length of payload that follows header (NOT including header)
	// Byte 6: Payload type (0x00 for DATA)
	// Byte 7: 0x00 (fixed)
	// Byte 8+: Payload
	header := make([]byte, 8) // STF (3) + Header (5)
	header[0] = 'S'
	header[1] = 'T'
	header[2] = 'F'
	header[3] = 0x01 // Version (fixed to 0x01)
	// Byte 4-5: Length (BIG-ENDIAN) - payload length only, NOT including header
	payloadLen := uint16(len(packet))
	binary.BigEndian.PutUint16(header[4:6], payloadLen)
	header[6] = 0x00 // Payload type (0x00 for DATA)
	header[7] = 0x00 // Reserved (fixed to 0x00)

	// Create full packet in one buffer
	fullPacket := make([]byte, len(header)+len(packet))
	copy(fullPacket, header)
	copy(fullPacket[8:], packet) // Payload starts at byte 8

	// Send full packet in one write operation
	_, err := clientConn.Write(fullPacket)
	if err != nil {
		return fmt.Errorf("failed to send packet to client: %w", err)
	}

	return nil
}

// StartPacketReceiver starts receiving packets from network
// vpnIPToUserGetter can be either a map[string]uint or a function that returns (uint, bool)
func (pf *PacketForwarder) StartPacketReceiver(vpnNetwork *net.IPNet, vpnIPToUserGetter interface{}, handler func(userID uint, packet []byte)) {
	if !pf.enabled || pf.rawConn == nil {
		return
	}

	go func() {
		// Use a reasonable buffer size (MTU + IP header)
		buf := make([]byte, 8192)
		for {
			n, _, err := pf.rawConn.ReadFromIP(buf)
			if err != nil {
				log.Printf("Error reading from raw socket: %v", err)
				continue
			}

			// Parse IP header
			if n < 20 {
				continue
			}

			// Extract destination IP
			dstIP := net.IP(buf[16:20])

			// Check if destination is in VPN network
			if !vpnNetwork.Contains(dstIP) {
				continue
			}

			// Find user ID by VPN IP
			userID := pf.findUserIDByVPNIP(dstIP, vpnIPToUserGetter)
			if userID == 0 {
				continue
			}

			// Create a copy of the packet to avoid issues with buffer reuse
			packet := make([]byte, n)
			copy(packet, buf[:n])

			// Call handler
			handler(userID, packet)
		}
	}()
}

// findUserIDByVPNIP finds user ID by VPN IP
// Supports both map[string]uint and func(string) (uint, bool)
func (pf *PacketForwarder) findUserIDByVPNIP(vpnIP net.IP, vpnIPToUserGetter interface{}) uint {
	ipStr := vpnIP.String()

	// Try function first (for sharded locks)
	if getter, ok := vpnIPToUserGetter.(func(string) (uint, bool)); ok {
		if userID, exists := getter(ipStr); exists {
			return userID
		}
		return 0
	}

	// Fallback to map (for non-sharded locks)
	if m, ok := vpnIPToUserGetter.(map[string]uint); ok {
		if userID, exists := m[ipStr]; exists {
			return userID
		}
		return 0
	}

	return 0
}

// Close closes the packet forwarder
func (pf *PacketForwarder) Close() error {
	if pf.rawConn != nil {
		return pf.rawConn.Close()
	}
	return nil
}

// EnableIPForwarding enables IP forwarding on the system
func EnableIPForwarding() error {
	// This requires root privileges
	// On Linux: echo 1 > /proc/sys/net/ipv4/ip_forward
	// Or use sysctl: sysctl -w net.ipv4.ip_forward=1

	file, err := os.OpenFile("/proc/sys/net/ipv4/ip_forward", os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open ip_forward: %w", err)
	}
	defer file.Close()

	if _, err := file.Write([]byte("1\n")); err != nil {
		return fmt.Errorf("failed to write ip_forward: %w", err)
	}

	log.Println("IP forwarding enabled successfully")
	return nil
}

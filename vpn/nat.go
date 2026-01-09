package vpn

import (
	"encoding/binary"
	"net"
)

// calculateIPChecksum calculates the IP header checksum
func calculateIPChecksum(header []byte) uint16 {
	if len(header) < 20 {
		return 0
	}

	// IP header length in 4-byte units
	ihl := int(header[0] & 0x0F)
	if ihl < 5 || len(header) < ihl*4 {
		return 0
	}

	var sum uint32
	// Sum all 16-bit words in IP header
	for i := 0; i < ihl*2; i++ {
		if i*2+1 < len(header) {
			sum += uint32(binary.BigEndian.Uint16(header[i*2 : i*2+2]))
		}
	}

	// Fold 32-bit sum to 16-bit
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// Take one's complement
	return ^uint16(sum)
}

// PerformUserSpaceNAT performs NAT masquerading in user space
// Modifies the packet in place: changes source IP and recalculates checksums
func (s *VPNServer) PerformUserSpaceNAT(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}

	// Check if it's IPv4
	if packet[0]>>4 != 4 {
		return false
	}

	// Get egress IP
	s.egressIPLock.RLock()
	egressIP := s.egressIP
	s.egressIPLock.RUnlock()

	if egressIP == nil {
		return false // No egress IP configured
	}

	// Extract source and destination IPs
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	// Get VPN network
	_, vpnNet, err := net.ParseCIDR(s.config.VPN.Network)
	if err != nil {
		return false
	}

	// Only perform NAT if source is VPN client and destination is external
	if !vpnNet.Contains(srcIP) || vpnNet.Contains(dstIP) {
		return false // Not a VPN client to external network packet
	}

	// Change source IP to egress IP
	copy(packet[12:16], egressIP.To4())

	// Recalculate IP checksum
	packet[10] = 0
	packet[11] = 0
	checksum := calculateIPChecksum(packet[:20])
	binary.BigEndian.PutUint16(packet[10:12], checksum)

	// Reset transport layer checksum (let kernel recalculate)
	protocol := packet[9]
	ipHeaderLen := int((packet[0] & 0x0F) * 4)

	if protocol == 6 { // TCP
		if len(packet) >= ipHeaderLen+16 {
			packet[ipHeaderLen+16] = 0
			packet[ipHeaderLen+17] = 0
		}
	} else if protocol == 17 { // UDP
		if len(packet) >= ipHeaderLen+6 {
			packet[ipHeaderLen+6] = 0
			packet[ipHeaderLen+7] = 0
		}
	} else if protocol == 1 { // ICMP
		if len(packet) >= ipHeaderLen+2 {
			packet[ipHeaderLen+2] = 0
			packet[ipHeaderLen+3] = 0
		}
	}

	return true // NAT performed
}


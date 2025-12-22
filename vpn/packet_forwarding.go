package vpn

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// ForwardPacketToClient forwards a packet from network to a specific OpenConnect client
// Always sends immediately to ensure packet boundaries are preserved
func (s *VPNServer) ForwardPacketToClient(dstIP net.IP, packet []byte) error {
	return s.forwardPacketImmediate(dstIP, packet)
}

// forwardPacketImmediate forwards a packet immediately without batching
func (s *VPNServer) forwardPacketImmediate(dstIP net.IP, packet []byte) error {
	// Find user ID by VPN IP
	dstIPStr := dstIP.String()
	userID, exists := s.getVPNIPUser(dstIPStr)
	if !exists {
		// Client may have disconnected - this is expected, don't log as error
		return fmt.Errorf("no client found for IP %s", dstIPStr)
	}

	// Get client
	client, exists := s.getClient(userID)
	if !exists || !client.Connected {
		return fmt.Errorf("client %d not connected", userID)
	}

	// Check if client is closing/disconnected by checking WriteClose channel
	select {
	case <-client.WriteClose:
		// Client is closing, don't try to send
		return fmt.Errorf("client %d is closing", userID)
	default:
		// Client is still active, continue
	}

	// Apply compression if enabled
	var compressedPacket []byte
	var useCompression bool
	if s.CompressionMgr != nil && s.config.VPN.EnableCompression {
		compressionType := CompressionType(s.config.VPN.CompressionType)
		if compressionType != CompressionNone {
			compressed, err := s.CompressionMgr.Compress(packet, compressionType)
			if err == nil && len(compressed) < len(packet) {
				compressedPacket = compressed
				useCompression = true
				if s.config.Server.Mode == "debug" {
					log.Printf("Compressed packet for client %d: %d -> %d bytes (%.1f%% reduction)",
						userID, len(packet), len(compressed), float64(len(packet)-len(compressed))/float64(len(packet))*100)
				}
			}
		}
	}
	if !useCompression {
		compressedPacket = packet
	}

	// Send packet using CSTP format (OpenConnect protocol)
	// Use memory pool optimized method
	// Server-to-client packets always use BIG-ENDIAN for length field (per spec)
	fullPacket, err := s.BuildCSTPPacket(compressedPacket)
	if err != nil {
		log.Printf("Error building CSTP packet: %v", err)
		return fmt.Errorf("failed to build CSTP packet: %w", err)
	}

	// CRITICAL: Copy the packet before sending to avoid buffer pool reuse issues
	// The buffer returned from BuildCSTPPacket is from a pool and may be reused
	// by other goroutines before the packet is actually sent over the network.
	// Copying ensures the packet data remains intact.
	packetCopy := make([]byte, len(fullPacket))
	copy(packetCopy, fullPacket)
	// Return the original buffer to the pool now that we have a copy
	s.PutPacketBuffer(fullPacket)

	// Send packet via channel to avoid blocking and ensure writes don't interfere with reads
	// If channel is full, wait a short time instead of immediately dropping
	select {
	case <-client.WriteClose:
		// Client is closing, don't try to send
		return fmt.Errorf("client %d is closing", userID)
	case client.WriteChan <- packetCopy:
		// Packet queued successfully
		if s.config.Server.Mode == "debug" {
			LogPacket("Successfully queued packet to client %d (IP: %s) write channel", userID, dstIP.String())
		}
		return nil
	default:
		// Channel is full, try waiting a short time
		select {
		case <-client.WriteClose:
			// Client closed during wait
			return fmt.Errorf("client write channel closed")
		case client.WriteChan <- packetCopy:
			if s.config.Server.Mode == "debug" {
				LogPacket("Successfully queued packet to client %d (IP: %s) after wait", userID, dstIP.String())
			}
			return nil
		case <-time.After(5 * time.Millisecond):
			// Still full after wait, drop packet
			LogPacketAlways("Warning: Write channel full for client %d (IP: %s), dropping packet", userID, dstIP.String())
			return fmt.Errorf("write channel full")
		}
	}
}

// ============================================================================
// CSTP Batch Forwarding
// ============================================================================

// CSTPBatchBuffer manages batch encapsulation of multiple IP packets into CSTP packets
type CSTPBatchBuffer struct {
	packets     [][]byte
	maxPackets  int
	maxSize     int
	currentSize int
	mu          sync.Mutex
}

// NewCSTPBatchBuffer creates a new batch buffer
func NewCSTPBatchBuffer(maxPackets, maxSize int) *CSTPBatchBuffer {
	if maxPackets <= 0 {
		maxPackets = 10 // Default: batch up to 10 packets
	}
	if maxSize <= 0 {
		maxSize = 8192 // Default: 8KB max batch size
	}
	return &CSTPBatchBuffer{
		packets:     make([][]byte, 0, maxPackets),
		maxPackets:  maxPackets,
		maxSize:     maxSize,
		currentSize: 0,
	}
}

// AddPacket adds a packet to the batch
// Returns true if batch is full and should be flushed
func (b *CSTPBatchBuffer) AddPacket(packet []byte) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	packetSize := len(packet)

	// Check if adding this packet would exceed limits
	if len(b.packets) >= b.maxPackets || b.currentSize+packetSize > b.maxSize {
		return true // Batch is full
	}

	b.packets = append(b.packets, packet)
	b.currentSize += packetSize
	return false
}

// GetPackets returns all packets and clears the buffer
func (b *CSTPBatchBuffer) GetPackets() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()

	packets := make([][]byte, len(b.packets))
	copy(packets, b.packets)
	b.packets = b.packets[:0]
	b.currentSize = 0
	return packets
}

// IsEmpty returns true if buffer is empty
func (b *CSTPBatchBuffer) IsEmpty() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.packets) == 0
}

// ForwardPacketsBatch forwards multiple packets to a client using batch CSTP encapsulation
// This reduces encapsulation overhead by batching multiple IP packets
func (s *VPNServer) ForwardPacketsBatch(dstIP net.IP, packets [][]byte) error {
	if len(packets) == 0 {
		return nil
	}

	// Find user ID by VPN IP
	userID, exists := s.getVPNIPUser(dstIP.String())
	if !exists {
		return fmt.Errorf("no client found for IP %s", dstIP.String())
	}

	// Get client
	client, exists := s.getClient(userID)
	if !exists || !client.Connected {
		return fmt.Errorf("client %d not connected", userID)
	}

	// For batch encapsulation, we send each packet separately but in quick succession
	// This reduces overhead compared to sending them one by one with delays
	// Note: True batch encapsulation (multiple packets in one CSTP frame) would require
	// client support, which OpenConnect may not have. So we send them sequentially but quickly.

	for _, packet := range packets {
		// Encapsulate each packet
		// Per OpenConnect spec draft-mavrogiannopoulos-openconnect-02:
		// Byte 0-2: 'S', 'T', 'F' (fixed)
		// Byte 3: 0x01 (fixed)
		// Byte 4-5: Length (BIG-ENDIAN) - length of payload that follows header (NOT including header)
		// Byte 6: Payload type (0x00 for DATA)
		// Byte 7: 0x00 (fixed)
		// Byte 8+: Payload
		header := make([]byte, 8) // STF (3) + Header (5)
		// Add "STF" prefix
		header[0] = 'S'
		header[1] = 'T'
		header[2] = 'F'
		header[3] = 0x01 // Version (fixed to 0x01)
		// Byte 4-5: Length (BIG-ENDIAN) - payload length only, NOT including header
		payloadLen := uint16(len(packet))
		binary.BigEndian.PutUint16(header[4:6], payloadLen)
		header[6] = 0x00 // Payload type (0x00 for DATA)
		header[7] = 0x00 // Reserved (fixed to 0x00)

		// Use packet pool
		packetSize := len(header) + len(packet)
		fullPacket := GetCSTPPacketBuffer()

		// Ensure we have enough space
		if cap(fullPacket) < packetSize {
			fullPacket = make([]byte, packetSize)
		} else {
			fullPacket = fullPacket[:packetSize]
		}

		// Copy header and payload
		copy(fullPacket, header)
		copy(fullPacket[len(header):], packet)

		// Verify packet format before sending
		if len(fullPacket) != packetSize {
			PutCSTPPacketBuffer(fullPacket)
			return fmt.Errorf("packet size mismatch: expected %d, got %d", packetSize, len(fullPacket))
		}

		// Verify length field matches expected payload size (BIG-ENDIAN at byte 4-5, after STF prefix)
		// The length field is at offset 4-5 (after 3-byte STF prefix + 1-byte version)
		// Length is payload length only, NOT including header
		if len(fullPacket) >= 8 && fullPacket[0] == 'S' && fullPacket[1] == 'T' && fullPacket[2] == 'F' {
			verifyLength := binary.BigEndian.Uint16(fullPacket[4:6])
			expectedLength := uint16(len(packet)) // Payload length only, NOT including header
			if verifyLength != expectedLength {
				PutCSTPPacketBuffer(fullPacket)
				return fmt.Errorf("length field mismatch: header says %d, expected %d", verifyLength, expectedLength)
			}
		}

		// Create a new slice for sending to avoid issues with buffer reuse
		sendPacket := make([]byte, packetSize)
		copy(sendPacket, fullPacket)
		PutCSTPPacketBuffer(fullPacket)

		// Send to client (non-blocking)
		select {
		case client.WriteChan <- sendPacket:
			// Success, packet will be sent by WriteLoop
		case <-time.After(10 * time.Millisecond):
			return fmt.Errorf("timeout sending batch packet to client %d", userID)
		}
	}

	return nil
}

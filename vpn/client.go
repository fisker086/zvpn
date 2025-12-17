package vpn

import (
	"encoding/binary"
	"log"
	"net"
	"time"
)

// WriteLoop handles writing packets to the client connection in a separate goroutine
// This ensures writes don't interfere with reads
// If write batching is enabled, it collects multiple packets and writes them in batches
func (c *VPNClient) WriteLoop() {
	defer func() {
		log.Printf("Write loop for client %d (IP: %s) stopped", c.UserID, c.IP.String())
	}()

	// Get config from server if available
	var enableBatching bool
	var batchSize int
	var batchTimeout time.Duration

	if c.server != nil && c.server.config != nil {
		enableBatching = c.server.config.VPN.EnableWriteBatching
		batchSize = c.server.config.VPN.WriteBatchSize
		batchTimeout = time.Duration(c.server.config.VPN.WriteBatchTimeout) * time.Millisecond
	} else {
		// Defaults: Disable batching by default to ensure CSTP packet boundaries
		// Batching can cause "Unknown packet received" errors with OpenConnect clients
		enableBatching = false
		batchSize = 1 // Process one packet at a time
		batchTimeout = 0 * time.Millisecond
	}

	// IMPORTANT: For CSTP protocol compatibility, disable batching if not explicitly enabled
	// Batching can cause packet boundary issues where multiple CSTP packets are merged
	// into a single TCP segment, causing OpenConnect clients to fail parsing.
	if !enableBatching {
		// Force single packet mode
		batchSize = 1
		batchTimeout = 0
	}

	// Validate batch size and timeout
	if batchSize <= 0 {
		batchSize = 10
	}
	if batchTimeout <= 0 {
		batchTimeout = 1 * time.Millisecond
	}

	if enableBatching {
		c.writeLoopBatched(batchSize, batchTimeout)
	} else {
		c.writeLoopSingle()
	}
}

// writeLoopSingle handles single packet writes (original behavior)
func (c *VPNClient) writeLoopSingle() {
	for {
		select {
		case packet, ok := <-c.WriteChan:
			if !ok {
				log.Printf("Write channel closed for client %d (IP: %s)", c.UserID, c.IP.String())
				return
			}
			// Check if connection is closing before processing packet
			select {
			case <-c.WriteClose:
				log.Printf("Write loop stopping for client %d (IP: %s): connection closing", c.UserID, c.IP.String())
				return
			default:
				c.writePacket(packet)
			}

		case <-c.WriteClose:
			return
		}
	}
}

// writeLoopBatched handles batched packet writes for better performance
func (c *VPNClient) writeLoopBatched(batchSize int, batchTimeout time.Duration) {
	batch := make([][]byte, 0, batchSize)
	ticker := time.NewTicker(batchTimeout)
	defer ticker.Stop()

	for {
		select {
		case packet, ok := <-c.WriteChan:
			if !ok {
				// Channel closed, flush any remaining packets
				if len(batch) > 0 {
					c.writeBatch(batch)
				}
				log.Printf("Write channel closed for client %d (IP: %s)", c.UserID, c.IP.String())
				return
			}

			batch = append(batch, packet)

			// Flush if batch is full
			if len(batch) >= batchSize {
				c.writeBatch(batch)
				batch = batch[:0] // Reset batch
			}

		case <-ticker.C:
			// Timeout: flush any accumulated packets
			if len(batch) > 0 {
				c.writeBatch(batch)
				batch = batch[:0] // Reset batch
			}

		case <-c.WriteClose:
			// Stop signal: don't flush remaining packets if connection is closing
			// Flushing would cause RST if client already sent FIN
			log.Printf("Write loop stopping for client %d (IP: %s): connection closing (dropping %d queued packets)",
				c.UserID, c.IP.String(), len(batch))
			return
		}
	}
}

// writePacket writes a single packet to the connection
func (c *VPNClient) writePacket(packet []byte) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	// Check if connection is closing before attempting write
	select {
	case <-c.WriteClose:
		// Connection is closing, don't write
		log.Printf("Skipping write to client %d (IP: %s): connection is closing", c.UserID, c.IP.String())
		return
	default:
		// Connection is still open, proceed with write
	}

	// Log packet details before writing (for debugging CSTP issues)
	// Check if packet has STF prefix (server-to-client packets now include STF prefix)
	if len(packet) >= 8 && packet[0] == 'S' && packet[1] == 'T' && packet[2] == 'F' {
		// Packet has STF prefix, CSTP header starts at offset 3
		// Format per BuildCSTPPacket: STF(3) + Version(1) + Length(2) + Type(1) + Reserved(1) + Payload
		// Byte 0-2: STF
		// Byte 3: Version (0x01)
		// Byte 4-5: Length (BIG-ENDIAN) - payload length only, NOT including header
		// Byte 6: Type (0x00)
		// Byte 7: Reserved (0x00)
		// Byte 8+: Payload
		payloadLength := binary.BigEndian.Uint16(packet[4:6]) // Length at byte 4-5
		// Total packet = STF(3) + Header(5) + Payload = 8 + payloadLength
		expectedTotalSize := 8 + int(payloadLength)

		// Verify CSTP length field matches expected size
		if expectedTotalSize != len(packet) {
			log.Printf("ERROR: CSTP length field mismatch! Header says payload is %d bytes (BIG-ENDIAN at byte 4-5), expected total %d bytes (8 header + %d payload), but packet is %d bytes. This will cause client parsing errors!",
				payloadLength, expectedTotalSize, payloadLength, len(packet))
		}
	}

	written := 0
	for written < len(packet) {
		n, err := c.Conn.Write(packet[written:])
		if err != nil {
			// Write error - connection is likely closed by client
			// This can happen when client sends FIN and we try to write after
			log.Printf("Failed to write packet to client %d (IP: %s): %v (wrote %d/%d bytes) - connection may be closed",
				c.UserID, c.IP.String(), err, written, len(packet))
			// Signal write loop to stop
			select {
			case <-c.WriteClose:
				// Already closed
			default:
				close(c.WriteClose)
			}
			return
		}
		written += n
	}

	// CRITICAL: Ensure TCP buffer is flushed immediately after writing
	// This prevents packets from being buffered and potentially merged, which can cause
	// client parsing errors. Each CSTP packet must be sent immediately and separately.
	//
	// For TCP connections, we ensure immediate sending by:
	// 1. TCP_NODELAY is already set in handler.go (disables Nagle algorithm) ✓
	// 2. Each packet is written in one operation (already done above) ✓
	// 3. Add a sufficient delay to ensure kernel sends the packet before next operation
	//
	// IMPORTANT: Even with TCP_NODELAY, TCP may still merge small writes in some cases,
	// especially if they happen very close together. A longer delay (10ms) ensures
	// the packet is sent and acknowledged before the next write operation.
	// This is critical for CSTP packets where each packet must be sent separately.
	// Increased delay to 10ms to better ensure packet boundaries are preserved.
	if tcpConn, ok := c.Conn.(*net.TCPConn); ok {
		// With TCP_NODELAY enabled, the write should be sent immediately
		// Add a longer delay to ensure kernel processes and sends the packet
		// This prevents multiple packets from being merged in the send buffer
		// Increased to 10ms to ensure packet is fully sent before next operation
		time.Sleep(10 * time.Millisecond) // 10 milliseconds - ensures packet is sent separately
		// Try to flush any remaining buffered data
		if err := tcpConn.SetWriteDeadline(time.Now().Add(1 * time.Millisecond)); err == nil {
			// Reset deadline immediately
			tcpConn.SetWriteDeadline(time.Time{})
		}
	}

	if written != len(packet) {
		log.Printf("Warning: Incomplete write to client %d (IP: %s): wrote %d/%d bytes",
			c.UserID, c.IP.String(), written, len(packet))
	}
}

// writeBatch writes multiple packets in a batch using writev-like approach
// For now, we write them sequentially but with a single lock acquisition
func (c *VPNClient) writeBatch(batch [][]byte) {
	if len(batch) == 0 {
		return
	}

	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	// Write all packets sequentially
	// Note: Go's net.Conn doesn't support writev directly, but we can optimize by
	// writing packets one after another with a single lock acquisition
	for _, packet := range batch {
		// Check if connection is closing before writing
		select {
		case <-c.WriteClose:
			// Connection is closing, stop writing batch
			log.Printf("Stopping batch write to client %d (IP: %s): connection is closing", c.UserID, c.IP.String())
			return
		default:
			// Connection is still open, proceed with write
		}

		// Log packet details before writing (for debugging CSTP issues)
		// Check if packet has STF prefix (server-to-client packets now include STF prefix)
		if len(packet) >= 8 && packet[0] == 'S' && packet[1] == 'T' && packet[2] == 'F' {
			// Packet has STF prefix, CSTP header starts at offset 3
			// Format per BuildCSTPPacket: STF(3) + Version(1) + Length(2) + Type(1) + Reserved(1) + Payload
			// Byte 0-2: STF
			// Byte 3: Version (0x01)
			// Byte 4-5: Length (BIG-ENDIAN) - payload length only, NOT including header
			// Byte 6: Type (0x00)
			// Byte 7: Reserved (0x00)
			// Byte 8+: Payload
			payloadLength := binary.BigEndian.Uint16(packet[4:6]) // Length at byte 4-5
			// Total packet = STF(3) + Header(5) + Payload = 8 + payloadLength
			expectedTotalSize := 8 + int(payloadLength)

			// Verify CSTP length field matches expected size
			if expectedTotalSize != len(packet) {
				log.Printf("ERROR: CSTP length field mismatch in batch! Header says payload is %d bytes (BIG-ENDIAN at byte 4-5), expected total %d bytes (8 header + %d payload), but packet is %d bytes. This will cause client parsing errors!",
					payloadLength, expectedTotalSize, payloadLength, len(packet))
			}
		}

		written := 0
		for written < len(packet) {
			n, err := c.Conn.Write(packet[written:])
			if err != nil {
				// Write error - connection is likely closed by client
				log.Printf("Failed to write batch packet to client %d (IP: %s): %v (wrote %d/%d bytes) - connection may be closed",
					c.UserID, c.IP.String(), err, written, len(packet))
				// Signal write loop to stop
				select {
				case <-c.WriteClose:
					// Already closed
				default:
					close(c.WriteClose)
				}
				return // Stop on first error
			}
			written += n
		}

		// CRITICAL: After each packet in batch, ensure it's sent immediately
		// This prevents packets from being merged in TCP buffer
		// With TCP_NODELAY enabled, each write should be sent immediately
		// Add a delay to ensure kernel processes and sends the packet
		if _, ok := c.Conn.(*net.TCPConn); ok {
			// Delay to ensure kernel sends the packet before next write
			// This is critical for CSTP packets where each packet must be sent separately
			// Increased to 5ms to ensure packet is fully sent before next operation
			time.Sleep(5 * time.Millisecond) // 5 milliseconds - ensures packet is sent separately
		}

		if written != len(packet) {
			log.Printf("Warning: Incomplete batch write to client %d (IP: %s): wrote %d/%d bytes",
				c.UserID, c.IP.String(), written, len(packet))
		}
	}

	// After writing all packets in batch, ensure all packets are sent
	// With TCP_NODELAY enabled, packets should be sent immediately
	// The tiny delays after each packet ensure kernel processes them separately

	// Log batch write (sampled)
	if len(batch) > 0 {
		totalBytes := 0
		for _, p := range batch {
			totalBytes += len(p)
		}
		LogPacket("Successfully wrote batch of %d packets (%d bytes) to client %d (IP: %s)",
			len(batch), totalBytes, c.UserID, c.IP.String())
	}
}

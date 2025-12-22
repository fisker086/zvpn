package openconnect

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"strings"
	"time"

	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/vpn"
	"github.com/fisker/zvpn/vpn/policy"
)

// min returns the minimum of two integers
// 使用math.Min提高性能和可读性
func min(a, b int) int {
	return int(math.Min(float64(a), float64(b)))
}

// CSTP Packet Types (per OpenConnect spec draft-mavrogiannopoulos-openconnect-02)
const (
	PacketTypeData       = 0x00 // DATA: IPv4 or IPv6 packet
	PacketTypeDPDReq     = 0x03 // DPD-REQ: dead peer detection request
	PacketTypeDPDResp    = 0x04 // DPD-RESP: dead peer detection response
	PacketTypeDisconnect = 0x05 // DISCONNECT: terminate session
	PacketTypeKeepalive  = 0x07 // KEEPALIVE: keep connection alive
	PacketTypeCompressed = 0x08 // COMPRESSED DATA: compressed data packet
	PacketTypeTerminate  = 0x09 // TERMINATE: server shutdown indication
	PacketTypeError      = 0x05 // Error packet from client (legacy, same as DISCONNECT)
	// Legacy aliases for backward compatibility
	PacketTypeDPD = PacketTypeDPDReq
)

// CSTP header length per spec: version(1) + length(2) + type(1) + reserved(1) = 5 bytes
// Total header with STF prefix: STF(3) + header(5) = 8 bytes
const cstpHeaderLen = 5        // CSTP header length (excluding STF prefix)
const cstpHeaderLenWithSTF = 8 // Total header length including STF prefix

// Maximum reasonable packet size: 1500 (MTU) + 8 (CSTP header) = 1508
// Allow up to 2000 for safety
const maxPacketSize = 2000

// CSTPParser is a stream parser for CSTP packets
type CSTPParser struct {
	buf             []byte // Buffer for accumulating data
	bufLen          int    // Current length of data in buffer
	state           parserState
	packetLen       uint16 // Length of current packet being parsed
	packetType      byte   // Type of current packet
	useLittleEndian bool   // Whether client uses little-endian for length field
}

type parserState int

const (
	stateNeedHeader parserState = iota
	stateNeedPayload
)

// TunnelClient represents an OpenConnect VPN tunnel client
type TunnelClient struct {
	User            *models.User
	Conn            net.Conn
	IP              net.IP
	VPNServer       *vpn.VPNServer
	TUNDevice       *vpn.TUNDevice
	parser          *CSTPParser
	useLittleEndian bool // Whether client uses little-endian for length field (detected from incoming packets)
}

// NewTunnelClient creates a new tunnel client
func NewTunnelClient(user *models.User, conn net.Conn, ip net.IP, vpnServer *vpn.VPNServer, tunDevice *vpn.TUNDevice) *TunnelClient {
	return &TunnelClient{
		User:      user,
		Conn:      conn,
		IP:        ip,
		VPNServer: vpnServer,
		TUNDevice: tunDevice,
		parser: &CSTPParser{
			buf:    make([]byte, maxPacketSize*2), // 减少缓冲区大小，只需要足够处理最大数据包的两倍
			bufLen: 0,
			state:  stateNeedHeader,
		},
	}
}

// HandleTunnelData handles VPN tunnel data - main loop for processing CSTP packets
// This function runs in a separate goroutine and handles all incoming CSTP packets from the client
func (tc *TunnelClient) HandleTunnelData() error {
	defer tc.Conn.Close()

	log.Printf("OpenConnect: Starting tunnel handler for user %s (IP: %s)", tc.User.Username, tc.IP.String())

	readBuf := make([]byte, 4096) // Read buffer
	timeoutCount := 0
	const maxTimeouts = 3

	for {
		// Set read timeout (30 seconds for normal packets)
		if err := tc.Conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return fmt.Errorf("failed to set read deadline: %w", err)
		}

		// Read data from connection
		n, err := tc.Conn.Read(readBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout - send keepalive
				timeoutCount++
				if timeoutCount >= maxTimeouts {
					log.Printf("OpenConnect: Too many timeouts for user %s", tc.User.Username)
					return fmt.Errorf("connection timeout")
				}

				// Send keepalive packet
				if err := tc.sendKeepalive(); err != nil {
					log.Printf("OpenConnect: Failed to send keepalive: %v", err)
				}
				continue
			}

			if err == io.EOF {
				log.Printf("OpenConnect: Client closed connection for user %s", tc.User.Username)
				return nil
			}

			log.Printf("OpenConnect: Read error for user %s: %v", tc.User.Username, err)
			return err
		}

		// Reset timeout count on successful read
		timeoutCount = 0

		// Log received data for debugging - 只在调试模式下启用
		// if n > 0 {
		//     previewLen := n
		//     if previewLen > 64 {
		//         previewLen = 64
		//     }
		//     log.Printf("OpenConnect: Received %d bytes from user %s (hex: %x)", n, tc.User.Username, readBuf[:previewLen])
		// }

		// Feed data to parser
		if err := tc.parser.feed(readBuf[:n]); err != nil {
			log.Printf("OpenConnect: Parser error: %v", err)
			return err
		}

		// Process all complete packets
		for {
			packet, err := tc.parser.nextPacket()
			if err == io.EOF {
				// No more complete packets, continue reading
				break
			}
			if err != nil {
				log.Printf("OpenConnect: Error parsing packet for user %s: %v", tc.User.Username, err)
				// Try to recover by resetting parser
				tc.parser.reset()
				break
			}

			// Note: We detect client's endianness for receiving packets, but server always uses BIG-ENDIAN for sending
			// No need to sync to VPNClient since server-to-client packets always use BIG-ENDIAN regardless of client preference

			// Log packet type for debugging (especially for ICMP packets)
			if packet.Type == PacketTypeData && len(packet.Payload) >= 20 {
				protocol := packet.Payload[9]
				if protocol == 1 { // ICMP
					icmpType := "unknown"
					if len(packet.Payload) >= 28 {
						switch packet.Payload[20] {
						case 0:
							icmpType = "echo reply"
						case 8:
							icmpType = "echo request"
						default:
							icmpType = fmt.Sprintf("type %d", packet.Payload[20])
						}
					}
					srcIP := net.IP(packet.Payload[12:16])
					dstIP := net.IP(packet.Payload[16:20])
					log.Printf("OpenConnect: Received ICMP %s packet from client %s (VPN IP: %s) to %s, payload length: %d",
						icmpType, tc.User.Username, srcIP.String(), dstIP.String(), len(packet.Payload))
				}
			}

			// Process packet
			if err := tc.processPacket(packet.Type, packet.Payload); err != nil {
				log.Printf("OpenConnect: Error processing packet type 0x%02x: %v", packet.Type, err)
				// For disconnect packets or format errors, return to close connection
				if packet.Type == PacketTypeDisconnect ||
					strings.Contains(err.Error(), "unknown packet format") ||
					strings.Contains(err.Error(), "reported unknown packet") {
					log.Printf("OpenConnect: Client requested disconnect or reported format error")
					return nil
				}
				// For other errors, continue processing
			}
		}
	}
}

// ParsedPacket represents a parsed CSTP packet
type ParsedPacket struct {
	Type    byte
	Payload []byte
}

// feed adds data to the parser buffer
func (p *CSTPParser) feed(data []byte) error {
	// Check if we have space
	if p.bufLen+len(data) > len(p.buf) {
		// Buffer overflow - this shouldn't happen with reasonable packet sizes
		log.Printf("OpenConnect: Parser buffer overflow (bufLen=%d, dataLen=%d)", p.bufLen, len(data))
		// Try to recover by clearing buffer and looking for next valid header
		p.reset()
		return nil
	}

	// Append data to buffer
	copy(p.buf[p.bufLen:], data)
	p.bufLen += len(data)
	return nil
}

// nextPacket extracts the next complete packet from the buffer
func (p *CSTPParser) nextPacket() (*ParsedPacket, error) {
	for {
		if p.state == stateNeedHeader {
			// Need to find a valid CSTP header (with STF prefix)
			if p.bufLen < cstpHeaderLenWithSTF {
				return nil, io.EOF // Not enough data
			}

			// Look for valid CSTP header starting from beginning of buffer
			// OpenConnect clients send "STF" prefix (3 bytes) + CSTP header (8 bytes) + payload
			// We need to search for "STF" prefix or CSTP header directly
			offset := 0
			foundValidHeader := false

			// Search through the buffer for a valid CSTP header
			// First try to find "STF" prefix, then validate the CSTP header after it
			// Start from offset 0 first (most common case)
			for offset <= p.bufLen-cstpHeaderLen {
				// Check if we have "STF" prefix at this offset
				if offset <= p.bufLen-3 && p.buf[offset] == 'S' && p.buf[offset+1] == 'T' && p.buf[offset+2] == 'F' {
					// Found "STF" prefix, CSTP header should be at offset+3
					cstpOffset := offset + 3
					if cstpOffset <= p.bufLen-cstpHeaderLen && p.buf[cstpOffset] == 0x01 {
						// Validate CSTP header per spec:
						// Byte 0 (cstpOffset+0): Version (0x01)
						// Byte 1-2 (cstpOffset+1-2): Length (BIG-ENDIAN) - payload length only
						// Byte 3 (cstpOffset+3): Payload type
						// Byte 4 (cstpOffset+4): Reserved (0x00)
						// Client-to-server packets use big-endian for length field per OpenConnect spec
						// However, some clients may send it in little-endian, so we try both
						packetLenBE := binary.BigEndian.Uint16(p.buf[cstpOffset+1 : cstpOffset+3])
						packetLenLE := binary.LittleEndian.Uint16(p.buf[cstpOffset+1 : cstpOffset+3])
						packetType := p.buf[cstpOffset+3]

						// Try big-endian first (per spec), fallback to little-endian if invalid
						// packetLen is payload length only (NOT including header)
						var packetLen uint16
						// Total packet size = STF(3) + Header(5) + Payload
						// So we need at least cstpHeaderLenWithSTF bytes, plus payload
						if packetLenBE <= maxPacketSize {
							packetLen = packetLenBE
						} else if packetLenLE <= maxPacketSize {
							packetLen = packetLenLE
							// Store preference for this client (for receiving packets only)
							// Note: Server always uses BIG-ENDIAN for sending packets regardless of client preference
							p.useLittleEndian = true
							log.Printf("OpenConnect: Using little-endian for length field (big-endian gave invalid length %d, little-endian gives %d)",
								packetLenBE, packetLenLE)
						} else {
							// Both are invalid, use big-endian for logging
							packetLen = packetLenBE
						}

						// Log raw header bytes for debugging
						if offset > 0 || packetType == PacketTypeError || packetLen > 500 {
							headerPreview := p.buf[cstpOffset:]
							previewLen := 16
							if len(headerPreview) < previewLen {
								previewLen = len(headerPreview)
							}
							// CSTP header detected - no logging needed for normal operation
						}

						// Validate packet length - payload length must be reasonable
						// Total packet size = STF(3) + Header(5) + Payload(packetLen)
						totalPacketSize := cstpHeaderLenWithSTF + int(packetLen)
						if packetLen <= maxPacketSize && totalPacketSize <= maxPacketSize+8 {
							// Additional validation: packet length should not exceed available buffer
							// This helps catch cases where the length field is corrupted
							availableBytes := p.bufLen - cstpOffset

							// Check if packet length is suspiciously large compared to available data
							// This indicates a corrupted header or error message
							if int(packetLen) > availableBytes+100 {
								// Packet length is way too large compared to available data
								// This might be a corrupted header or error message
								// Search for error message text in the buffer (limited to first 100 bytes for performance)
								searchStart := 0
								searchEnd := p.bufLen
								if searchEnd > 100 {
									searchEnd = 100 // Limit search range for performance
								}

								// Convert buffer slice to string for efficient error message detection
								bufferSlice := string(p.buf[searchStart:searchEnd])

								// Check if buffer contains potential error message keywords
								if strings.Contains(bufferSlice, "Unknown") ||
									strings.Contains(bufferSlice, "unknown") ||
									strings.Contains(bufferSlice, "packet") ||
									strings.Contains(bufferSlice, "received") {

									// Extract printable text from the buffer
									var text string
									textStart := -1
									textEnd := -1

									// Find start of printable text
									for i := searchStart; i < searchEnd; i++ {
										b := p.buf[i]
										if (b >= 32 && b < 127) || b == '\n' || b == '\r' {
											textStart = i
											break
										}
									}

									// Find end of printable text
									if textStart != -1 {
										textEnd = textStart
										for j := textStart; j < searchEnd && j < textStart+100; j++ {
											b := p.buf[j]
											if (b >= 32 && b < 127) || b == '\n' || b == '\r' || b == 0 {
												textEnd = j + 1
											} else {
												break
											}
										}

										// Extract and clean the text
										if textEnd > textStart {
											text = string(p.buf[textStart:textEnd])
											text = strings.TrimSpace(text)
										}
									}

									if text != "" {
										// Found error message
										log.Printf("OpenConnect: ⚠️ Detected error message instead of CSTP packet: %q (length field says %d but only %d bytes available)",
											text, packetLen, availableBytes)
										// Clear the buffer since we've processed this error message
										p.bufLen = 0
										p.state = stateNeedHeader
										// Return the error message as a special packet type
										// This will be handled by the caller
										return &ParsedPacket{
											Type:    PacketTypeError,
											Payload: []byte(text),
										}, nil
									}
								}

								// Invalid packet length - skip this potential header
								offset++
								continue
							}

							// Valid header found after "STF" prefix
							// Only remove bytes before the STF prefix if we found it at non-zero offset
							if offset > 0 {
								// Found STF at non-zero offset - remove bytes before it
								copy(p.buf, p.buf[offset:])
								p.bufLen -= offset
							}

							p.packetType = packetType
							// packetLen is payload length, total packet = STF(3) + Header(5) + Payload
							p.packetLen = uint16(cstpHeaderLenWithSTF + int(packetLen))
							p.state = stateNeedPayload
							// prefixLen := offset // offset is the distance from start to STF prefix
							foundValidHeader = true
							break
						} else {
							// Invalid packet length - log for debugging
							if offset > 0 {
								// Reset parser if we have invalid data
								p.reset()
								return nil, io.EOF
							}
						}
					}
				}

				// Also check if there's a CSTP header directly at this offset (without "STF" prefix)
				// This handles legacy format or cases where prefix might be missing or corrupted
				// NOTE: Modern OpenConnect always uses STF prefix, so this is a fallback
				if p.buf[offset] == 0x01 && offset <= p.bufLen-8 {
					// Legacy CSTP 8-byte header format (without STF prefix):
					// Byte 0: Version (0x01)
					// Byte 1: Type
					// Byte 2-3: Flags/Reserved
					// Byte 4-5: Length (BIG-ENDIAN) - payload length only, NOT including header
					// Byte 6-7: Reserved
					// Client-to-server packets use big-endian for length field per OpenConnect spec
					// However, some clients may send it in little-endian, so we try both
					packetType := p.buf[offset+1]
					packetLenBE := binary.BigEndian.Uint16(p.buf[offset+4 : offset+6])
					packetLenLE := binary.LittleEndian.Uint16(p.buf[offset+4 : offset+6])

					// Try big-endian first (per spec), fallback to little-endian if invalid
					// packetLen is payload length only (NOT including header)
					var packetLen uint16
					if packetLenBE <= maxPacketSize {
						packetLen = packetLenBE
					} else if packetLenLE <= maxPacketSize {
						packetLen = packetLenLE
						// Store preference for this client (for receiving packets only)
						// Note: Server always uses BIG-ENDIAN for sending packets regardless of client preference
						p.useLittleEndian = true
						log.Printf("OpenConnect: Using little-endian for length field (big-endian gave invalid length %d, little-endian gives %d)",
							packetLenBE, packetLenLE)
					} else {
						// Both are invalid, use big-endian for logging
						packetLen = packetLenBE
					}

					// Validate packet length - payload length must be reasonable
					// Total packet size = Header(8) + Payload(packetLen)
					totalPacketSize := 8 + int(packetLen)
					if packetLen <= maxPacketSize && totalPacketSize <= maxPacketSize+8 {
						// Valid CSTP header found without "STF" prefix
						if offset > 0 {
							// Legacy format without STF prefix - remove padding
							copy(p.buf, p.buf[offset:])
							p.bufLen -= offset
						}

						p.packetType = packetType
						// packetLen is payload length, total packet = Header(8) + Payload
						// For legacy format without STF, header is 8 bytes
						p.packetLen = uint16(8 + int(packetLen))
						p.state = stateNeedPayload
						foundValidHeader = true
						break
					}
				}

				offset++
			}

			if !foundValidHeader {
				// No valid header found, continue to error handling below
			} else {
				// Found valid header, continue to payload parsing
				continue
			}

			// If we couldn't find a valid header and have data, log it
			if offset > p.bufLen-cstpHeaderLen && p.bufLen >= 8 {
				previewLen := p.bufLen
				if previewLen > 16 {
					previewLen = 16
				}
				log.Printf("OpenConnect: No valid CSTP header found in buffer (first %d bytes: %x)", previewLen, p.buf[:previewLen])
			}

			if offset > p.bufLen-cstpHeaderLen {
				// No valid header found in buffer
				if p.bufLen > 1000 {
					// Buffer too large, likely corrupted - reset
					log.Printf("OpenConnect: No valid header found in %d bytes, resetting parser", p.bufLen)
					p.reset()
				}
				return nil, io.EOF
			}

			// Continue to payload parsing
		}

		if p.state == stateNeedPayload {
			// Need complete packet
			if p.bufLen < int(p.packetLen) {
				return nil, io.EOF // Not enough data
			}

			// Extract packet
			// Determine payload start based on whether we have STF prefix or not
			// Modern format: STF(3) + Header(5) = 8 bytes, payload starts at offset 8
			// Legacy format: Header(8) = 8 bytes, payload starts at offset 8
			// Check if buffer starts with STF prefix to determine format
			var payloadStart int
			if p.bufLen >= 3 && p.buf[0] == 'S' && p.buf[1] == 'T' && p.buf[2] == 'F' {
				// Modern format with STF prefix
				payloadStart = cstpHeaderLenWithSTF // 8 bytes (STF 3 + Header 5)
			} else {
				// Legacy format without STF prefix
				payloadStart = 8 // 8 bytes (Header only)
			}

			// For data packets (type 0x00), payload is IP packet
			if p.packetType == PacketTypeData && p.bufLen >= payloadStart+20 {
				// Verify IP header starts correctly (IPv4: 0x45, IPv6: 0x60)
				if p.buf[payloadStart] == 0x45 {
					// IPv4 packet detected - no logging needed for normal operation
					// IPv4 header detected - no logging needed for normal operation
				} else if (p.buf[payloadStart] & 0xf0) == 0x60 {
					// IPv6 header detected - no logging needed for normal operation
				} else {
					// Some packets may have padding or non-standard format
					// Only log if we're sure this is a data packet and the data looks suspicious
					// Try to find IP header at nearby offsets (some clients add padding)
					foundIPHeader := false
					for offset := payloadStart; offset < payloadStart+4 && offset < p.bufLen-20; offset++ {
						if p.buf[offset] == 0x45 || (p.buf[offset]&0xf0) == 0x60 {
							foundIPHeader = true
							// IP header found at different offset (padding) - no logging needed
							break
						}
					}
					// Calculate expected payload length to check if it's a data packet
					expectedPayloadLen := int(p.packetLen) - payloadStart
					if !foundIPHeader && expectedPayloadLen > 20 && p.packetType == PacketTypeData {
						// Only log if we can't find IP header nearby, payload is large enough, and it's a data packet
						previewLen := min(16, p.bufLen-payloadStart)
						log.Printf("OpenConnect: Unexpected data at payload start (offset %d): %x (expected IPv4 0x45 or IPv6 0x60)", payloadStart, p.buf[payloadStart:payloadStart+previewLen])
					}
				}
			}

			// payloadLen = total packet size - header size
			payloadLen := int(p.packetLen) - payloadStart
			if payloadLen < 0 {
				log.Printf("OpenConnect: ERROR - Negative payload length: packetLen=%d, payloadStart=%d, payloadLen=%d, bufLen=%d",
					p.packetLen, payloadStart, payloadLen, p.bufLen)
				payloadLen = 0
			}
			payload := make([]byte, payloadLen)
			if payloadLen > 0 && p.bufLen >= int(p.packetLen) {
				copy(payload, p.buf[payloadStart:p.packetLen])
				// Log ICMP packets for debugging
				if p.packetType == PacketTypeData && len(payload) >= 28 && payload[9] == 1 {
					icmpType := payload[20]
					icmpTypeStr := "unknown"
					switch icmpType {
					case 0:
						icmpTypeStr = "echo reply"
					case 8:
						icmpTypeStr = "echo request"
					}
					srcIP := net.IP(payload[12:16])
					dstIP := net.IP(payload[16:20])
					log.Printf("OpenConnect: Extracted ICMP %s packet from payload: %s -> %s, payloadLen=%d",
						icmpTypeStr, srcIP.String(), dstIP.String(), payloadLen)
				}
			} else {
				// DPD, Keepalive, and other control packets may have zero payload, which is normal
				if p.packetType == PacketTypeDPD || p.packetType == PacketTypeDPDResp || p.packetType == PacketTypeKeepalive {
					// Control packets with zero payload are normal, don't log as error
				} else if payloadLen == 0 && p.packetType == PacketTypeData {
					// Data packets should have payload, but small packets might be valid
					// Only log if buffer is large enough but payload is missing
					if p.bufLen >= int(p.packetLen) {
						log.Printf("OpenConnect: WARNING - Data packet has zero payload: packetLen=%d, bufLen=%d, payloadStart=%d",
							p.packetLen, p.bufLen, payloadStart)
					}
				} else {
					// Buffer not ready yet, this is expected during packet assembly
					// Don't log as error
				}
			}

			packet := &ParsedPacket{
				Type:    p.packetType,
				Payload: payload,
			}

			// Remove processed packet from buffer
			// p.packetLen is the total CSTP packet length (STF 3 + Header 5 + Payload)
			// After removing "STF" prefix, buffer starts at CSTP header (offset 0)
			// Standard format: 5-byte header + payload at offset 5
			actualPacketSize := int(p.packetLen)

			if actualPacketSize > p.bufLen {
				log.Printf("OpenConnect: Warning: packetLen (%d) > bufLen (%d), resetting parser", p.packetLen, p.bufLen)
				p.reset()
				return nil, io.EOF
			}

			// Log buffer state before removal for debugging (only if there's significant leftover)
			if actualPacketSize < p.bufLen {
				// There will be leftover data after this packet
				leftoverLen := p.bufLen - actualPacketSize
				if leftoverLen > 0 && leftoverLen < 20 {
					// Log small leftover (likely indicates a problem)
					previewLen := leftoverLen
					if previewLen > 16 {
						previewLen = 16
					}
					// Buffer cleanup - no logging needed for normal operation
				}
			}

			// Remove the processed packet from buffer
			copy(p.buf, p.buf[actualPacketSize:])
			p.bufLen -= actualPacketSize

			// Reset state for next packet
			p.state = stateNeedHeader
			p.packetLen = 0
			p.packetType = 0

			// Validate packet type
			// Known types: 0x00-0x05
			// 0x08 might be compressed data or error message from client
			// We'll silently ignore unknown types to avoid log spam
			if packet.Type > PacketTypeError {
				// Log first few occurrences for debugging, then silence
				if packet.Type == 0x08 && payloadLen > 0 && payloadLen < 100 {
					// Check if it's an error message
					msg := string(payload)
					if len(msg) > 0 && (msg[0] >= 32 && msg[0] < 127) {
						log.Printf("OpenConnect: Client error message (type 0x08): %q", msg)
					}
				}
				// Skip this packet and continue
				continue
			}

			return packet, nil
		}
	}
}

// reset resets the parser state
func (p *CSTPParser) reset() {
	p.bufLen = 0
	p.state = stateNeedHeader
	p.packetLen = 0
	p.packetType = 0
}

// processPacket processes a single CSTP packet based on its type
func (tc *TunnelClient) processPacket(packetType byte, payload []byte) error {
	switch packetType {
	case PacketTypeData:
		return tc.processDataPacket(payload)
	case PacketTypeKeepalive:
		// Keepalive received, reset timeout
		return nil
	case PacketTypeDisconnect:
		// DISCONNECT (0x05) - terminate session
		// Note: PacketTypeError is also 0x05 but is handled separately in error detection
		return fmt.Errorf("disconnect requested")
	case PacketTypeDPD:
		return tc.processDPDPacket(payload)
	case PacketTypeDPDResp:
		// DPD response from client; nothing to do
		return nil
	default:
		log.Printf("OpenConnect: Unknown packet type: 0x%02x, length: %d", packetType, len(payload))
		return nil
	}
}

// processDataPacket processes a data packet containing IP traffic
// Handles decompression if compression is enabled
func (tc *TunnelClient) processDataPacket(payload []byte) error {
	// Decompress if compression is enabled
	if tc.VPNServer != nil && tc.VPNServer.CompressionMgr != nil {
		cfg := tc.VPNServer.GetConfig()
		if cfg != nil && cfg.VPN.EnableCompression {
			compressionType := vpn.CompressionType(cfg.VPN.CompressionType)
			if compressionType != vpn.CompressionNone {
				decompressed, err := tc.VPNServer.CompressionMgr.Decompress(payload, compressionType)
				if err != nil {
					log.Printf("Warning: Failed to decompress packet from user %s: %v", tc.User.Username, err)
					// Continue with original payload (might not be compressed)
				} else {
					payload = decompressed
				}
			}
		}
	}
	// Check if this is actually an error message from the client
	// OpenConnect sometimes sends error messages in data packets
	if len(payload) > 0 && len(payload) < 200 {
		// Check if payload starts with printable ASCII (likely an error message)
		// Error messages often start with error code (1 byte) + reserved (1 byte) + message
		if len(payload) >= 2 {
			// Check if bytes 2+ are printable ASCII
			isPrintable := true
			for i := 2; i < len(payload) && i < 100; i++ {
				if payload[i] < 32 || payload[i] >= 127 {
					if payload[i] != 0 && payload[i] != '\n' && payload[i] != '\r' {
						isPrintable = false
						break
					}
				}
			}
			if isPrintable && len(payload) > 2 {
				errorMsg := string(payload[2:])
				// Check if it looks like an error message
				if len(errorMsg) > 5 && (errorMsg[0] >= 'A' && errorMsg[0] <= 'Z' || errorMsg[0] >= 'a' && errorMsg[0] <= 'z') {
					errorCode := payload[0]
					log.Printf("OpenConnect: Client error message in data packet (code: 0x%02x): %q", errorCode, errorMsg)
					// Don't process as IP packet, but don't close connection
					return nil
				}
			}
		}
	}

	// Minimum IP header size is 20 bytes
	if len(payload) < 20 {
		return nil // Skip too small packets
	}

	// Check IP version (first 4 bits)
	ipVersion := payload[0] >> 4
	if ipVersion != 4 {
		// Only support IPv4 for now
		return nil
	}

	// Validate IP header length
	ipHeaderLen := int((payload[0] & 0x0F) * 4)
	if ipHeaderLen < 20 || ipHeaderLen > len(payload) {
		log.Printf("OpenConnect: Invalid IP header length: %d", ipHeaderLen)
		return nil
	}

	// Extract source and destination IPs for logging
	srcIP := net.IP(payload[12:16])
	dstIP := net.IP(payload[16:20])
	protocol := payload[9]

	// Verify source IP matches assigned VPN IP
	if !srcIP.Equal(tc.IP) {
		log.Printf("OpenConnect: Source IP mismatch: expected %s, got %s", tc.IP.String(), srcIP.String())
		return fmt.Errorf("source IP mismatch: expected %s, got %s", tc.IP.String(), srcIP.String())
	}

	// Always log ICMP packets for debugging ping issues
	if protocol == 1 { // ICMP
		icmpType := "unknown"
		if len(payload) >= 28 {
			icmpTypeCode := payload[20] // ICMP type is at offset 20 (after IP header)
			switch icmpTypeCode {
			case 0:
				icmpType = "echo reply"
			case 8:
				icmpType = "echo request"
			case 3:
				icmpType = "destination unreachable"
			case 11:
				icmpType = "time exceeded"
			default:
				icmpType = fmt.Sprintf("type %d", icmpTypeCode)
			}
		}
		vpn.LogPacketAlways("OpenConnect: Processing ICMP %s packet from %s to %s (length: %d)",
			icmpType, srcIP.String(), dstIP.String(), len(payload))
	} else {
		vpn.LogPacket("OpenConnect: Processing data packet from %s to %s (protocol: %d, length: %d)",
			srcIP.String(), dstIP.String(), protocol, len(payload))
	}

	// OPTIMIZATION: Check if this is client-to-client communication
	// If so, forward directly without going through TUN device (faster path)
	// Get VPN network configuration
	cfg := tc.VPNServer.GetConfig()
	if cfg != nil {
		_, ipNet, err := net.ParseCIDR(cfg.VPN.Network)
		if err == nil {
			// Get server VPN IP
			serverVPNIP := make(net.IP, len(ipNet.IP))
			copy(serverVPNIP, ipNet.IP)
			serverVPNIP[len(serverVPNIP)-1] = 1

			// Check if this is client-to-client communication (Case 3)
			if ipNet.Contains(srcIP) && ipNet.Contains(dstIP) && !dstIP.Equal(serverVPNIP) {
				// Client-to-client communication - forward directly, bypassing TUN device
				// This is the optimal path: no TUN read/write, no kernel routing overhead
				if protocol == 1 { // ICMP - always log for debugging
					log.Printf("OpenConnect: Direct forwarding ICMP packet from client %s to client %s (bypassing TUN device)",
						srcIP.String(), dstIP.String())
				} else {
					vpn.LogPacket("OpenConnect: Direct forwarding packet from client %s to client %s (bypassing TUN device)",
						srcIP.String(), dstIP.String())
				}

				// Perform policy check before forwarding
				if err := tc.performPolicyCheck(payload); err != nil {
					log.Printf("OpenConnect: Packet denied by policy: %v", err)
					return err
				}

				// Forward directly to destination client
				if err := tc.VPNServer.ForwardPacketToClient(dstIP, payload); err != nil {
					// Check if error is due to client disconnection (expected)
					errMsg := err.Error()
					if strings.Contains(errMsg, "no client found") ||
						strings.Contains(errMsg, "not connected") ||
						strings.Contains(errMsg, "is closing") ||
						strings.Contains(errMsg, "write channel closed") {
						// Client disconnected - this is expected, don't log as error
						if protocol == 1 {
							vpn.LogPacket("OpenConnect: Client %s disconnected, skipping direct forwarding", dstIP.String())
						}
					} else {
						// Other errors should be logged
						log.Printf("OpenConnect: Failed to forward packet from client %s to %s: %v",
							srcIP.String(), dstIP.String(), err)
					}
				} else {
					if protocol == 1 { // ICMP - always log for debugging
						log.Printf("OpenConnect: Successfully forwarded ICMP packet from client %s to client %s (direct path)",
							srcIP.String(), dstIP.String())
					}
				}
				// Return early - don't write to TUN device
				return nil
			}
		}
	}

	// Execute policy check
	// Optimization: If eBPF is enabled and policies are synced to eBPF,
	// we can skip user-space policy check for better performance.
	// eBPF will handle policy checks at kernel level (see ARCHITECTURE_OPTIMIZATION.md)
	if err := tc.performPolicyCheck(payload); err != nil {
		log.Printf("OpenConnect: Packet denied by policy: %v", err)
		return err
	}

	// Forward packet to TUN device
	// All protocols (ICMP, TCP, UDP, HTTP, etc.) are handled by the kernel
	// The kernel will process the packet and generate response if needed
	// Response will be read from TUN by listenTUNDevice and forwarded back
	// NOTE: We do NOT perform user-space NAT here because it breaks kernel conntrack.
	// Instead, we rely on kernel's conntrack and routing to handle NAT via iptables/nftables
	// or eBPF TC hook (if implemented). The kernel will automatically track connections
	// and route response packets back to the VPN client.
	if tc.TUNDevice != nil {
		// Write packet to TUN device WITHOUT modifying it
		// The kernel's conntrack will track the connection, and NAT will be handled
		// by the kernel's netfilter subsystem (iptables/nftables) or eBPF TC hook
		n, err := tc.TUNDevice.Write(payload)
		if err != nil {
			log.Printf("OpenConnect: Failed to write to TUN device: %v", err)
			return fmt.Errorf("failed to write to TUN: %w", err)
		}
		// Always log ICMP packets (important for debugging ping issues)
		if protocol == 1 { // ICMP
			// Check ICMP type for more detailed logging
			icmpType := "unknown"
			if len(payload) >= 20+8 {
				icmpTypeCode := payload[20] // ICMP type is at offset 20 (after IP header)
				switch icmpTypeCode {
				case 0:
					icmpType = "echo reply"
				case 8:
					icmpType = "echo request"
				case 3:
					icmpType = "destination unreachable"
				case 11:
					icmpType = "time exceeded"
				default:
					icmpType = fmt.Sprintf("type %d", icmpTypeCode)
				}
			}
			vpn.LogPacketAlways("OpenConnect: Wrote %d bytes (ICMP %s) to TUN device (packet from %s to %s)",
				n, icmpType, srcIP.String(), dstIP.String())
		} else {
			vpn.LogPacket("OpenConnect: Wrote %d bytes to TUN device (packet from %s to %s, protocol: %d)",
				n, srcIP.String(), dstIP.String(), protocol)
		}
	} else {
		log.Printf("OpenConnect: TUN device is nil, cannot forward packet")
	}

	return nil
}

// processDPDPacket processes a Dead Peer Detection packet
func (tc *TunnelClient) processDPDPacket(payload []byte) error {
	// Reply with DPD response
	log.Printf("OpenConnect: Received DPD packet from user %s, sending DPD response", tc.User.Username)
	return tc.sendPacket(PacketTypeDPDResp, payload)
}

// performPolicyCheck handles the policy check logic based on whether eBPF is enabled
// This function reduces code duplication by centralizing the policy check logic
func (tc *TunnelClient) performPolicyCheck(packet []byte) error {
	// Extract packet information to determine if this is VPN internal traffic
	if len(packet) < 20 {
		return nil
	}
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	// Check if this is VPN internal traffic (client-to-client or client-to-server)
	// VPN internal traffic doesn't go through eth0, so eBPF can't handle it
	// We need to do full policy check in user space for VPN internal traffic
	isVPNInternal := false
	cfg := tc.VPNServer.GetConfig()
	if cfg != nil {
		_, ipNet, err := net.ParseCIDR(cfg.VPN.Network)
		if err == nil {
			// If both source and destination are in VPN network, it's VPN internal traffic
			if ipNet.Contains(srcIP) && ipNet.Contains(dstIP) {
				isVPNInternal = true
			}
		}
	}

	ebpfProgram := tc.VPNServer.GetEBPFProgram()
	protocol := packet[9]
	protocolName := getProtocolName(protocol)

	// Log policy check for debugging (ICMP always, TCP/UDP for VPN internal traffic)
	if protocol == 1 || (isVPNInternal && (protocol == 6 || protocol == 17)) { // ICMP or TCP/UDP VPN internal
		log.Printf("OpenConnect: [POLICY CHECK] performPolicyCheck: Protocol=%s, Src=%s, Dst=%s, isVPNInternal=%v, ebpfProgram=%v",
			protocolName, srcIP.String(), dstIP.String(), isVPNInternal, ebpfProgram != nil)
	}
	if ebpfProgram == nil || isVPNInternal {
		// No eBPF, or VPN internal traffic (eBPF can't handle VPN internal traffic)
		// Must check in user space for ALL protocols (ICMP, TCP, UDP, etc.)
		if protocol == 1 || (isVPNInternal && (protocol == 6 || protocol == 17)) { // ICMP or TCP/UDP VPN internal
			log.Printf("OpenConnect: [POLICY CHECK] Using user-space policy check (checkPolicy) for %s",
				protocolName)
		}
		return tc.checkPolicy(packet)
	} else {
		// eBPF is enabled and this is external traffic - do lightweight check
		// eBPF will handle policy checks for external traffic at kernel level
		if protocol == 1 { // ICMP
			log.Printf("OpenConnect: [POLICY CHECK] Using lightweight check (eBPF handles external traffic)")
		}
		return tc.checkPolicyLightweight(packet)
	}
}

// checkPolicyLightweight performs a lightweight policy check
// This is used when eBPF is enabled - eBPF handles most policy checks
// This function only checks critical policies that can't be handled by eBPF
func (tc *TunnelClient) checkPolicyLightweight(packet []byte) error {
	// For now, just do basic validation
	// Full policy checks are done in eBPF XDP
	if len(packet) < 20 {
		return nil
	}
	// Additional lightweight checks can be added here
	return nil
}

// checkPolicy checks if the packet is allowed by policy
func (tc *TunnelClient) checkPolicy(packet []byte) error {
	if tc.VPNServer == nil {
		return nil
	}

	policyMgr := tc.VPNServer.GetPolicyManager()
	if policyMgr == nil {
		return nil
	}

	// Extract packet information for policy check
	if len(packet) < 20 {
		return nil
	}

	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])
	protocol := packet[9]

	// Create policy context
	ctx := policy.NewContext()
	ctx.UserID = tc.User.ID
	ctx.VPNIP = tc.IP.String()
	ctx.ClientIP = tc.Conn.RemoteAddr().String()
	ctx.SrcIP = srcIP.String()
	ctx.DstIP = dstIP.String()
	netProtocol := getProtocolName(protocol)

	// Extract ports if TCP/UDP
	if protocol == 6 || protocol == 17 { // TCP or UDP
		if len(packet) >= 24 {
			ctx.SrcPort = binary.BigEndian.Uint16(packet[20:22])
			ctx.DstPort = binary.BigEndian.Uint16(packet[22:24])
		}
		// Infer application layer protocol from destination port
		ctx.Protocol = inferApplicationProtocol(netProtocol, ctx.DstPort)
	} else {
		ctx.Protocol = netProtocol
	}

	// Determine which hook points to check based on packet flow
	// - Client-to-client: PRE_ROUTING + FORWARD
	// - Client-to-server: PRE_ROUTING + INPUT
	// - External traffic: PRE_ROUTING + POST_ROUTING
	cfg := tc.VPNServer.GetConfig()
	isClientToClient := false
	isClientToServer := false
	if cfg != nil {
		_, ipNet, err := net.ParseCIDR(cfg.VPN.Network)
		if err == nil {
			if ipNet.Contains(srcIP) && ipNet.Contains(dstIP) {
				// Both source and destination are in VPN network
				// Check if destination is server VPN IP
				serverVPNIP := make(net.IP, len(ipNet.IP))
				copy(serverVPNIP, ipNet.IP)
				serverVPNIP[len(serverVPNIP)-1] = 1
				if dstIP.Equal(serverVPNIP) {
					isClientToServer = true
				} else {
					isClientToClient = true
				}
			}
		}
	}

	// Check PRE_ROUTING hook (always checked)
	// Log policy check for ICMP and VPN internal TCP/UDP packets (for debugging)
	if protocol == 1 || (isClientToClient || isClientToServer) && (protocol == 6 || protocol == 17) { // ICMP or VPN internal TCP/UDP
		log.Printf("OpenConnect: [POLICY CHECK] Checking PRE_ROUTING hook: User=%s, Src=%s, Dst=%s, Protocol=%s, isClientToClient=%v, isClientToServer=%v",
			tc.User.Username, ctx.SrcIP, ctx.DstIP, ctx.Protocol, isClientToClient, isClientToServer)
	}
	action := policyMgr.ExecutePolicies(policy.HookPreRouting, ctx)
	if protocol == 1 || (isClientToClient || isClientToServer) && (protocol == 6 || protocol == 17) { // ICMP or VPN internal TCP/UDP
		log.Printf("OpenConnect: [POLICY CHECK] PRE_ROUTING hook result: action=%d (0=ALLOW, 1=DENY, 2=REDIRECT, 3=LOG)",
			action)
	}
	if action == policy.ActionDeny {
		// Log policy denial for debugging (all protocols)
		if protocol == 6 || protocol == 17 { // TCP or UDP - include port info
			log.Printf("OpenConnect: [POLICY DENY] PRE_ROUTING hook denied packet: User=%s, Src=%s:%d, Dst=%s:%d, Protocol=%s",
				tc.User.Username, ctx.SrcIP, ctx.SrcPort, ctx.DstIP, ctx.DstPort, ctx.Protocol)
		} else {
			log.Printf("OpenConnect: [POLICY DENY] PRE_ROUTING hook denied packet: User=%s, Src=%s, Dst=%s, Protocol=%s",
				tc.User.Username, ctx.SrcIP, ctx.DstIP, ctx.Protocol)
		}
		return fmt.Errorf("packet denied by PRE_ROUTING policy")
	}

	// Check additional hook points based on packet flow
	if isClientToClient {
		// Client-to-client: check FORWARD hook
		forwardAction := policyMgr.ExecutePolicies(policy.HookForward, ctx)
		if forwardAction == policy.ActionDeny {
			if protocol == 6 || protocol == 17 { // TCP or UDP - include port info
				log.Printf("OpenConnect: [POLICY DENY] FORWARD hook denied packet: User=%s, Src=%s:%d, Dst=%s:%d, Protocol=%s",
					tc.User.Username, ctx.SrcIP, ctx.SrcPort, ctx.DstIP, ctx.DstPort, ctx.Protocol)
			} else {
				log.Printf("OpenConnect: [POLICY DENY] FORWARD hook denied packet: User=%s, Src=%s, Dst=%s, Protocol=%s",
					tc.User.Username, ctx.SrcIP, ctx.DstIP, ctx.Protocol)
			}
			return fmt.Errorf("packet denied by FORWARD policy")
		}
		if forwardAction != policy.ActionAllow {
			action = forwardAction
		}
	} else if isClientToServer {
		// Client-to-server: check INPUT hook
		if protocol == 1 || protocol == 6 || protocol == 17 { // ICMP, TCP, or UDP
			log.Printf("OpenConnect: [POLICY CHECK] Checking INPUT hook: User=%s, Src=%s, Dst=%s, Protocol=%s",
				tc.User.Username, ctx.SrcIP, ctx.DstIP, ctx.Protocol)
		}
		inputAction := policyMgr.ExecutePolicies(policy.HookInput, ctx)
		if protocol == 1 || protocol == 6 || protocol == 17 { // ICMP, TCP, or UDP
			log.Printf("OpenConnect: [POLICY CHECK] INPUT hook result: action=%d (0=ALLOW, 1=DENY, 2=REDIRECT, 3=LOG)",
				inputAction)
		}
		if inputAction == policy.ActionDeny {
			// Log policy denial for debugging (all protocols)
			if protocol == 6 || protocol == 17 { // TCP or UDP - include port info
				log.Printf("OpenConnect: [POLICY DENY] INPUT hook denied packet: User=%s, Src=%s:%d, Dst=%s:%d, Protocol=%s",
					tc.User.Username, ctx.SrcIP, ctx.SrcPort, ctx.DstIP, ctx.DstPort, ctx.Protocol)
			} else {
				log.Printf("OpenConnect: [POLICY DENY] INPUT hook denied packet: User=%s, Src=%s, Dst=%s, Protocol=%s",
					tc.User.Username, ctx.SrcIP, ctx.DstIP, ctx.Protocol)
			}
			return fmt.Errorf("packet denied by INPUT policy")
		}
		if inputAction != policy.ActionAllow {
			action = inputAction
		}
	} else {
		// External traffic: check POST_ROUTING hook
		postAction := policyMgr.ExecutePolicies(policy.HookPostRouting, ctx)
		if postAction == policy.ActionDeny {
			return fmt.Errorf("packet denied by POST_ROUTING policy")
		}
		if postAction != policy.ActionAllow {
			action = postAction
		}
	}

	switch action {
	case policy.ActionDeny:
		return fmt.Errorf("packet denied by policy")
	case policy.ActionRedirect:
		// 重定向：将目标IP改为VPN网络内的地址
		// 这里需要根据配置的VPN网络来重定向
		// 实际实现中，重定向通常意味着将流量路由到VPN网络
		// 由于我们已经通过VPN隧道，这里可以记录日志并允许通过
		// 真正的重定向应该在路由层面配置
		// 没啥用，前端已经去掉了重定向功能，代码放着也没事
		log.Printf("OpenConnect: Packet redirected by policy - User: %s, Src: %s, Dst: %s -> VPN network",
			tc.User.Username, ctx.SrcIP, ctx.DstIP)
		// 允许通过，重定向由路由配置处理
		return nil
	case policy.ActionLog:
		// 记录日志并允许通过
		log.Printf("OpenConnect: [POLICY LOG] User: %s (ID: %d), Src: %s, Dst: %s, Protocol: %s, SrcPort: %d, DstPort: %d",
			tc.User.Username, ctx.UserID, ctx.SrcIP, ctx.DstIP, ctx.Protocol, ctx.SrcPort, ctx.DstPort)
		// 允许通过
		return nil
	default:
		// ActionAllow 或其他情况，允许通过
		return nil
	}
}

// sendPacket sends a CSTP packet with the given type and payload
// This function is thread-safe and can be called concurrently with reads
// IMPORTANT: Both server-to-client and client-to-server packets NOW include "STF" prefix for compatibility
// This ensures the client can properly parse packets from the server
func (tc *TunnelClient) sendPacket(packetType byte, data []byte) error {
	// Use "STF" prefix + 8-byte CSTP header format for all packets to ensure compatibility
	// CSTP format with STF prefix:
	// Bytes 0-2: "STF" prefix
	// Byte 3: Version (0x01)
	// Byte 4: Type
	// Byte 5-6: Flags/Reserved
	// Byte 7-8: Length (BIG-ENDIAN - this is the ONLY big-endian field)
	// Byte 9-10: Reserved
	// Payload starts at byte 11

	// Per OpenConnect spec draft-mavrogiannopoulos-openconnect-02:
	// Byte 0-2: 'S', 'T', 'F' (fixed)
	// Byte 3: 0x01 (fixed)
	// Byte 4-5: Length (BIG-ENDIAN) - length of payload that follows header (NOT including header)
	// Byte 6: Payload type
	// Byte 7: 0x00 (fixed)
	// Byte 8+: Payload
	stfLen := 3
	headerLen := 5                  // Version(1) + Length(2) + Type(1) + Reserved(1) = 5 bytes (excluding STF prefix)
	payloadLen := uint16(len(data)) // Length field is payload length only, NOT including header
	fullPacket := make([]byte, stfLen+headerLen+len(data))

	// Write STF prefix
	fullPacket[0] = 'S'
	fullPacket[1] = 'T'
	fullPacket[2] = 'F'

	// Write CSTP header (starts at offset 3)
	fullPacket[3] = 0x01 // Version (fixed to 0x01)
	// Byte 4-5: Length (BIG-ENDIAN) - length of payload, NOT including header
	binary.BigEndian.PutUint16(fullPacket[4:6], payloadLen)
	// Byte 6: Payload type
	fullPacket[6] = packetType
	// Byte 7: Reserved (fixed to 0x00)
	fullPacket[7] = 0x00

	// Copy payload after header (starts at byte 8)
	if len(data) > 0 {
		copy(fullPacket[8:], data)
	}

	// Log packet details for debugging
	if vpn.ShouldLogPacket() {
		// Server always uses BIG-ENDIAN for server-to-client packets
		// Length field is payload length only (NOT including header)
		log.Printf("OpenConnect: Sending packet to user %s: type=0x%02x, payload length=%d (BIG-ENDIAN at byte 4-5), total packet=%d bytes, first 16 bytes: %x",
			tc.User.Username, packetType, payloadLen, len(fullPacket), fullPacket[:min(16, len(fullPacket))])
	}

	// Send packet atomically
	if _, err := tc.Conn.Write(fullPacket); err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	return nil
}

// sendKeepalive sends a keepalive packet to the client
func (tc *TunnelClient) sendKeepalive() error {
	return tc.sendPacket(PacketTypeKeepalive, nil)
}

// getProtocolName returns the network layer protocol name for a given protocol number
func getProtocolName(protocol uint8) string {
	switch protocol {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("unknown-%d", protocol)
	}
}

// inferApplicationProtocol infers application layer protocol from network protocol and port
func inferApplicationProtocol(netProtocol string, dstPort uint16) string {
	// If not TCP or UDP, return network protocol as-is
	if netProtocol != "tcp" && netProtocol != "udp" {
		return netProtocol
	}

	// Common port mappings for application protocols
	switch dstPort {
	case 20, 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		if netProtocol == "udp" {
			return "dns"
		}
		return netProtocol // TCP DNS is less common
	case 67, 68:
		return "dhcp"
	case 69:
		return "tftp"
	case 80:
		return "http"
	case 443:
		return "https"
	case 8080:
		return "http-alt"
	case 8443:
		return "https-alt"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 27017:
		return "mongodb"
	case 3389:
		return "rdp"
	case 5900:
		return "vnc"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 389:
		return "ldap"
	case 636:
		return "ldaps"
	case 143:
		return "imap"
	case 993:
		return "imaps"
	case 110:
		return "pop3"
	case 995:
		return "pop3s"
	case 9092:
		return "kafka"
	case 9200:
		return "elasticsearch"
	case 9300:
		return "elasticsearch-cluster"
	case 2181:
		return "zookeeper"
	case 9042:
		return "cassandra"
	case 7000, 7001:
		return "cassandra-cluster"
	case 27018:
		return "mongodb-shard"
	case 5984:
		return "couchdb"
	case 11211:
		return "memcached"
	case 5672:
		return "amqp"
	case 15672:
		return "rabbitmq-management"
	case 5671:
		return "amqps"
	case 1883:
		return "mqtt"
	case 8883:
		return "mqtts"
	case 2379, 2380:
		return "etcd"
	case 10250:
		return "kubelet"
	case 6443:
		return "kubernetes-api"
	default:
		// Return network protocol if no application protocol can be inferred
		return netProtocol
	}
}

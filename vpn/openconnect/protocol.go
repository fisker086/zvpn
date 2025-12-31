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
	useLittleEndian bool  // Whether client uses little-endian for length field (detected from incoming packets)
	lastDataTime    int64 // Last data packet time (Unix timestamp)
	idleTimeout     int64 // Idle timeout in seconds (0 means disabled)
}

// NewTunnelClient creates a new tunnel client
func NewTunnelClient(user *models.User, conn net.Conn, ip net.IP, vpnServer *vpn.VPNServer, tunDevice *vpn.TUNDevice) *TunnelClient {
	now := time.Now().Unix()
	tc := &TunnelClient{
		User:         user,
		Conn:         conn,
		IP:           ip,
		VPNServer:    vpnServer,
		TUNDevice:    tunDevice,
		lastDataTime: now,
		idleTimeout:  0, // 默认禁用，从配置中读取
		parser: &CSTPParser{
			buf:    make([]byte, maxPacketSize*2),
			bufLen: 0,
			state:  stateNeedHeader,
		},
	}

	// 从配置中读取空闲超时（如果配置了）
	if vpnServer != nil {
		if cfg := vpnServer.GetConfig(); cfg != nil {
			// 当前 X-CSTP-Idle-Timeout 设置为 0（禁用）
			// 如果需要启用，可以从配置中读取
			// tc.idleTimeout = int64(cfg.VPN.IdleTimeout)
		}
	}

	return tc
}

// HandleTunnelData handles VPN tunnel data - main loop for processing CSTP packets
// This function runs in a separate goroutine and handles all incoming CSTP packets from the client
// NOTE: Connection closing is handled by the caller to ensure proper shutdown order:
// 1. Stop WriteLoop goroutine first
// 2. Then close the connection
// This prevents RST packets when connection closes
func (tc *TunnelClient) HandleTunnelData() error {
	// Connection closing is now handled by the caller (handler.go)
	// This allows proper shutdown sequence: stop WriteLoop -> close connection

	log.Printf("OpenConnect: Starting tunnel handler for user %s (IP: %s)", tc.User.Username, tc.IP.String())

	readBuf := make([]byte, 4096) // Read buffer
	timeoutCount := 0
	const maxTimeouts = 3

	// 获取 keepalive 配置，read timeout 应该略大于 keepalive 值（keepalive * 1.5）
	// 这样可以在客户端发送 keepalive 之前，服务端先检测到超时并发送 keepalive
	readTimeout := 30 * time.Second // 默认值
	if tc.VPNServer != nil {
		if cfg := tc.VPNServer.GetConfig(); cfg != nil {
			cstpKeepalive := cfg.VPN.CSTPKeepalive
			if cstpKeepalive == 0 {
				cstpKeepalive = 20 // 默认值：20秒（AnyConnect 标准）
			}
			// read timeout = keepalive * 1.5，确保在客户端发送 keepalive 之前检测到超时
			readTimeout = time.Duration(cstpKeepalive) * time.Second * 3 / 2
		}
	}

	for {
		// Set read timeout based on keepalive interval
		if err := tc.Conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
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

		// Feed data to parser
		if err := tc.parser.feed(readBuf[:n]); err != nil {
			log.Printf("OpenConnect: Parser feed error for user %s: %v", tc.User.Username, err)
			// Parser feed errors are usually recoverable (buffer overflow, etc.)
			// Reset parser and continue instead of closing connection
			tc.parser.reset()
			continue
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
				// For disconnect packets, this is a normal operation, not an error
				if packet.Type == PacketTypeDisconnect {
					log.Printf("OpenConnect: Client %s requested disconnect (normal operation)", tc.User.Username)
					return nil
				}
				// For format errors, log as warning and continue
				if strings.Contains(err.Error(), "unknown packet format") ||
					strings.Contains(err.Error(), "reported unknown packet") {
					log.Printf("OpenConnect: Client reported format error: %v", err)
					// Continue processing other packets instead of closing connection
					continue
				}
				// For source IP mismatch, this might be a transient issue, log and continue
				if strings.Contains(err.Error(), "source IP mismatch") {
					log.Printf("OpenConnect: Source IP mismatch for user %s: %v (continuing)", tc.User.Username, err)
					// Continue processing other packets instead of closing connection
					continue
				}
				// For other errors, log as error but continue processing
				// Only close connection for critical errors (idle timeout, etc.)
				if strings.Contains(err.Error(), "idle timeout") ||
					strings.Contains(err.Error(), "connection timeout") {
					log.Printf("OpenConnect: Critical error for user %s: %v (closing connection)", tc.User.Username, err)
					return err
				}
				log.Printf("OpenConnect: Error processing packet type 0x%02x for user %s: %v (continuing)", packet.Type, tc.User.Username, err)
				// Continue processing other packets instead of closing connection
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

			// If we couldn't find a valid header and have data
			// This is normal for MTU detection data or other non-CSTP data packets
			// We silently ignore these and reset the parser when buffer gets too large
			if offset > p.bufLen-cstpHeaderLen {
				// No valid header found in buffer
				// Reset only if buffer exceeds maximum packet size (maxPacketSize = 2000)
				// This ensures normal large packets won't be incorrectly reset
				// Buffer size is maxPacketSize*2 (4000), so we reset when it exceeds maxPacketSize
				// to allow room for packet fragmentation and assembly
				if p.bufLen > maxPacketSize {
					// Buffer exceeds maximum packet size without finding valid header
					// This is likely MTU detection data or corrupted/non-CSTP data - reset silently
					// This is normal behavior during MTU detection, no need to log
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
			// Some clients may add padding before the IP header, so we need to find the actual IP header
			var actualPayloadStart int = payloadStart
			if p.packetType == PacketTypeData && p.bufLen >= payloadStart+20 {
				// Verify IP header starts correctly (IPv4: 0x45, IPv6: 0x60)
				if p.buf[payloadStart] == 0x45 {
					// IPv4 packet detected - no logging needed for normal operation
					actualPayloadStart = payloadStart
				} else if (p.buf[payloadStart] & 0xf0) == 0x60 {
					// IPv6 header detected - no logging needed for normal operation
					actualPayloadStart = payloadStart
				} else {
					// Some packets may have padding or non-standard format
					// Try to find IP header at nearby offsets (some clients add padding)
					// Search up to 16 bytes ahead for IP header (some clients add significant padding)
					// But make sure we don't search beyond the actual packet length
					expectedPayloadLen := int(p.packetLen) - payloadStart

					// Only search if we have enough payload space (at least 20 bytes for IP header)
					// If packetLen is too small (e.g., 8 bytes = header only), skip IP header search
					if expectedPayloadLen >= 20 {
						// Only search within the actual packet boundary
						maxSearchOffset := min(payloadStart+min(16, expectedPayloadLen), int(p.packetLen))
						foundIPHeader := false
						for offset := payloadStart; offset < maxSearchOffset && offset <= p.bufLen-20; offset++ {
							// Critical: ensure offset is within current packet boundary
							if offset >= int(p.packetLen) {
								break // Don't search beyond current packet
							}

							if p.buf[offset] == 0x45 || (p.buf[offset]&0xf0) == 0x60 {
								// Verify this is actually an IP header by checking the IP header length field
								// IPv4: byte 0 bits 0-3 = IHL (Internet Header Length), should be >= 5 (20 bytes minimum)
								// IPv6: fixed 40 bytes header
								isValidIPHeader := false
								if p.buf[offset] == 0x45 {
									// IPv4: check IHL (should be 5 for standard 20-byte header)
									ihl := int(p.buf[offset] & 0x0F)
									if ihl >= 5 && ihl <= 15 {
										// Verify the IP header is within packet boundary
										ipHeaderLen := ihl * 4
										if offset+ipHeaderLen <= int(p.packetLen) && offset+ipHeaderLen <= p.bufLen {
											// Additional check: verify version field and total length field make sense
											if offset+4 <= p.bufLen {
												totalLen := int(binary.BigEndian.Uint16(p.buf[offset+2 : offset+4]))
												// Total length should be reasonable (at least IP header length, at most 65535)
												// AND the entire IP packet must fit within current packet boundary
												if totalLen >= ipHeaderLen && totalLen <= 65535 && offset+totalLen <= int(p.packetLen) {
													isValidIPHeader = true
												}
											}
										}
									}
								} else if (p.buf[offset] & 0xf0) == 0x60 {
									// IPv6: fixed header, just check we have enough bytes within packet
									if offset+40 <= int(p.packetLen) && offset+40 <= p.bufLen {
										isValidIPHeader = true
									}
								}

								if isValidIPHeader {
									foundIPHeader = true
									actualPayloadStart = offset
									// IP header found at different offset (padding) - log for debugging
									if offset != payloadStart {
										log.Printf("OpenConnect: Found IP header at offset %d (expected %d, padding: %d bytes)",
											offset, payloadStart, offset-payloadStart)
									}
									break
								}
							}
						}
						if !foundIPHeader && expectedPayloadLen > 20 && p.packetType == PacketTypeData {
							// Only log if we can't find IP header nearby, payload is large enough, and it's a data packet
							previewLen := min(16, p.bufLen-payloadStart)
							log.Printf("OpenConnect: Unexpected data at payload start (offset %d): %x (expected IPv4 0x45 or IPv6 0x60)", payloadStart, p.buf[payloadStart:payloadStart+previewLen])
						}
					} else {
						// Packet too small to contain IP header, skip search
						// This is normal for control packets (DPD, Keepalive, etc.)
					}
				}
			}

			// payloadLen = total packet size - header size
			// Use actualPayloadStart to account for padding before IP header
			// Note: p.packetLen is the total CSTP packet length from header start
			// So payloadLen should be calculated from the CSTP header, not from actualPayloadStart
			// But if there's padding, we need to adjust
			payloadLen := int(p.packetLen) - payloadStart
			if actualPayloadStart > payloadStart {
				// There's padding before IP header, adjust payload length
				// The padding is part of the payload from CSTP perspective, but not from IP perspective
				// So we subtract the padding from the payload length
				paddingLen := actualPayloadStart - payloadStart
				payloadLen = payloadLen - paddingLen
			}
			if payloadLen < 0 {
				log.Printf("OpenConnect: ERROR - Negative payload length: packetLen=%d, payloadStart=%d, actualPayloadStart=%d, payloadLen=%d, bufLen=%d",
					p.packetLen, payloadStart, actualPayloadStart, payloadLen, p.bufLen)
				// If payloadLen is negative, it means the IP header we found is beyond the packet boundary
				// This shouldn't happen with our improved search, but handle it gracefully
				actualPayloadStart = payloadStart
				payloadLen = int(p.packetLen) - payloadStart
				if payloadLen < 0 {
					payloadLen = 0
				}
			}
			payload := make([]byte, payloadLen)
			if payloadLen > 0 && p.bufLen >= int(p.packetLen) {
				// Use explicit end index to ensure correct payload extraction
				// Extract from actualPayloadStart to skip any padding before IP header
				payloadEnd := actualPayloadStart + payloadLen
				if payloadEnd > p.bufLen {
					payloadEnd = p.bufLen
				}
				// Ensure we don't extract beyond packet boundary
				if payloadEnd > int(p.packetLen) {
					payloadEnd = int(p.packetLen)
				}
				if actualPayloadStart < payloadEnd {
					copy(payload, p.buf[actualPayloadStart:payloadEnd])
					// Adjust payload length if we truncated
					if len(payload) > payloadEnd-actualPayloadStart {
						payload = payload[:payloadEnd-actualPayloadStart]
					}
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
						log.Printf("OpenConnect: Extracted ICMP %s packet from payload: %s -> %s, payloadLen=%d, actualPayloadStart=%d, packetLen=%d",
							icmpTypeStr, srcIP.String(), dstIP.String(), len(payload), actualPayloadStart, p.packetLen)
					}
				} else {
					// Invalid extraction range
					log.Printf("OpenConnect: WARNING - Invalid payload extraction range: actualPayloadStart=%d, payloadEnd=%d, packetLen=%d",
						actualPayloadStart, payloadEnd, p.packetLen)
					payload = nil
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
		// Keepalive received, check idle timeout
		log.Printf("OpenConnect: recv LinkCstp Keepalive - user: %s, IP: %s, remote: %s",
			tc.User.Username, tc.IP.String(), tc.Conn.RemoteAddr())

		// 更新最后数据包时间（包括心跳包）
		tc.lastDataTime = time.Now().Unix()

		// 检查空闲超时（如果启用）
		if tc.idleTimeout > 0 {
			now := time.Now().Unix()
			lastTime := tc.lastDataTime
			if lastTime < (now - tc.idleTimeout) {
				log.Printf("OpenConnect: IdleTimeout - user: %s, IP: %s, remote: %s, lastTime: %d",
					tc.User.Username, tc.IP.String(), tc.Conn.RemoteAddr(), lastTime)
				return fmt.Errorf("idle timeout")
			}
		}

		return nil
	case PacketTypeDisconnect:
		// DISCONNECT (0x05) - terminate session (normal operation, not an error)
		// Note: PacketTypeError is also 0x05 but is handled separately in error detection
		// Return a special error that will be handled gracefully by the caller
		return fmt.Errorf("disconnect requested")
	case PacketTypeDPD:
		return tc.processDPDPacket(payload)
	case PacketTypeDPDResp:
		// DPD response from client; update last activity time
		tc.lastDataTime = time.Now().Unix()
		return nil
	default:
		// Log unknown packet types but don't crash - this could be DTLS protocol messages
		log.Printf("OpenConnect: Unknown packet type: 0x%02x, length: %d", packetType, len(payload))
		// For unknown packet types, silently skip
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

	// 验证数据包格式（使用统一的验证函数，确保后端验证一致性）
	if err := validateIPPacket(payload); err != nil {
		// IPv6 数据包是预期的，静默跳过（系统只支持 IPv4）
		if IsUnsupportedIPVersion(err) {
			return nil // 静默跳过 IPv6 数据包
		}
		// 其他错误记录日志
		log.Printf("OpenConnect: Invalid packet from user %s: %v", tc.User.Username, err)
		return nil // 跳过无效数据包
	}

	// 提取IP头长度（用于后续处理）
	ipHeaderLen := int((payload[0] & 0x0F) * 4)
	if ipHeaderLen > len(payload) {
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

	// 更新最后数据包时间
	tc.lastDataTime = time.Now().Unix()

	// ICMP packet logging removed to reduce latency
	// Uncomment for debugging if needed:
	// if protocol == 1 { // ICMP
	// 	icmpType := "unknown"
	// 	if len(payload) >= 28 {
	// 		icmpTypeCode := payload[20] // ICMP type is at offset 20 (after IP header)
	// 		switch icmpTypeCode {
	// 		case 0:
	// 			icmpType = "echo reply"
	// 		case 8:
	// 			icmpType = "echo request"
	// 		case 3:
	// 			icmpType = "destination unreachable"
	// 		case 11:
	// 			icmpType = "time exceeded"
	// 		default:
	// 			icmpType = fmt.Sprintf("type %d", icmpTypeCode)
	// 		}
	// 	}
	// 	vpn.LogPacketAlways("OpenConnect: Processing ICMP %s packet from %s to %s (length: %d)",
	// 		icmpType, srcIP.String(), dstIP.String(), len(payload))
	// } else {
	// 	vpn.LogPacket("OpenConnect: Processing data packet from %s to %s (protocol: %d, length: %d)",
	// 		srcIP.String(), dstIP.String(), protocol, len(payload))
	// }

	// OPTIMIZATION: Check if this is client-to-client communication
	// If so, forward directly without going through TUN device (faster path)
	// Get VPN network configuration
	cfg := tc.VPNServer.GetConfig()
	if cfg != nil {
		ipNet, err := parseVPNNetwork(cfg.VPN.Network)
		if err == nil {
			// 获取服务器VPN IP（后端验证的关键）
			serverVPNIP := getServerVPNIP(ipNet)

			// 检查是否是客户端到客户端通信（Case 3）
			if isVPNInternalTraffic(srcIP, dstIP, ipNet) && !dstIP.Equal(serverVPNIP) {
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
	// Instead, we rely on kernel's conntrack and routing to handle NAT via nftables
	// or eBPF TC hook (if implemented). The kernel will automatically track connections
	// and route response packets back to the VPN client.
	if tc.TUNDevice != nil {
		// Write packet to TUN device WITHOUT modifying it
		// The kernel's conntrack will track the connection, and NAT will be handled
		// by the kernel's netfilter subsystem (nftables) or eBPF TC hook
		_, err := tc.TUNDevice.Write(payload)
		if err != nil {
			log.Printf("OpenConnect: Failed to write to TUN device: %v", err)
			return fmt.Errorf("failed to write to TUN: %w", err)
		}
		// ICMP packet logging removed to reduce latency
		// Uncomment for debugging if needed:
		// if protocol == 1 { // ICMP
		// 	icmpType := "unknown"
		// 	if len(payload) >= 20+8 {
		// 		icmpTypeCode := payload[20] // ICMP type is at offset 20 (after IP header)
		// 		switch icmpTypeCode {
		// 		case 0:
		// 			icmpType = "echo reply"
		// 		case 8:
		// 			icmpType = "echo request"
		// 		case 3:
		// 			icmpType = "destination unreachable"
		// 		case 11:
		// 			icmpType = "time exceeded"
		// 		default:
		// 			icmpType = fmt.Sprintf("type %d", icmpTypeCode)
		// 		}
		// 	}
		// 	vpn.LogPacketAlways("OpenConnect: Wrote %d bytes (ICMP %s) to TUN device (packet from %s to %s)",
		// 		n, icmpType, srcIP.String(), dstIP.String())
		// } else {
		// 	vpn.LogPacket("OpenConnect: Wrote %d bytes to TUN device (packet from %s to %s, protocol: %d)",
		// 		n, srcIP.String(), dstIP.String(), protocol)
		// }
	} else {
		log.Printf("OpenConnect: TUN device is nil, cannot forward packet")
	}

	return nil
}

// processDPDPacket processes a Dead Peer Detection packet
// IMPORTANT: CSTP (TCP) 和 DTLS (UDP) 是分开的，两个互不干涉
// - 如果从 TCP 通道收到 DPD-REQ，只通过 TCP 发送 DPD-RESP
// - 如果从 DTLS 通道收到 DPD-REQ，只通过 DTLS 发送 DPD-RESP（在 dtls.go 中处理）
// - 两个通道独立处理，不互相影响
func (tc *TunnelClient) processDPDPacket(payload []byte) error {
	// Update last data time for DPD packets
	tc.lastDataTime = time.Now().Unix()

	// Reply with DPD response on TCP only (CSTP channel)
	// Note: This is called when DPD-REQ is received on TCP channel
	log.Printf("OpenConnect: Received DPD-REQ on TCP channel from user %s, sending DPD-RESP on TCP", tc.User.Username)
	return tc.sendPacket(PacketTypeDPDResp, payload)
}

// logPolicyDenial 记录策略拒绝日志（统一格式，减少重复代码）
func logPolicyDenial(hookName, username string, ctx *policy.Context, protocol byte) {
	if protocol == 6 || protocol == 17 { // TCP or UDP - 包含端口信息
		log.Printf("OpenConnect: [POLICY DENY] %s hook denied packet: User=%s, Src=%s:%d, Dst=%s:%d, Protocol=%s",
			hookName, username, ctx.SrcIP, ctx.SrcPort, ctx.DstIP, ctx.DstPort, ctx.Protocol)
	} else {
		log.Printf("OpenConnect: [POLICY DENY] %s hook denied packet: User=%s, Src=%s, Dst=%s, Protocol=%s",
			hookName, username, ctx.SrcIP, ctx.DstIP, ctx.Protocol)
	}
}

// performPolicyCheck handles the policy check logic based on whether eBPF is enabled
// This function reduces code duplication by centralizing the policy check logic
// 后端验证的关键：无论客户端如何配置，服务端都必须进行策略验证
func (tc *TunnelClient) performPolicyCheck(packet []byte) error {
	// 验证数据包格式（后端验证的关键步骤）
	if err := validateIPPacket(packet); err != nil {
		// IPv6 数据包是预期的，静默跳过（系统只支持 IPv4）
		if IsUnsupportedIPVersion(err) {
			return nil // 静默跳过 IPv6 数据包，不进行策略检查
		}
		log.Printf("OpenConnect: [POLICY CHECK] Invalid packet format: %v", err)
		return fmt.Errorf("invalid packet format: %w", err)
	}

	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	// 检查是否是VPN内部流量（客户端到客户端或客户端到服务器）
	// VPN内部流量不经过eth0，eBPF无法处理，必须在用户空间进行完整策略检查
	isVPNInternal := false
	cfg := tc.VPNServer.GetConfig()
	if cfg != nil {
		ipNet, err := parseVPNNetwork(cfg.VPN.Network)
		if err == nil {
			// 如果源和目标都在VPN网络中，则是VPN内部流量
			isVPNInternal = isVPNInternalTraffic(srcIP, dstIP, ipNet)
		}
	}

	ebpfProgram := tc.VPNServer.GetEBPFProgram()

	// 策略检查日志已移除以减少延迟
	// 如需调试，可取消注释：
	// protocol := packet[9]
	// protocolName := getProtocolName(protocol)
	// if protocol == 1 || (isVPNInternal && (protocol == 6 || protocol == 17)) {
	// 	log.Printf("OpenConnect: [POLICY CHECK] performPolicyCheck: Protocol=%s, Src=%s, Dst=%s, isVPNInternal=%v, ebpfProgram=%v",
	// 		protocolName, srcIP.String(), dstIP.String(), isVPNInternal, ebpfProgram != nil)
	// }

	if ebpfProgram == nil || isVPNInternal {
		// 无eBPF，或VPN内部流量（eBPF无法处理VPN内部流量）
		// 必须在用户空间对所有协议（ICMP、TCP、UDP等）进行完整策略检查
		return tc.checkPolicy(packet)
	} else {
		// eBPF已启用且这是外部流量 - 进行轻量级检查
		// eBPF将在内核层面处理外部流量的策略检查
		return tc.checkPolicyLightweight(packet)
	}
}

// checkPolicyLightweight performs a lightweight policy check
// This is used when eBPF is enabled - eBPF handles most policy checks
// This function only checks critical policies that can't be handled by eBPF
// 后端验证的关键：即使eBPF处理了大部分检查，仍需要基本的验证
func (tc *TunnelClient) checkPolicyLightweight(packet []byte) error {
	// 基本验证：确保数据包格式正确
	if err := validateIPPacket(packet); err != nil {
		// IPv6 数据包是预期的，静默跳过（系统只支持 IPv4）
		if IsUnsupportedIPVersion(err) {
			return nil // 静默跳过 IPv6 数据包
		}
		return fmt.Errorf("invalid packet format: %w", err)
	}
	// 完整的策略检查由eBPF XDP在内核层面处理
	// 这里可以添加eBPF无法处理的额外检查
	return nil
}

// checkPolicy checks if the packet is allowed by policy
// 后端验证的核心：无论客户端如何配置路由，服务端都必须进行完整的策略验证
func (tc *TunnelClient) checkPolicy(packet []byte) error {
	if tc.VPNServer == nil {
		return nil
	}

	policyMgr := tc.VPNServer.GetPolicyManager()
	if policyMgr == nil {
		return nil
	}

	// 验证数据包格式（后端验证的关键步骤）
	if err := validateIPPacket(packet); err != nil {
		// IPv6 数据包是预期的，静默跳过（系统只支持 IPv4）
		if IsUnsupportedIPVersion(err) {
			return nil // 静默跳过 IPv6 数据包
		}
		return fmt.Errorf("invalid packet format: %w", err)
	}

	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])
	protocol := packet[9]

	// 创建策略上下文
	ctx := policy.NewContext()
	ctx.UserID = tc.User.ID
	ctx.VPNIP = tc.IP.String()
	ctx.ClientIP = tc.Conn.RemoteAddr().String()
	ctx.SrcIP = srcIP.String()
	ctx.DstIP = dstIP.String()
	netProtocol := getProtocolName(protocol)

	// 如果是TCP/UDP，提取端口信息
	if protocol == 6 || protocol == 17 { // TCP or UDP
		if len(packet) >= 24 {
			ctx.SrcPort = binary.BigEndian.Uint16(packet[20:22])
			ctx.DstPort = binary.BigEndian.Uint16(packet[22:24])
		}
		// 从目标端口推断应用层协议
		ctx.Protocol = inferApplicationProtocol(netProtocol, ctx.DstPort)
	} else {
		ctx.Protocol = netProtocol
	}

	// 根据数据包流向确定需要检查的hook点
	// - 客户端到客户端：PRE_ROUTING + FORWARD
	// - 客户端到服务器：PRE_ROUTING + INPUT
	// - 外部流量：PRE_ROUTING + POST_ROUTING
	cfg := tc.VPNServer.GetConfig()
	isClientToClient := false
	isClientToServer := false
	if cfg != nil {
		ipNet, err := parseVPNNetwork(cfg.VPN.Network)
		if err == nil {
			if isVPNInternalTraffic(srcIP, dstIP, ipNet) {
				// 源和目标都在VPN网络中
				// 检查目标是否是服务器VPN IP
				serverVPNIP := getServerVPNIP(ipNet)
				if dstIP.Equal(serverVPNIP) {
					isClientToServer = true
				} else {
					isClientToClient = true
				}
			}
		}
	}

	// Check PRE_ROUTING hook (always checked)
	// Policy check logging removed to reduce latency
	// Uncomment for debugging if needed:
	// if protocol == 1 || (isClientToClient || isClientToServer) && (protocol == 6 || protocol == 17) {
	// 	log.Printf("OpenConnect: [POLICY CHECK] Checking PRE_ROUTING hook: User=%s, Src=%s, Dst=%s, Protocol=%s, isClientToClient=%v, isClientToServer=%v",
	// 		tc.User.Username, ctx.SrcIP, ctx.DstIP, ctx.Protocol, isClientToClient, isClientToServer)
	// }
	action := policyMgr.ExecutePolicies(policy.HookPreRouting, ctx)
	// Uncomment for debugging if needed:
	// if protocol == 1 || (isClientToClient || isClientToServer) && (protocol == 6 || protocol == 17) {
	// 	log.Printf("OpenConnect: [POLICY CHECK] PRE_ROUTING hook result: action=%d (0=ALLOW, 1=DENY, 2=REDIRECT, 3=LOG)",
	// 		action)
	// }
	if action == policy.ActionDeny {
		// 记录策略拒绝日志（所有协议）
		logPolicyDenial("PRE_ROUTING", tc.User.Username, ctx, protocol)
		return fmt.Errorf("packet denied by PRE_ROUTING policy")
	}

	// Check additional hook points based on packet flow
	if isClientToClient {
		// Client-to-client: check FORWARD hook
		forwardAction := policyMgr.ExecutePolicies(policy.HookForward, ctx)
		if forwardAction == policy.ActionDeny {
			logPolicyDenial("FORWARD", tc.User.Username, ctx, protocol)
			return fmt.Errorf("packet denied by FORWARD policy")
		}
		if forwardAction != policy.ActionAllow {
			action = forwardAction
		}
	} else if isClientToServer {
		// Client-to-server: check INPUT hook
		// Policy check logging removed to reduce latency
		// Uncomment for debugging if needed:
		// if protocol == 1 || protocol == 6 || protocol == 17 {
		// 	log.Printf("OpenConnect: [POLICY CHECK] Checking INPUT hook: User=%s, Src=%s, Dst=%s, Protocol=%s",
		// 		tc.User.Username, ctx.SrcIP, ctx.DstIP, ctx.Protocol)
		// }
		inputAction := policyMgr.ExecutePolicies(policy.HookInput, ctx)
		// Uncomment for debugging if needed:
		// if protocol == 1 || protocol == 6 || protocol == 17 {
		// 	log.Printf("OpenConnect: [POLICY CHECK] INPUT hook result: action=%d (0=ALLOW, 1=DENY, 2=REDIRECT, 3=LOG)",
		// 		inputAction)
		// }
		if inputAction == policy.ActionDeny {
			logPolicyDenial("INPUT", tc.User.Username, ctx, protocol)
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

// BuildCSTPPacket builds a CSTP packet with the given type and payload
// Returns the packet bytes without sending it
func (tc *TunnelClient) BuildCSTPPacket(packetType byte, data []byte) []byte {
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

	return fullPacket
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

	// Use BuildCSTPPacket to build the packet
	fullPacket := tc.BuildCSTPPacket(packetType, data)
	payloadLen := uint16(len(data))

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
// IMPORTANT: CSTP (TCP) 和 DTLS (UDP) 是分开的，两个互不干涉
// - TCP keepalive: 只通过 TCP 通道发送（CSTP 通道）
// - DTLS keepalive: 只通过 DTLS 通道发送（在 dtls.go 的 handleDTLSConnection 中独立处理）
// - 如果客户端禁用了 UDP (--disable-udp)，DTLS 连接不存在，不会发送 DTLS keepalive
// 两个通道独立处理，各自在自己的超时时发送自己的 keepalive
func (tc *TunnelClient) sendKeepalive() error {
	// Send TCP keepalive only (CSTP channel)
	// Note: DTLS keepalive is handled independently in dtls.go when DTLS connection times out
	log.Printf("OpenConnect: Sending keepalive on TCP channel for user %s", tc.User.Username)
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
// Only includes protocols that are actually supported by the frontend for audit logging
func inferApplicationProtocol(netProtocol string, dstPort uint16) string {
	// If not TCP or UDP, return network protocol as-is
	if netProtocol != "tcp" && netProtocol != "udp" {
		return netProtocol
	}

	// Only include protocols supported by frontend audit log configuration:
	// tcp, udp, http, https, ssh, ftp, smtp, mysql, dns, icmp
	switch dstPort {
	case 20, 21:
		return "ftp"
	case 22:
		return "ssh"
	case 25:
		return "smtp"
	case 53:
		if netProtocol == "udp" {
			return "dns"
		}
		return netProtocol // TCP DNS is less common
	case 80:
		return "http"
	case 443:
		return "https"
	case 3306:
		return "mysql"
	default:
		// Return network protocol if no application protocol can be inferred
		return netProtocol
	}
}

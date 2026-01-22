package openconnect

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/vpn"
	"github.com/fisker/zvpn/vpn/policy"
)

const (
	PacketTypeData       = 0x00
	PacketTypeDPDReq     = 0x03
	PacketTypeDPDResp    = 0x04
	PacketTypeDisconnect = 0x05
	PacketTypeKeepalive  = 0x07
	PacketTypeCompressed = 0x08
	PacketTypeTerminate  = 0x09
	PacketTypeError      = 0x05

	PacketTypeDPD = PacketTypeDPDReq
)

const cstpHeaderLen = 5
const cstpHeaderLenWithSTF = 8

const maxPacketSize = 2000

type CSTPParser struct {
	buf             []byte
	bufLen          int
	state           parserState
	packetLen       uint16
	packetType      byte
	useLittleEndian bool
}

type parserState int

const (
	stateNeedHeader parserState = iota
	stateNeedPayload
)

type TunnelClient struct {
	User            *models.User
	Conn            net.Conn
	IP              net.IP
	VPNServer       *vpn.VPNServer
	TUNDevice       *vpn.TUNDevice
	parser          *CSTPParser
	useLittleEndian bool
	lastDataTime    int64
	idleTimeout     int64
}

func NewTunnelClient(user *models.User, conn net.Conn, ip net.IP, vpnServer *vpn.VPNServer, tunDevice *vpn.TUNDevice) *TunnelClient {
	now := time.Now().Unix()
	tc := &TunnelClient{
		User:         user,
		Conn:         conn,
		IP:           ip,
		VPNServer:    vpnServer,
		TUNDevice:    tunDevice,
		lastDataTime: now,
		idleTimeout:  0,
		parser: &CSTPParser{
			buf:    make([]byte, maxPacketSize*2),
			bufLen: 0,
			state:  stateNeedHeader,
		},
	}

	return tc
}

func (tc *TunnelClient) HandleTunnelData() error {

	log.Printf("OpenConnect: Starting tunnel handler for user %s (IP: %s)", tc.User.Username, tc.IP.String())

	readBuf := make([]byte, 4096)
	timeoutCount := 0
	const maxTimeouts = 3

	readTimeout := 30 * time.Second
	if tc.VPNServer != nil {
		if cfg := tc.VPNServer.GetConfig(); cfg != nil {
			cstpKeepalive := cfg.VPN.CSTPKeepalive
			if cstpKeepalive == 0 {
				cstpKeepalive = 20
			}

			readTimeout = time.Duration(cstpKeepalive) * time.Second * 3 / 2
		}
	}

	for {

		if err := tc.Conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return fmt.Errorf("failed to set read deadline: %w", err)
		}

		n, err := tc.Conn.Read(readBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {

				if tc.VPNServer != nil {
					_, stillExists := tc.VPNServer.GetClient(tc.User.ID)
					if !stillExists {
						log.Printf("OpenConnect: 客户端 %s (VPN IP: %s) 已从 VPNServer 中移除，停止发送 keepalive",
							tc.User.Username, tc.IP.String())
						return fmt.Errorf("client disconnected")
					}
				}

				timeoutCount++
				if timeoutCount >= maxTimeouts {
					log.Printf("OpenConnect: Too many timeouts for user %s", tc.User.Username)
					return fmt.Errorf("connection timeout")
				}

				if err := tc.sendKeepalive(); err != nil {
					log.Printf("OpenConnect: Failed to send keepalive: %v", err)

					return err
				}
				continue
			}

			if err == io.EOF {
				log.Printf("OpenConnect: Client closed connection (EOF) for user %s (VPN IP: %s)", tc.User.Username, tc.IP.String())
				return nil
			}

			log.Printf("OpenConnect: Read error for user %s: %v", tc.User.Username, err)
			return err
		}

		timeoutCount = 0

		if err := tc.parser.feed(readBuf[:n]); err != nil {
			log.Printf("OpenConnect: Parser feed error for user %s: %v", tc.User.Username, err)

			tc.parser.reset()
			continue
		}

		for {
			packet, err := tc.parser.nextPacket()
			if err == io.EOF {

				break
			}
			if err != nil {
				log.Printf("OpenConnect: Error parsing packet for user %s: %v", tc.User.Username, err)

				tc.parser.reset()
				break
			}

			if err := tc.processPacket(packet.Type, packet.Payload); err != nil {

				if packet.Type == PacketTypeDisconnect {
					log.Printf("OpenConnect: Client %s requested disconnect (normal operation) - VPN IP: %s, Time since connection: %v",
						tc.User.Username, tc.IP.String(), time.Since(time.Unix(tc.lastDataTime, 0)))
					log.Printf("OpenConnect: This usually means client received CSTP config but could not apply it (check route configuration)")
					return nil
				}

				if strings.Contains(err.Error(), "unknown packet format") ||
					strings.Contains(err.Error(), "reported unknown packet") {
					log.Printf("OpenConnect: Client reported format error: %v", err)

					continue
				}

				if strings.Contains(err.Error(), "source IP mismatch") {
					log.Printf("OpenConnect: Source IP mismatch for user %s: %v (continuing)", tc.User.Username, err)

					continue
				}

				if strings.Contains(err.Error(), "idle timeout") ||
					strings.Contains(err.Error(), "connection timeout") {
					log.Printf("OpenConnect: Critical error for user %s: %v (closing connection)", tc.User.Username, err)
					return err
				}
				log.Printf("OpenConnect: Error processing packet type 0x%02x for user %s: %v (continuing)", packet.Type, tc.User.Username, err)

			}
		}
	}
}

type ParsedPacket struct {
	Type    byte
	Payload []byte
}

func (p *CSTPParser) feed(data []byte) error {

	if p.bufLen+len(data) > len(p.buf) {

		log.Printf("OpenConnect: Parser buffer overflow (bufLen=%d, dataLen=%d)", p.bufLen, len(data))

		p.reset()
		return nil
	}

	copy(p.buf[p.bufLen:], data)
	p.bufLen += len(data)
	return nil
}

func (p *CSTPParser) nextPacket() (*ParsedPacket, error) {
	for {
		if p.state == stateNeedHeader {

			if p.bufLen < cstpHeaderLenWithSTF {
				return nil, io.EOF
			}

			offset := 0
			foundValidHeader := false

			for offset <= p.bufLen-cstpHeaderLen {

				if offset <= p.bufLen-3 && p.buf[offset] == 'S' && p.buf[offset+1] == 'T' && p.buf[offset+2] == 'F' {

					cstpOffset := offset + 3
					if cstpOffset <= p.bufLen-cstpHeaderLen && p.buf[cstpOffset] == 0x01 {

						packetLenBE := binary.BigEndian.Uint16(p.buf[cstpOffset+1 : cstpOffset+3])
						packetLenLE := binary.LittleEndian.Uint16(p.buf[cstpOffset+1 : cstpOffset+3])
						packetType := p.buf[cstpOffset+3]

						var packetLen uint16

						if packetLenBE <= maxPacketSize {
							packetLen = packetLenBE
						} else if packetLenLE <= maxPacketSize {
							packetLen = packetLenLE

							p.useLittleEndian = true
							log.Printf("OpenConnect: Using little-endian for length field (big-endian gave invalid length %d, little-endian gives %d)",
								packetLenBE, packetLenLE)
						} else {

							packetLen = packetLenBE
						}

						if offset > 0 || packetType == PacketTypeError || packetLen > 500 {
							headerPreview := p.buf[cstpOffset:]
							previewLen := 16
							if len(headerPreview) < previewLen {
								previewLen = len(headerPreview)
							}

						}

						totalPacketSize := cstpHeaderLenWithSTF + int(packetLen)
						if packetLen <= maxPacketSize && totalPacketSize <= maxPacketSize+8 {

							availableBytes := p.bufLen - cstpOffset

							if int(packetLen) > availableBytes+100 {

								searchStart := 0
								searchEnd := p.bufLen
								if searchEnd > 100 {
									searchEnd = 100
								}

								bufferSlice := string(p.buf[searchStart:searchEnd])

								if strings.Contains(bufferSlice, "Unknown") ||
									strings.Contains(bufferSlice, "unknown") ||
									strings.Contains(bufferSlice, "packet") ||
									strings.Contains(bufferSlice, "received") {

									var text string
									textStart := -1
									textEnd := -1

									for i := searchStart; i < searchEnd; i++ {
										b := p.buf[i]
										if (b >= 32 && b < 127) || b == '\n' || b == '\r' {
											textStart = i
											break
										}
									}

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

										if textEnd > textStart {
											text = string(p.buf[textStart:textEnd])
											text = strings.TrimSpace(text)
										}
									}

									if text != "" {

										log.Printf("OpenConnect: ⚠️ Detected error message instead of CSTP packet: %q (length field says %d but only %d bytes available)",
											text, packetLen, availableBytes)

										p.bufLen = 0
										p.state = stateNeedHeader

										return &ParsedPacket{
											Type:    PacketTypeError,
											Payload: []byte(text),
										}, nil
									}
								}

								offset++
								continue
							}

							if offset > 0 {

								copy(p.buf, p.buf[offset:])
								p.bufLen -= offset
							}

							p.packetType = packetType

							p.packetLen = uint16(cstpHeaderLenWithSTF + int(packetLen))
							p.state = stateNeedPayload

							foundValidHeader = true
							break
						} else {

							if offset > 0 {

								p.reset()
								return nil, io.EOF
							}
						}
					}
				}

				if p.buf[offset] == 0x01 && offset <= p.bufLen-8 {

					packetType := p.buf[offset+1]
					packetLenBE := binary.BigEndian.Uint16(p.buf[offset+4 : offset+6])
					packetLenLE := binary.LittleEndian.Uint16(p.buf[offset+4 : offset+6])

					var packetLen uint16
					if packetLenBE <= maxPacketSize {
						packetLen = packetLenBE
					} else if packetLenLE <= maxPacketSize {
						packetLen = packetLenLE

						p.useLittleEndian = true
						log.Printf("OpenConnect: Using little-endian for length field (big-endian gave invalid length %d, little-endian gives %d)",
							packetLenBE, packetLenLE)
					} else {

						packetLen = packetLenBE
					}

					totalPacketSize := 8 + int(packetLen)
					if packetLen <= maxPacketSize && totalPacketSize <= maxPacketSize+8 {

						if offset > 0 {

							copy(p.buf, p.buf[offset:])
							p.bufLen -= offset
						}

						p.packetType = packetType

						p.packetLen = uint16(8 + int(packetLen))
						p.state = stateNeedPayload
						foundValidHeader = true
						break
					}
				}

				offset++
			}

			if !foundValidHeader {

			} else {

				continue
			}

			if offset > p.bufLen-cstpHeaderLen {

				if p.bufLen > maxPacketSize {

					p.reset()
				}
				return nil, io.EOF
			}

		}

		if p.state == stateNeedPayload {

			if p.bufLen < int(p.packetLen) {
				return nil, io.EOF
			}

			var payloadStart int
			if p.bufLen >= 3 && p.buf[0] == 'S' && p.buf[1] == 'T' && p.buf[2] == 'F' {

				payloadStart = cstpHeaderLenWithSTF
			} else {

				payloadStart = 8
			}

			var actualPayloadStart int = payloadStart
			if p.packetType == PacketTypeData && p.bufLen >= payloadStart+20 {

				if p.buf[payloadStart] == 0x45 {

					actualPayloadStart = payloadStart
				} else if (p.buf[payloadStart] & 0xf0) == 0x60 {

					actualPayloadStart = payloadStart
				} else {

					expectedPayloadLen := int(p.packetLen) - payloadStart

					if expectedPayloadLen >= 20 {

						maxSearchOffset := min(payloadStart+min(16, expectedPayloadLen), int(p.packetLen))
						foundIPHeader := false
						for offset := payloadStart; offset < maxSearchOffset && offset <= p.bufLen-20; offset++ {

							if offset >= int(p.packetLen) {
								break
							}

							if p.buf[offset] == 0x45 || (p.buf[offset]&0xf0) == 0x60 {

								isValidIPHeader := false
								if p.buf[offset] == 0x45 {

									ihl := int(p.buf[offset] & 0x0F)
									if ihl >= 5 && ihl <= 15 {

										ipHeaderLen := ihl * 4
										if offset+ipHeaderLen <= int(p.packetLen) && offset+ipHeaderLen <= p.bufLen {

											if offset+4 <= p.bufLen {
												totalLen := int(binary.BigEndian.Uint16(p.buf[offset+2 : offset+4]))

												if totalLen >= ipHeaderLen && totalLen <= 65535 && offset+totalLen <= int(p.packetLen) {
													isValidIPHeader = true
												}
											}
										}
									}
								} else if (p.buf[offset] & 0xf0) == 0x60 {

									if offset+40 <= int(p.packetLen) && offset+40 <= p.bufLen {
										isValidIPHeader = true
									}
								}

								if isValidIPHeader {
									foundIPHeader = true
									actualPayloadStart = offset

									if offset != payloadStart {
										log.Printf("OpenConnect: Found IP header at offset %d (expected %d, padding: %d bytes)",
											offset, payloadStart, offset-payloadStart)
									}
									break
								}
							}
						}
						if !foundIPHeader && expectedPayloadLen > 20 && p.packetType == PacketTypeData {

							previewLen := min(16, p.bufLen-payloadStart)
							log.Printf("OpenConnect: Unexpected data at payload start (offset %d): %x (expected IPv4 0x45 or IPv6 0x60)", payloadStart, p.buf[payloadStart:payloadStart+previewLen])
						}
					} else {

					}
				}
			}

			payloadLen := int(p.packetLen) - payloadStart
			if actualPayloadStart > payloadStart {

				paddingLen := actualPayloadStart - payloadStart
				payloadLen = payloadLen - paddingLen
			}
			if payloadLen < 0 {
				log.Printf("OpenConnect: ERROR - Negative payload length: packetLen=%d, payloadStart=%d, actualPayloadStart=%d, payloadLen=%d, bufLen=%d",
					p.packetLen, payloadStart, actualPayloadStart, payloadLen, p.bufLen)

				actualPayloadStart = payloadStart
				payloadLen = int(p.packetLen) - payloadStart
				if payloadLen < 0 {
					payloadLen = 0
				}
			}
			payload := make([]byte, payloadLen)
			if payloadLen > 0 && p.bufLen >= int(p.packetLen) {

				payloadEnd := actualPayloadStart + payloadLen
				if payloadEnd > p.bufLen {
					payloadEnd = p.bufLen
				}

				if payloadEnd > int(p.packetLen) {
					payloadEnd = int(p.packetLen)
				}
				if actualPayloadStart < payloadEnd {
					copy(payload, p.buf[actualPayloadStart:payloadEnd])

					if len(payload) > payloadEnd-actualPayloadStart {
						payload = payload[:payloadEnd-actualPayloadStart]
					}

				} else {

					log.Printf("OpenConnect: WARNING - Invalid payload extraction range: actualPayloadStart=%d, payloadEnd=%d, packetLen=%d",
						actualPayloadStart, payloadEnd, p.packetLen)
					payload = nil
				}
			} else {

				if p.packetType == PacketTypeDPD || p.packetType == PacketTypeDPDResp || p.packetType == PacketTypeKeepalive {

				} else if payloadLen == 0 && p.packetType == PacketTypeData {

					if p.bufLen >= int(p.packetLen) {
						log.Printf("OpenConnect: WARNING - Data packet has zero payload: packetLen=%d, bufLen=%d, payloadStart=%d",
							p.packetLen, p.bufLen, payloadStart)
					}
				} else {

				}
			}

			packet := &ParsedPacket{
				Type:    p.packetType,
				Payload: payload,
			}

			actualPacketSize := int(p.packetLen)

			if actualPacketSize > p.bufLen {
				log.Printf("OpenConnect: Warning: packetLen (%d) > bufLen (%d), resetting parser", p.packetLen, p.bufLen)
				p.reset()
				return nil, io.EOF
			}

			if actualPacketSize < p.bufLen {

				leftoverLen := p.bufLen - actualPacketSize
				if leftoverLen > 0 && leftoverLen < 20 {

					previewLen := leftoverLen
					if previewLen > 16 {
						previewLen = 16
					}

				}
			}

			copy(p.buf, p.buf[actualPacketSize:])
			p.bufLen -= actualPacketSize

			p.state = stateNeedHeader
			p.packetLen = 0
			p.packetType = 0

			if packet.Type > PacketTypeError {

				if packet.Type == 0x08 && payloadLen > 0 && payloadLen < 100 {

					msg := string(payload)
					if len(msg) > 0 && (msg[0] >= 32 && msg[0] < 127) {
						log.Printf("OpenConnect: Client error message (type 0x08): %q", msg)
					}
				}

				continue
			}

			return packet, nil
		}
	}
}

func (p *CSTPParser) reset() {
	p.bufLen = 0
	p.state = stateNeedHeader
	p.packetLen = 0
	p.packetType = 0
}

func (tc *TunnelClient) processPacket(packetType byte, payload []byte) error {
	switch packetType {
	case PacketTypeData:
		return tc.processDataPacket(payload)
	case PacketTypeKeepalive:

		tc.lastDataTime = time.Now().Unix()

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

		return fmt.Errorf("disconnect requested")
	case PacketTypeDPD:
		return tc.processDPDPacket(payload)
	case PacketTypeDPDResp:

		tc.lastDataTime = time.Now().Unix()
		return nil
	default:

		log.Printf("OpenConnect: Unknown packet type: 0x%02x, length: %d", packetType, len(payload))

		return nil
	}
}

func (tc *TunnelClient) processDataPacket(payload []byte) error {

	if tc.VPNServer != nil && tc.VPNServer.CompressionMgr != nil {
		cfg := tc.VPNServer.GetConfig()
		if cfg != nil && cfg.VPN.EnableCompression {
			compressionType := vpn.CompressionType(cfg.VPN.CompressionType)
			if compressionType != vpn.CompressionNone {
				decompressed, err := tc.VPNServer.CompressionMgr.Decompress(payload, compressionType)
				if err != nil {
					log.Printf("Warning: Failed to decompress packet from user %s: %v", tc.User.Username, err)

				} else {
					payload = decompressed
				}
			}
		}
	}

	if len(payload) > 0 && len(payload) < 200 {

		if len(payload) >= 2 {

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

				if len(errorMsg) > 5 && (errorMsg[0] >= 'A' && errorMsg[0] <= 'Z' || errorMsg[0] >= 'a' && errorMsg[0] <= 'z') {
					errorCode := payload[0]
					log.Printf("OpenConnect: Client error message in data packet (code: 0x%02x): %q", errorCode, errorMsg)

					return nil
				}
			}
		}
	}

	if err := validateIPPacket(payload); err != nil {

		if IsUnsupportedIPVersion(err) {
			return nil
		}

		log.Printf("OpenConnect: Invalid packet from user %s: %v", tc.User.Username, err)
		return nil
	}

	ipHeaderLen := int((payload[0] & 0x0F) * 4)
	if ipHeaderLen > len(payload) {
		log.Printf("OpenConnect: Invalid IP header length: %d", ipHeaderLen)
		return nil
	}

	srcIP := net.IP(payload[12:16])
	dstIP := net.IP(payload[16:20])

	if !srcIP.Equal(tc.IP) {
		originalSrcIP := srcIP.String()
		log.Printf("OpenConnect: Source IP mismatch: expected %s, got %s (correcting)",
			tc.IP.String(), originalSrcIP)

		if len(payload) >= 16 && tc.IP != nil {
			if ipv4 := tc.IP.To4(); ipv4 != nil {
				copy(payload[12:16], ipv4)
				srcIP = tc.IP
				log.Printf("OpenConnect: Source IP corrected from %s to %s", originalSrcIP, tc.IP.String())
			} else {
				log.Printf("OpenConnect: Warning - VPN IP %s is not IPv4, cannot correct source IP", tc.IP.String())
			}
		}
	}

	tc.lastDataTime = time.Now().Unix()

	var ipNet *net.IPNet
	cfg := tc.VPNServer.GetConfig()
	if cfg != nil {
		var err error
		ipNet, err = parseVPNNetwork(cfg.VPN.Network)
		if err == nil {

			serverVPNIP := getServerVPNIP(ipNet)

			if isVPNInternalTraffic(srcIP, dstIP, ipNet) && !dstIP.Equal(serverVPNIP) {

				vpn.LogPacket("OpenConnect: Direct forwarding packet from client %s to client %s (bypassing TUN device)",
					srcIP.String(), dstIP.String())

				if err := tc.performPolicyCheck(payload); err != nil {
					log.Printf("OpenConnect: Packet denied by policy: %v", err)
					return err
				}

				if err := tc.VPNServer.ForwardPacketToClient(dstIP, payload); err != nil {
					log.Printf("OpenConnect: Failed to forward packet from client %s to %s: %v",
						srcIP.String(), dstIP.String(), err)
				}

				return nil
			}
		}
	}

	if err := tc.performPolicyCheck(payload); err != nil {
		log.Printf("OpenConnect: Packet denied by policy: %v", err)
		return err
	}


	if tc.TUNDevice != nil {
		_, err := tc.TUNDevice.Write(payload)
		if err != nil {
			log.Printf("OpenConnect: Failed to write to TUN device: %v", err)
			return fmt.Errorf("failed to write to TUN: %w", err)
		}

	} else {
		log.Printf("OpenConnect: TUN device is nil, cannot forward packet")
	}

	return nil
}

func (tc *TunnelClient) processDPDPacket(payload []byte) error {

	tc.lastDataTime = time.Now().Unix()

	return tc.sendPacket(PacketTypeDPDResp, payload)
}

func logPolicyDenial(hookName, username string, ctx *policy.Context, protocol byte) {
	if protocol == 6 || protocol == 17 {
		log.Printf("OpenConnect: [POLICY DENY] %s hook denied packet: User=%s, Src=%s:%d, Dst=%s:%d, Protocol=%s",
			hookName, username, ctx.SrcIP, ctx.SrcPort, ctx.DstIP, ctx.DstPort, ctx.Protocol)
	} else {
		log.Printf("OpenConnect: [POLICY DENY] %s hook denied packet: User=%s, Src=%s, Dst=%s, Protocol=%s",
			hookName, username, ctx.SrcIP, ctx.DstIP, ctx.Protocol)
	}
}

func (tc *TunnelClient) performPolicyCheck(packet []byte) error {

	if err := validateIPPacket(packet); err != nil {

		if IsUnsupportedIPVersion(err) {
			return nil
		}
		log.Printf("OpenConnect: [POLICY CHECK] Invalid packet format: %v", err)
		return fmt.Errorf("invalid packet format: %w", err)
	}

	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	isVPNInternal := false
	cfg := tc.VPNServer.GetConfig()
	if cfg != nil {
		ipNet, err := parseVPNNetwork(cfg.VPN.Network)
		if err == nil {

			isVPNInternal = isVPNInternalTraffic(srcIP, dstIP, ipNet)
		}
	}

	ebpfProgram := tc.VPNServer.GetEBPFProgram()

	if ebpfProgram == nil || isVPNInternal {

		return tc.checkPolicy(packet)
	} else {

		return tc.checkPolicyLightweight(packet)
	}
}

func (tc *TunnelClient) checkPolicyLightweight(packet []byte) error {

	if err := validateIPPacket(packet); err != nil {

		if IsUnsupportedIPVersion(err) {
			return nil
		}
		return fmt.Errorf("invalid packet format: %w", err)
	}

	return nil
}

func (tc *TunnelClient) checkPolicy(packet []byte) error {
	if tc.VPNServer == nil {
		return nil
	}

	policyMgr := tc.VPNServer.GetPolicyManager()
	if policyMgr == nil {
		return nil
	}

	if err := validateIPPacket(packet); err != nil {

		if IsUnsupportedIPVersion(err) {
			return nil
		}
		return fmt.Errorf("invalid packet format: %w", err)
	}

	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])
	protocol := packet[9]

	ctx := policy.NewContext()
	ctx.UserID = tc.User.ID
	ctx.VPNIP = tc.IP.String()
	ctx.ClientIP = tc.Conn.RemoteAddr().String()
	ctx.SrcIP = srcIP.String()
	ctx.DstIP = dstIP.String()

	if protocol == 6 || protocol == 17 {
		if len(packet) >= 24 {
			ctx.SrcPort = binary.BigEndian.Uint16(packet[20:22])
			ctx.DstPort = binary.BigEndian.Uint16(packet[22:24])
		}
		if protocol == 6 {
			ctx.Protocol = "tcp"
		} else {
			ctx.Protocol = "udp"
		}
	} else if protocol == 1 {
		ctx.Protocol = "icmp"
	} else {
		ctx.Protocol = fmt.Sprintf("unknown-%d", protocol)
	}

	cfg := tc.VPNServer.GetConfig()
	isClientToClient := false
	isClientToServer := false
	if cfg != nil {
		ipNet, err := parseVPNNetwork(cfg.VPN.Network)
		if err == nil {
			if isVPNInternalTraffic(srcIP, dstIP, ipNet) {

				serverVPNIP := getServerVPNIP(ipNet)
				if dstIP.Equal(serverVPNIP) {
					isClientToServer = true
				} else {
					isClientToClient = true
				}
			}
		}
	}

	action := policyMgr.ExecutePolicies(policy.HookPreRouting, ctx)

	if action == policy.ActionDeny {

		logPolicyDenial("PRE_ROUTING", tc.User.Username, ctx, protocol)
		return fmt.Errorf("packet denied by PRE_ROUTING policy")
	}

	if isClientToClient {

		forwardAction := policyMgr.ExecutePolicies(policy.HookForward, ctx)
		if forwardAction == policy.ActionDeny {
			logPolicyDenial("FORWARD", tc.User.Username, ctx, protocol)
			return fmt.Errorf("packet denied by FORWARD policy")
		}
		if forwardAction != policy.ActionAllow {
			action = forwardAction
		}
	} else if isClientToServer {

		inputAction := policyMgr.ExecutePolicies(policy.HookInput, ctx)

		if inputAction == policy.ActionDeny {
			logPolicyDenial("INPUT", tc.User.Username, ctx, protocol)
			return fmt.Errorf("packet denied by INPUT policy")
		}
		if inputAction != policy.ActionAllow {
			action = inputAction
		}
	} else {

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

		log.Printf("OpenConnect: Packet redirected by policy - User: %s, Src: %s, Dst: %s -> VPN network",
			tc.User.Username, ctx.SrcIP, ctx.DstIP)

		return nil
	case policy.ActionLog:

		log.Printf("OpenConnect: [POLICY LOG] User: %s (ID: %d), Src: %s, Dst: %s, Protocol: %s, SrcPort: %d, DstPort: %d",
			tc.User.Username, ctx.UserID, ctx.SrcIP, ctx.DstIP, ctx.Protocol, ctx.SrcPort, ctx.DstPort)

		return nil
	default:

		return nil
	}
}

func (tc *TunnelClient) BuildCSTPPacket(packetType byte, data []byte) []byte {
	stfLen := 3
	headerLen := 5
	payloadLen := uint16(len(data))
	fullPacket := make([]byte, stfLen+headerLen+len(data))

	fullPacket[0] = 'S'
	fullPacket[1] = 'T'
	fullPacket[2] = 'F'

	fullPacket[3] = 0x01

	binary.BigEndian.PutUint16(fullPacket[4:6], payloadLen)

	fullPacket[6] = packetType

	fullPacket[7] = 0x00

	if len(data) > 0 {
		copy(fullPacket[8:], data)
	}

	return fullPacket
}

func (tc *TunnelClient) sendPacket(packetType byte, data []byte) error {

	fullPacket := tc.BuildCSTPPacket(packetType, data)
	payloadLen := uint16(len(data))

	if vpn.ShouldLogPacket() {

		log.Printf("OpenConnect: Sending packet to user %s: type=0x%02x, payload length=%d (BIG-ENDIAN at byte 4-5), total packet=%d bytes, first 16 bytes: %x",
			tc.User.Username, packetType, payloadLen, len(fullPacket), fullPacket[:min(16, len(fullPacket))])
	}

	if _, err := tc.Conn.Write(fullPacket); err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	return nil
}

func (tc *TunnelClient) sendKeepalive() error {

	return tc.sendPacket(PacketTypeKeepalive, nil)
}


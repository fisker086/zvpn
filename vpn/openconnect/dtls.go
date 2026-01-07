package openconnect

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/pion/logging"
)

const (
	BufferSize = 1500
)

type customLoggerFactory struct {
	DefaultLogLevel logging.LogLevel
}

func (c *customLoggerFactory) NewLogger(scope string) logging.LeveledLogger {
	log.Printf("DTLS: LoggerFactory.NewLogger called for scope: %s (this means DTLS library is active)", scope)
	return &customLogger{scope: scope, level: c.DefaultLogLevel}
}

type customLogger struct {
	scope string
	level logging.LogLevel
}

func (c *customLogger) Trace(msg string) {

}

func (c *customLogger) Tracef(format string, args ...interface{}) {

}

func (c *customLogger) Debug(msg string) {

}

func (c *customLogger) Debugf(format string, args ...interface{}) {

}

func (c *customLogger) Info(msg string) {
	log.Printf("DTLS [%s] INFO: %s", c.scope, msg)
}

func (c *customLogger) Infof(format string, args ...interface{}) {
	log.Printf("DTLS [%s] INFO: "+format, append([]interface{}{c.scope}, args...)...)
}

func (c *customLogger) Warn(msg string) {
	log.Printf("DTLS [%s] WARN: %s", c.scope, msg)
}

func (c *customLogger) Warnf(format string, args ...interface{}) {
	log.Printf("DTLS [%s] WARN: "+format, append([]interface{}{c.scope}, args...)...)
}

func (c *customLogger) Error(msg string) {
	log.Printf("DTLS [%s] ERROR: %s", c.scope, msg)
}

func (c *customLogger) Errorf(format string, args ...interface{}) {
	log.Printf("DTLS [%s] ERROR: "+format, append([]interface{}{c.scope}, args...)...)
}

type dtlsSessionStore struct {
	sessions map[string]*dtlsSessionInfo
	lock     sync.RWMutex
	handler  *Handler
}

type dtlsSessionInfo struct {
	sessionID    []byte
	masterSecret []byte
	expiresAt    time.Time
}

var _ dtls.SessionStore = (*dtlsSessionStore)(nil)

func newDTLSSessionStore(handler *Handler) *dtlsSessionStore {
	return &dtlsSessionStore{
		sessions: make(map[string]*dtlsSessionInfo),
		handler:  handler,
	}
}

func (s *dtlsSessionStore) Set(key []byte, session dtls.Session) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	keyStr := hex.EncodeToString(key)
	log.Printf("DTLS: Session store Set called with key: %s, session ID: %x", keyStr, session.ID)
	s.sessions[keyStr] = &dtlsSessionInfo{
		sessionID:    session.ID,
		masterSecret: session.Secret,
		expiresAt:    time.Now().Add(24 * time.Hour),
	}
	return nil
}

func (s *dtlsSessionStore) Get(key []byte) (dtls.Session, error) {
	keyStr := hex.EncodeToString(key)

	s.lock.RLock()
	info, exists := s.sessions[keyStr]
	now := time.Now()
	s.lock.RUnlock()

	if !exists {
		return dtls.Session{}, errors.New("session not found")
	}

	if now.After(info.expiresAt) {
		s.lock.Lock()
		delete(s.sessions, keyStr)
		s.lock.Unlock()
		return dtls.Session{}, errors.New("session expired")
	}

	return dtls.Session{
		ID:     info.sessionID,
		Secret: info.masterSecret,
	}, nil
}

func (s *dtlsSessionStore) StoreMasterSecret(sessionIDHex string, masterSecretHex string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if masterSecretHex == "" {
		return nil
	}

	masterSecret, err := hex.DecodeString(masterSecretHex)
	if err != nil {
		log.Printf("DTLS: Failed to decode master secret: %v", err)
		return err
	}

	sessionID, err := hex.DecodeString(sessionIDHex)
	if err != nil {
		log.Printf("DTLS: Failed to decode session ID: %v", err)
		return err
	}

	log.Printf("DTLS: Storing master secret for session ID: %s", sessionIDHex)
	s.sessions[sessionIDHex] = &dtlsSessionInfo{
		sessionID:    sessionID,
		masterSecret: masterSecret,
		expiresAt:    time.Now().Add(24 * time.Hour),
	}
	return nil
}

func (s *dtlsSessionStore) Del(key []byte) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	keyStr := hex.EncodeToString(key)
	delete(s.sessions, keyStr)
	return nil
}

var dtlsCipherSuites = map[string]dtls.CipherSuiteID{
	"ECDHE-RSA-AES256-GCM-SHA384": dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-RSA-AES128-GCM-SHA256": dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

func checkDtls12Ciphersuite(ciphersuite string) string {
	if ciphersuite == "" {

		return "ECDHE-RSA-AES256-GCM-SHA384"
	}

	csArr := strings.Split(ciphersuite, ":")
	for _, v := range csArr {
		v = strings.TrimSpace(v)

		if _, ok := dtlsCipherSuites[v]; ok {
			return v
		}
	}

	return "ECDHE-RSA-AES256-GCM-SHA384"
}

func (h *Handler) startRealDTLSServer() error {
	log.Printf("StartDTLSServer called: EnableDTLS=%v", h.config.VPN.EnableDTLS)
	if !h.config.VPN.EnableDTLS {
		log.Printf("DTLS is disabled in config, skipping DTLS server startup")
		return nil
	}

	log.Printf("DTLS: Generating self-signed RSA certificate for DTLS (compatible with OpenConnect)")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}
	cert, err := selfsign.SelfSign(priv)
	if err != nil {
		return fmt.Errorf("failed to generate self-signed certificate: %w", err)
	}
	log.Printf("DTLS: Self-signed RSA certificate generated successfully (RSA 2048-bit)")

	logf := &customLoggerFactory{}
	logf.DefaultLogLevel = logging.LogLevelInfo

	sessStore := newDTLSSessionStore(h)

	h.dtlsSessionStore = sessStore

	dtlsMTU := h.config.VPN.MTU
	if dtlsMTU <= 0 {

		dtlsMTU = BufferSize
		log.Printf("DTLS: MTU not configured, using default: %d", dtlsMTU)
	} else {
		log.Printf("DTLS: Using MTU from config: %d", dtlsMTU)
	}

	supportedCipherSuites := []dtls.CipherSuiteID{

		dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}

	supportedSuites := []string{}
	for _, cs := range supportedCipherSuites {
		if name := dtls.CipherSuiteName(cs); name != "" {
			supportedSuites = append(supportedSuites, name)
		}
	}
	if len(supportedSuites) > 0 {
		log.Printf("DTLS: Configured %d cipher suites: %v", len(supportedCipherSuites), supportedSuites)
		log.Printf("DTLS: Note - Only GCM suites are supported by pion/dtls v2, CBC suites are not available")
	}

	dtlsConfig := &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		ExtendedMasterSecret: dtls.DisableExtendedMasterSecret,
		CipherSuites:         supportedCipherSuites,
		LoggerFactory:        logf,
		MTU:                  dtlsMTU,
		SessionStore:         sessStore,

		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(context.Background(), 5*time.Second)
		},

		ClientAuth: dtls.NoClientCert,
	}

	log.Printf("DTLS: Configuration - MTU: %d, Handshake timeout: 5s, ClientAuth: NoClientCert", dtlsMTU)

	dtlsPort := h.config.VPN.OpenConnectPort
	if h.config.VPN.DTLSPort != "" && h.config.VPN.DTLSPort != h.config.VPN.OpenConnectPort {
		log.Printf("DTLS: WARNING - DTLSPort (%s) != OpenConnectPort (%s), using OpenConnectPort for DTLS",
			h.config.VPN.DTLSPort, h.config.VPN.OpenConnectPort)
		log.Printf("DTLS: OpenConnect clients expect DTLS on the same port as TCP (UDP)")
	}
	addr := fmt.Sprintf("%s:%s", h.config.Server.Host, dtlsPort)
	log.Printf("DTLS: Listening on UDP port %s (same as TCP port %s)", dtlsPort, h.config.VPN.OpenConnectPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve DTLS UDP address: %w", err)
	}

	log.Printf("DTLS: Creating DTLS listener on %s", udpAddr.String())

	ln, err := dtls.Listen("udp", udpAddr, dtlsConfig)
	if err != nil {
		log.Printf("DTLS: Failed to listen on UDP port %s: %v", dtlsPort, err)
		return fmt.Errorf("failed to listen on DTLS UDP port %s: %w", dtlsPort, err)
	}

	h.dtlsListener = ln

	log.Printf("DTLS: Server started on UDP %s (port %s)", addr, dtlsPort)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("DTLS: Listener closed, exiting accept loop")
					return
				}
				errStr := err.Error()
				if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
					log.Printf("DTLS: Handshake timeout - Check UDP port %s and firewall rules", dtlsPort)
				} else if strings.Contains(errStr, "cipher suites") || strings.Contains(errStr, "no shared") {
					log.Printf("DTLS: CRITICAL - Cipher suite mismatch detected!")
					log.Printf("DTLS: Server configured cipher suites:")
					for i, cs := range supportedCipherSuites {
						suiteName := dtls.CipherSuiteName(cs)
						if suiteName != "" {
							log.Printf("DTLS:   [%d] %s (0x%04X)", i, suiteName, uint16(cs))
						} else {
							log.Printf("DTLS:   [%d] 0x%04X (Unknown)", i, uint16(cs))
						}
					}

					if cert.Leaf != nil {
						pubKeyType := "unknown"
						switch cert.Leaf.PublicKey.(type) {
						case *rsa.PublicKey:
							pubKeyType = "RSA"
						case interface{}:

							pubKeyType = fmt.Sprintf("%T", cert.Leaf.PublicKey)
						}
						log.Printf("DTLS: Certificate public key type: %s", pubKeyType)
						log.Printf("DTLS: ECDHE-RSA cipher suites require RSA certificate")
						if pubKeyType != "RSA" {
							log.Printf("DTLS: ERROR - Certificate type mismatch! ECDHE-RSA suites need RSA certificate, but got %s", pubKeyType)
						}
					} else {
						log.Printf("DTLS: WARNING - Cannot determine certificate type (cert.Leaf is nil)")
					}
				} else {
					log.Printf("DTLS: Accept error: %v", err)
				}

				continue
			}

			log.Printf("DTLS: Handshake successful, connection from %s", conn.RemoteAddr())
			go h.handleDTLSConnection(conn)
		}
	}()

	return nil
}

func (h *Handler) handleDTLSConnection(conn net.Conn) {
	defer conn.Close()

	dtlsConn := conn.(*dtls.Conn)
	sessionID := hex.EncodeToString(dtlsConn.ConnectionState().SessionID)

	remoteAddr := conn.RemoteAddr()
	udpAddr, ok := remoteAddr.(*net.UDPAddr)
	if !ok {
		log.Printf("DTLS: Invalid remote address type: %T", remoteAddr)
		return
	}

	h.dtlsLock.Lock()
	var matchedClient *TunnelClient
	var matchedClientKey string
	var matchedVPNIP string

	if sessionID != "" {
		for vpnIP, clientInfo := range h.dtlsClients {
			if clientInfo != nil && clientInfo.DTLSSessionID == sessionID {
				matchedClient = clientInfo.Client
				matchedClientKey = vpnIP
				matchedVPNIP = vpnIP

				clientInfo.DTLSConn = conn
				clientInfo.UDPAddr = udpAddr
				clientInfo.LastSeen = time.Now()
				log.Printf("DTLS: 快速会话ID匹配成功 - 用户: %s, VPN IP: %s, 会话ID: %s",
					clientInfo.Client.User.Username, vpnIP, sessionID[:16]+"...")
				break
			}
		}
	}

	if matchedClient == nil {
		for vpnIP, clientInfo := range h.dtlsClients {
			if clientInfo != nil && clientInfo.UDPAddr != nil &&
				clientInfo.UDPAddr.IP.Equal(udpAddr.IP) && clientInfo.UDPAddr.Port == udpAddr.Port {
				matchedClient = clientInfo.Client
				matchedClientKey = vpnIP
				matchedVPNIP = vpnIP

				if clientInfo.DTLSSessionID == "" && sessionID != "" {
					clientInfo.DTLSSessionID = sessionID
				}

				clientInfo.DTLSConn = conn
				clientInfo.UDPAddr = udpAddr
				clientInfo.LastSeen = time.Now()
				log.Printf("DTLS: UDP地址匹配成功 - 用户: %s, VPN IP: %s, 会话ID: %s",
					clientInfo.Client.User.Username, vpnIP, sessionID[:16]+"...")
				break
			}
		}
	}

	if matchedClient == nil {
		for vpnIP, clientInfo := range h.dtlsClients {
			if clientInfo != nil && clientInfo.Client != nil && clientInfo.DTLSConn == nil {
				matchedClient = clientInfo.Client
				matchedClientKey = vpnIP
				matchedVPNIP = vpnIP

				if sessionID != "" {
					clientInfo.DTLSSessionID = sessionID
				}

				clientInfo.DTLSConn = conn
				clientInfo.UDPAddr = udpAddr
				clientInfo.LastSeen = time.Now()
				log.Printf("DTLS: 回退匹配成功 - 用户: %s, VPN IP: %s, 会话ID: %s",
					clientInfo.Client.User.Username, vpnIP, sessionID[:16]+"...")
				break
			}
		}
	}

	if matchedClient != nil && matchedClientKey != "" {
		if matchedClient.VPNServer != nil {
			if vpnClient, exists := matchedClient.VPNServer.GetClient(matchedClient.User.ID); exists && vpnClient != nil {
				vpnClient.DTLSConn = conn
				log.Printf("DTLS: 更新VPNClient DTLS连接 - 用户: %s (VPN IP: %s)",
					matchedClient.User.Username, matchedClient.IP.String())

				go func() {

					time.Sleep(10 * time.Millisecond)

					dpdResp := []byte{PacketTypeDPDResp}

					for i := 0; i < 3; i++ {
						if conn != nil {
							if _, err := conn.Write(dpdResp); err != nil {
								log.Printf("DTLS: 通过 DTLS 通道发送 DPD 响应 #%d 失败: %v", i+1, err)
								break
							}

							if i < 2 {
								time.Sleep(5 * time.Millisecond)
							}
						}
					}
				}()
			}
		}
	}
	h.dtlsLock.Unlock()

	if matchedClient == nil {
		log.Printf("DTLS: 所有匹配方法都失败 - 会话ID: %s, 远程地址: %s, 当前客户端数量: %d",
			sessionID[:16]+"...", udpAddr, len(h.dtlsClients))
		return
	}

	readBufSize := 4096
	readBuf := make([]byte, readBufSize)

	// 获取客户端信息以判断是否为移动端
	var isMobile bool
	h.dtlsLock.RLock()
	if matchedVPNIP != "" {
		if clientInfo, exists := h.dtlsClients[matchedVPNIP]; exists && clientInfo != nil {
			isMobile = clientInfo.IsMobile
		}
	}
	h.dtlsLock.RUnlock()

	readTimeout := 30 * time.Second
	if matchedClient.VPNServer != nil {
		if cfg := matchedClient.VPNServer.GetConfig(); cfg != nil {
			var keepalive int
			if isMobile {
				// 移动端使用移动端配置
				keepalive = cfg.VPN.MobileKeepalive
				if keepalive == 0 {
					keepalive = 4
				}
			} else {
				// PC端使用PC端配置
				keepalive = cfg.VPN.CSTPKeepalive
				if keepalive == 0 {
					keepalive = 20
				}
			}

			readTimeout = time.Duration(keepalive) * time.Second * 3 / 2
		}
	}

	for {

		if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			log.Printf("DTLS: 设置读取超时失败: %v", err)
			return
		}

		n, err := conn.Read(readBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {

				if matchedVPNIP != "" {

					h.dtlsLock.RLock()
					clientInfo, stillExists := h.dtlsClients[matchedVPNIP]
					h.dtlsLock.RUnlock()

					if stillExists && clientInfo != nil {
						dtlsKeepalive := []byte{PacketTypeKeepalive}
						if _, writeErr := conn.Write(dtlsKeepalive); writeErr != nil {
							log.Printf("DTLS: 发送 keepalive 失败: %v (连接可能已关闭)", writeErr)

							return
						}
					} else {

						log.Printf("DTLS: 客户端 %s (VPN IP: %s) 已从 dtlsClients 中移除，停止发送 keepalive",
							matchedClient.User.Username, matchedVPNIP)
						return
					}
				} else {

					log.Printf("DTLS: matchedClient 为 nil，停止发送 keepalive")
					return
				}
				continue
			}

			if err == io.EOF {
				log.Printf("DTLS: 客户端关闭DTLS连接 - 会话 %s", sessionID[:16]+"...")
				return
			}

			log.Printf("DTLS: 读取错误: %v", err)
			return
		}

		if n < 1 {
			continue
		}

		packetType := readBuf[0]

		switch packetType {
		case PacketTypeKeepalive:

			continue

		case PacketTypeDisconnect:

			log.Printf("DTLS: 收到 DISCONNECT 包，客户端 %s 请求断开 DTLS 连接", matchedClient.User.Username)
			return

		case PacketTypeDPDReq:

			readBuf[0] = PacketTypeDPDResp
			if _, err := conn.Write(readBuf[:n]); err != nil {
				log.Printf("DTLS: 发送 DPD-RESP 失败: %v", err)
			}
			continue

		case PacketTypeDPDResp:

			continue

		case PacketTypeCompressed:

			if n < 2 {
				continue
			}

			fallthrough

		case PacketTypeData:

			if n < 2 {
				continue
			}

			payload := readBuf[1:n]

			if err := matchedClient.processPacket(PacketTypeData, payload); err != nil {
				log.Printf("DTLS: 处理 DATA 包时出错: %v", err)
			}
			continue

		default:

			log.Printf("DTLS: 收到未知包类型: 0x%02x，长度: %d", packetType, n)
			continue
		}
	}
}

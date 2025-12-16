package openconnect

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
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
	// BufferSize DTLS 缓冲区大小
	BufferSize = 1400
)

// customLoggerFactory 自定义日志工厂，确保日志被输出
type customLoggerFactory struct {
	DefaultLogLevel logging.LogLevel
}

func (c *customLoggerFactory) NewLogger(scope string) logging.LeveledLogger {
	log.Printf("DTLS: LoggerFactory.NewLogger called for scope: %s (this means DTLS library is active)", scope)
	return &customLogger{scope: scope, level: c.DefaultLogLevel}
}

// customLogger 自定义 logger，输出到标准日志
type customLogger struct {
	scope string
	level logging.LogLevel
}

func (c *customLogger) Trace(msg string) {
	// 总是输出 Trace 日志以便调试
	log.Printf("DTLS [%s] TRACE: %s", c.scope, msg)
}

func (c *customLogger) Tracef(format string, args ...interface{}) {
	// 总是输出 Trace 日志以便调试
	log.Printf("DTLS [%s] TRACE: "+format, append([]interface{}{c.scope}, args...)...)
}

func (c *customLogger) Debug(msg string) {
	// 总是输出 Debug 日志以便调试
	log.Printf("DTLS [%s] DEBUG: %s", c.scope, msg)
	// 如果包含关键信息，额外输出
	msgLower := strings.ToLower(msg)
	if strings.Contains(msgLower, "handshake") ||
		strings.Contains(msgLower, "client") ||
		strings.Contains(msgLower, "error") ||
		strings.Contains(msgLower, "packet") ||
		strings.Contains(msgLower, "udp") ||
		strings.Contains(msgLower, "read") ||
		strings.Contains(msgLower, "write") ||
		strings.Contains(msgLower, "received") ||
		strings.Contains(msgLower, "sent") {
		log.Printf("DTLS [%s] DEBUG (KEY): %s", c.scope, msg)
	}
}

func (c *customLogger) Debugf(format string, args ...interface{}) {
	// 总是输出 Debug 日志以便调试
	msg := fmt.Sprintf(format, args...)
	log.Printf("DTLS [%s] DEBUG: "+format, append([]interface{}{c.scope}, args...)...)
	// 如果包含关键信息，额外输出
	msgLower := strings.ToLower(msg)
	if strings.Contains(msgLower, "handshake") ||
		strings.Contains(msgLower, "client") ||
		strings.Contains(msgLower, "error") ||
		strings.Contains(msgLower, "packet") ||
		strings.Contains(msgLower, "udp") ||
		strings.Contains(msgLower, "connect") {
		log.Printf("DTLS [%s] DEBUG (KEY): "+format, append([]interface{}{c.scope}, args...)...)
	}
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

// dtlsSessionStore DTLS 会话存储（用于存储和检索 DTLS session）
// 参考 anylink 的实现，需要能够从 session ID 获取 master secret
// anylink 使用 Dtls2MasterSecret 和 Dtls2CSess 来关联 DTLS session 和 TCP session
type dtlsSessionStore struct {
	sessions map[string]*dtlsSessionInfo
	lock     sync.RWMutex
	handler  *Handler // 用于访问客户端信息
	// anylink 使用全局的 Dtls2MasterSecret 和 Dtls2CSess 映射
	// 我们使用 handler 来访问 dtlsClients，从中可以获取客户端信息
}

type dtlsSessionInfo struct {
	sessionID    []byte
	masterSecret []byte
	expiresAt    time.Time
}

// dtlsSessionStore 实现 dtls.SessionStore 接口
var _ dtls.SessionStore = (*dtlsSessionStore)(nil)

func newDTLSSessionStore(handler *Handler) *dtlsSessionStore {
	return &dtlsSessionStore{
		sessions: make(map[string]*dtlsSessionInfo),
		handler:  handler,
	}
}

// Set 存储 DTLS session
func (s *dtlsSessionStore) Set(key []byte, session dtls.Session) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	keyStr := hex.EncodeToString(key)
	log.Printf("DTLS: Session store Set called with key: %s, session ID: %x", keyStr, session.ID)
	s.sessions[keyStr] = &dtlsSessionInfo{
		sessionID:    session.ID,
		masterSecret: session.Secret,
		expiresAt:    time.Now().Add(24 * time.Hour), // 24小时过期
	}
	return nil
}

// Get 获取 DTLS session
// 参考 anylink 的实现：Dtls2MasterSecret(k)
// 注意：如果返回错误，DTLS 库会允许新的握手（不使用 session resumption）
func (s *dtlsSessionStore) Get(key []byte) (dtls.Session, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	keyStr := hex.EncodeToString(key)
	log.Printf("DTLS: Session store Get called with key: %s", keyStr)

	// 首先尝试从存储的 session 中获取
	info, exists := s.sessions[keyStr]
	if exists {
		// 检查是否过期
		if time.Now().After(info.expiresAt) {
			delete(s.sessions, keyStr)
			log.Printf("DTLS: Session expired for key: %s", keyStr)
		} else {
			log.Printf("DTLS: Found session for key: %s", keyStr)
			return dtls.Session{
				ID:     info.sessionID,
				Secret: info.masterSecret,
			}, nil
		}
	}

	// 如果 session store 中没有，返回错误以允许新的握手
	// OpenConnect 客户端通常会进行新的 DTLS 握手，而不是使用 session resumption
	log.Printf("DTLS: Session not found for key: %s, allowing new handshake", keyStr)
	return dtls.Session{}, errors.New("session not found")
}

// Del 删除 DTLS session
func (s *dtlsSessionStore) Del(key []byte) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	keyStr := hex.EncodeToString(key)
	delete(s.sessions, keyStr)
	return nil
}

// dtlsCipherSuites DTLS 加密套件映射（OpenConnect 兼容）
var dtlsCipherSuites = map[string]dtls.CipherSuiteID{
	"ECDHE-RSA-AES256-GCM-SHA384": dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-RSA-AES128-GCM-SHA256": dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// checkDtls12Ciphersuite 检查并返回支持的加密套件
func checkDtls12Ciphersuite(ciphersuite string) string {
	for k := range dtlsCipherSuites {
		if k == ciphersuite {
			return k
		}
	}
	// 返回默认值
	return "ECDHE-RSA-AES128-GCM-SHA256"
}

// startRealDTLSServer 启动真正的 DTLS 服务器（参考 anylink 实现）
func (h *Handler) startRealDTLSServer() error {
	log.Printf("StartDTLSServer called: EnableDTLS=%v", h.config.VPN.EnableDTLS)
	if !h.config.VPN.EnableDTLS {
		log.Printf("DTLS is disabled in config, skipping DTLS server startup")
		return nil
	}

	// 加载 TLS 证书（与 HTTPS 服务器使用相同的证书）
	log.Printf("DTLS: Loading certificate from %s and key from %s", h.config.VPN.CertFile, h.config.VPN.KeyFile)
	cert, err := tls.LoadX509KeyPair(h.config.VPN.CertFile, h.config.VPN.KeyFile)
	if err != nil {
		log.Printf("DTLS: Failed to load TLS certificate: %v", err)
		log.Printf("DTLS: Generating self-signed certificate for DTLS...")

		// 如果加载失败，生成自签名证书（兼容 OpenConnect）
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate RSA key: %w", err)
		}
		cert, err = selfsign.SelfSign(priv)
		if err != nil {
			return fmt.Errorf("failed to generate self-signed certificate: %w", err)
		}
		log.Printf("DTLS: WARNING - Using self-signed certificate (clients may reject this)")
		log.Printf("DTLS: Generated self-signed certificate")
	} else {
		// 解析证书以获取详细信息
		if cert.Leaf == nil {
			// 尝试解析证书
			if len(cert.Certificate) > 0 {
				// 这里可以解析证书，但为了简化，我们只记录成功加载
				log.Printf("DTLS: Certificate loaded successfully")
			}
		} else {
			log.Printf("DTLS: Certificate loaded successfully (CN: %s)", cert.Leaf.Subject.CommonName)
		}
	}

	// 创建日志工厂（启用详细日志以便调试）
	// 使用自定义 logger 确保日志被输出
	logf := &customLoggerFactory{}
	logf.DefaultLogLevel = logging.LogLevelDebug // 使用 Debug 级别以便看到更多信息

	// 创建 session store（传入 handler 以便访问客户端信息）
	sessStore := newDTLSSessionStore(h)

	// 配置 DTLS
	log.Printf("DTLS: Configuring DTLS with %d cipher suites", len(dtlsCipherSuites))
	dtlsConfig := &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		ExtendedMasterSecret: dtls.DisableExtendedMasterSecret, // OpenConnect 兼容（必须禁用）
		CipherSuites: func() []dtls.CipherSuiteID {
			var cs []dtls.CipherSuiteID
			for name, id := range dtlsCipherSuites {
				cs = append(cs, id)
				log.Printf("DTLS: Enabled cipher suite: %s (ID: %d, hex: 0x%04x)", name, id, id)
			}
			log.Printf("DTLS: Total %d cipher suites configured", len(cs))
			return cs
		}(),
		LoggerFactory: logf,
		MTU:           BufferSize,
		SessionStore:  sessStore,
		ConnectContextMaker: func() (context.Context, func()) {
			// 增加握手超时时间到 30 秒（OpenConnect 客户端可能需要更长时间）
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			return ctx, func() {
				log.Printf("DTLS: Handshake context cancelled or timed out")
				cancel()
			}
		},
		// 不要求客户端证书（OpenConnect 客户端通常不提供客户端证书）
		ClientAuth: dtls.NoClientCert,
	}

	// 解析地址
	// 注意：OpenConnect 客户端使用与 TCP 相同的端口进行 DTLS 连接（UDP）
	// 所以 DTLS 应该监听在 OpenConnectPort（TCP 443），而不是 DTLSPort
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

	// 注意：dtls.Listen 内部会创建一个 UDP 连接并处理 DTLS 握手
	// 如果客户端发送了 UDP 包，我们的自定义 logger 应该会记录日志
	// 如果没有看到任何日志，可能意味着：
	// 1. 客户端没有发送 UDP 包
	// 2. UDP 包被防火墙阻止
	// 3. 或者客户端配置有问题

	log.Printf("DTLS: Creating DTLS listener with custom logger...")
	log.Printf("DTLS: Custom logger will output all handshake logs with 'DTLS [scope]' prefix")

	// 关键：检查 DTLS 配置
	cipherSuites := dtlsConfig.CipherSuites
	log.Printf("DTLS: Config summary:")
	log.Printf("DTLS:   - Certificates: %d", len(dtlsConfig.Certificates))
	log.Printf("DTLS:   - CipherSuites: %d", len(cipherSuites))
	log.Printf("DTLS:   - ExtendedMasterSecret: Disabled (OpenConnect requirement)")
	log.Printf("DTLS:   - ClientAuth: NoClientCert")
	log.Printf("DTLS:   - MTU: %d", dtlsConfig.MTU)
	log.Printf("DTLS:   - LoggerFactory: %T", dtlsConfig.LoggerFactory)
	log.Printf("DTLS:   - SessionStore: %T", dtlsConfig.SessionStore)
	log.Printf("DTLS: Listening on UDP address: %s", udpAddr.String())

	// 使用 dtls.Listen 创建 DTLS 监听器
	// 这会处理 DTLS 握手和数据传输
	log.Printf("DTLS: Calling dtls.Listen()...")
	log.Printf("DTLS: All UDP packets will be handled by pion/dtls library")
	log.Printf("DTLS: DTLS handshake logs will appear with 'DTLS [scope]' prefix")
	log.Printf("DTLS: If you don't see 'DTLS: LoggerFactory.NewLogger called' logs, UDP packets may not be reaching the server")

	// 注意：dtls.Listen() 内部会创建一个 UDP 连接并开始监听
	// 如果 UDP 包到达，pion/dtls 会调用我们的 LoggerFactory.NewLogger
	ln, err := dtls.Listen("udp", udpAddr, dtlsConfig)
	if err != nil {
		log.Printf("DTLS: Failed to listen on UDP port %s: %v", dtlsPort, err)
		return fmt.Errorf("failed to listen on DTLS UDP port %s: %w", dtlsPort, err)
	}

	// 存储 listener
	h.dtlsListener = ln

	log.Printf("DTLS: dtls.Listen() succeeded, listener type: %T", ln)
	log.Printf("DTLS UDP server started successfully on %s (UDP port %s)", addr, dtlsPort)
	log.Printf("DTLS: Listener created successfully, ready to accept connections")
	log.Printf("DTLS: Server is ready to accept DTLS connections on UDP port %s", dtlsPort)
	log.Printf("DTLS: Note - Accept() will only return after successful handshake. Failed handshakes won't be logged here.")
	log.Printf("DTLS: IMPORTANT - If no 'DTLS [scope]' logs appear, it means:")
	log.Printf("DTLS:   1. UDP packets are not reaching the server (check firewall/network)")
	log.Printf("DTLS:   2. Client is not sending DTLS handshake packets")
	log.Printf("DTLS:   3. Use 'sudo tcpdump -i any -n udp port %s' to verify UDP packets", dtlsPort)

	// 启动接受连接的 goroutine
	go func() {
		log.Printf("DTLS: Accept loop started, waiting for DTLS connections...")
		log.Printf("DTLS: IMPORTANT - Accept() will block until handshake completes successfully")
		log.Printf("DTLS: If handshake fails, you should see 'DTLS [scope] ERROR' logs above")
		log.Printf("DTLS: If no logs appear, check:")
		log.Printf("DTLS:   1. Client is actually attempting DTLS connection")
		log.Printf("DTLS:   2. UDP port %s is accessible from client", dtlsPort)
		log.Printf("DTLS:   3. Firewall is not blocking UDP packets")
		log.Printf("DTLS:   4. Check if UDP packets are reaching the server (use: sudo tcpdump -i any -n udp port %s)", dtlsPort)
		log.Printf("DTLS:   5. Check client logs for DTLS connection errors")
		log.Printf("DTLS:   6. Verify network connectivity: ping server and check UDP port with: nc -u -v server_ip %s", dtlsPort)

		for {
			conn, err := ln.Accept()
			if err != nil {
				// 检查是否是关闭错误
				if strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("DTLS: Listener closed, exiting accept loop")
					return
				}
				log.Printf("DTLS: Accept error (handshake failed or connection closed): %v (type: %T)", err, err)
				log.Printf("DTLS: This error means Accept() returned, which usually indicates handshake failure")
				log.Printf("DTLS: Check 'DTLS [scope] ERROR' logs above for detailed error information")
				continue
			}

			log.Printf("DTLS: ✓ Handshake successful! New connection accepted from %s", conn.RemoteAddr())
			// 处理 DTLS 连接
			go h.handleDTLSConnection(conn)
		}
	}()

	return nil
}

// handleDTLSConnection 处理 DTLS 连接
func (h *Handler) handleDTLSConnection(conn net.Conn) {
	defer conn.Close()

	dtlsConn := conn.(*dtls.Conn)
	sessionID := hex.EncodeToString(dtlsConn.ConnectionState().SessionID)
	log.Printf("DTLS: New connection established, session ID: %s", sessionID)

	// 获取客户端地址
	remoteAddr := conn.RemoteAddr()
	udpAddr, ok := remoteAddr.(*net.UDPAddr)
	if !ok {
		log.Printf("DTLS: Invalid remote address type: %T", remoteAddr)
		return
	}

	// 查找匹配的客户端（通过 UDP 地址或未连接的客户端）
	h.dtlsLock.Lock()
	var matchedClient *TunnelClient
	var matchedVPNIP string

	log.Printf("DTLS: Attempting to match client for DTLS connection from %s (session ID: %s)", udpAddr, sessionID)
	log.Printf("DTLS: Total registered clients: %d", len(h.dtlsClients))

	// 首先尝试通过 UDP 地址匹配（最准确）
	// 注意：客户端在注册时 UDPAddr 可能是 nil，所以这个匹配可能不会成功
	for vpnIP, clientInfo := range h.dtlsClients {
		if clientInfo.UDPAddr != nil && clientInfo.UDPAddr.IP.Equal(udpAddr.IP) && clientInfo.UDPAddr.Port == udpAddr.Port {
			matchedClient = clientInfo.Client
			matchedVPNIP = vpnIP
			// 更新 DTLS 连接和地址信息
			clientInfo.DTLSConn = conn
			clientInfo.UDPAddr = udpAddr
			clientInfo.LastSeen = time.Now()
			log.Printf("DTLS: Matched client by UDP address (VPN IP: %s, UDP: %s)", vpnIP, udpAddr)
			break
		}
	}

	// 如果没有通过地址匹配，尝试通过第一个未连接的客户端匹配
	// 这是最常见的场景：客户端刚建立 TCP 连接，现在尝试建立 DTLS 连接
	if matchedClient == nil {
		log.Printf("DTLS: No client matched by UDP address, trying to match unconnected client...")
		for vpnIP, clientInfo := range h.dtlsClients {
			if clientInfo.Client != nil && clientInfo.DTLSConn == nil {
				matchedClient = clientInfo.Client
				matchedVPNIP = vpnIP
				// 设置 DTLS 连接和地址信息
				clientInfo.DTLSConn = conn
				clientInfo.UDPAddr = udpAddr
				clientInfo.LastSeen = time.Now()
				log.Printf("DTLS: Matched unconnected client for session ID %s (VPN IP: %s, User: %s)", sessionID, vpnIP, clientInfo.Client.User.Username)
				break
			}
		}
	}
	h.dtlsLock.Unlock()

	if matchedClient == nil {
		log.Printf("DTLS: ERROR - No matching client found for session ID: %s, remote: %s", sessionID, udpAddr)
		log.Printf("DTLS: This usually means:")
		log.Printf("DTLS:   1. Client TCP connection was not established before DTLS handshake")
		log.Printf("DTLS:   2. Client was not registered in dtlsClients map")
		log.Printf("DTLS:   3. All clients already have DTLS connections")
		log.Printf("DTLS: Available clients: %d", len(h.dtlsClients))
		for vpnIP, clientInfo := range h.dtlsClients {
			if clientInfo.Client != nil {
				log.Printf("DTLS:   - VPN IP: %s, User: %s, Has DTLS Conn: %v, UDP Addr: %v",
					vpnIP, clientInfo.Client.User.Username, clientInfo.DTLSConn != nil, clientInfo.UDPAddr)
			} else {
				log.Printf("DTLS:   - VPN IP: %s, Client: nil", vpnIP)
			}
		}
		log.Printf("DTLS: Closing DTLS connection due to no matching client")
		return
	}

	log.Printf("DTLS: Matched client for session ID %s (VPN IP: %s, remote: %s)", sessionID, matchedVPNIP, udpAddr)

	// 处理 DTLS 数据流
	buf := make([]byte, BufferSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("DTLS: Read error: %v", err)
			return
		}

		if n < 5 {
			log.Printf("DTLS: Packet too short: %d bytes", n)
			continue
		}

		// 解析 CSTP 数据包
		packetType := buf[3]
		length := binary.BigEndian.Uint16(buf[1:3])

		if int(length)+5 != n {
			log.Printf("DTLS: Invalid packet length: declared=%d, actual=%d", int(length)+5, n)
			if n >= 5 {
				payload := buf[5:n]
				go func() {
					if err := matchedClient.processPacket(packetType, payload); err != nil {
						log.Printf("DTLS: Error processing packet: %v", err)
					}
				}()
			}
			continue
		}

		payload := buf[5:n]
		log.Printf("DTLS: Received packet, type=0x%02x, length=%d", packetType, length)

		// 处理数据包
		go func() {
			if err := matchedClient.processPacket(packetType, payload); err != nil {
				log.Printf("DTLS: Error processing packet: %v", err)
			}
		}()
	}
}

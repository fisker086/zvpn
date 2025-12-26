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
	// BufferSize DTLS 缓冲区大小
	// 设置为1500字节以支持标准MTU（1460字节payload + 40字节头部开销）
	// 这样可以正确处理MTU检测时发送的大尺寸DPD包
	BufferSize = 1500
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
	// 如果包含关键信息，额外输出（特别是扩展相关的）
	msgLower := strings.ToLower(msg)
	if strings.Contains(msgLower, "handshake") ||
		strings.Contains(msgLower, "client") ||
		strings.Contains(msgLower, "error") ||
		strings.Contains(msgLower, "packet") ||
		strings.Contains(msgLower, "udp") ||
		strings.Contains(msgLower, "read") ||
		strings.Contains(msgLower, "write") ||
		strings.Contains(msgLower, "received") ||
		strings.Contains(msgLower, "sent") ||
		strings.Contains(msgLower, "extension") ||
		strings.Contains(msgLower, "hello") ||
		strings.Contains(msgLower, "flight") ||
		strings.Contains(msgLower, "serverhello") ||
		strings.Contains(msgLower, "supported") ||
		strings.Contains(msgLower, "curve") ||
		strings.Contains(msgLower, "point") ||
		strings.Contains(msgLower, "format") ||
		strings.Contains(msgLower, "group") ||
		strings.Contains(msgLower, "algorithm") ||
		strings.Contains(msgLower, "signature") {
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
		strings.Contains(msgLower, "connect") ||
		strings.Contains(msgLower, "extension") ||
		strings.Contains(msgLower, "hello") ||
		strings.Contains(msgLower, "flight") {
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
// 需要能够从 session ID 获取 master secret
// 使用 handler 来访问 dtlsClients，从中可以获取客户端信息
type dtlsSessionStore struct {
	sessions map[string]*dtlsSessionInfo
	lock     sync.RWMutex
	handler  *Handler // 用于访问客户端信息
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
// 注意：如果返回错误，DTLS 库会允许新的握手（不使用 session resumption）
func (s *dtlsSessionStore) Get(key []byte) (dtls.Session, error) {
	keyStr := hex.EncodeToString(key)

	s.lock.RLock()
	info, exists := s.sessions[keyStr]
	now := time.Now()
	s.lock.RUnlock()

	if !exists {
		return dtls.Session{}, errors.New("session not found")
	}

	// 检查是否过期（需要写锁来删除）
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

// StoreMasterSecret 存储 master secret（从客户端 CONNECT 请求中获取）
// 这个方法在 sendCSTPConfig 中调用，将 master secret 与 session ID 关联
func (s *dtlsSessionStore) StoreMasterSecret(sessionIDHex string, masterSecretHex string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if masterSecretHex == "" {
		return nil // 如果没有 master secret，不存储
	}

	// 解码 master secret（hex 字符串）
	masterSecret, err := hex.DecodeString(masterSecretHex)
	if err != nil {
		log.Printf("DTLS: Failed to decode master secret: %v", err)
		return err
	}

	// 解码 session ID（hex 字符串）
	sessionID, err := hex.DecodeString(sessionIDHex)
	if err != nil {
		log.Printf("DTLS: Failed to decode session ID: %v", err)
		return err
	}

	log.Printf("DTLS: Storing master secret for session ID: %s", sessionIDHex)
	s.sessions[sessionIDHex] = &dtlsSessionInfo{
		sessionID:    sessionID,
		masterSecret: masterSecret,
		expiresAt:    time.Now().Add(24 * time.Hour), // 24小时过期
	}
	return nil
}

// Del 删除 DTLS session
func (s *dtlsSessionStore) Del(key []byte) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	keyStr := hex.EncodeToString(key)
	delete(s.sessions, keyStr)
	return nil
}

// dtlsCipherSuites DTLS 加密套件映射（用于解析客户端请求）
// 只支持两个密码套件
var dtlsCipherSuites = map[string]dtls.CipherSuiteID{
	"ECDHE-RSA-AES256-GCM-SHA384": dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"ECDHE-RSA-AES128-GCM-SHA256": dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

// checkDtls12Ciphersuite 验证和选择客户端请求的 DTLS 1.2 密码套件
// 如果客户端请求的套件不在支持列表中，返回默认值
func checkDtls12Ciphersuite(ciphersuite string) string {
	if ciphersuite == "" {
		// 如果没有请求，返回默认值（优先级最高的）
		return "ECDHE-RSA-AES256-GCM-SHA384"
	}

	// 分割客户端请求的密码套件列表（冒号分隔）
	csArr := strings.Split(ciphersuite, ":")
	for _, v := range csArr {
		v = strings.TrimSpace(v)
		// 检查是否在支持的密码套件列表中
		if _, ok := dtlsCipherSuites[v]; ok {
			return v
		}
	}

	// 如果没有找到支持的密码套件，返回默认值（优先级最高的）
	return "ECDHE-RSA-AES256-GCM-SHA384"
}

// startRealDTLSServer 启动真正的 DTLS 服务器
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

	// 配置 DTLS：从 dtlsCipherSuites map 中获取密码套件列表
	// 只启用两个特定的密码套件，不使用 pion/dtls 的默认套件
	priorityCipherSuites := make([]dtls.CipherSuiteID, 0, len(dtlsCipherSuites))
	for _, vv := range dtlsCipherSuites {
		priorityCipherSuites = append(priorityCipherSuites, vv)
	}

	// 确保只包含两个密码套件
	if len(priorityCipherSuites) != 2 {
		log.Printf("DTLS: WARNING - Expected 2 cipher suites, got %d", len(priorityCipherSuites))
	}
	log.Printf("DTLS: Configuring DTLS with %d cipher suites", len(priorityCipherSuites))

	// 创建 session store（使用 sessionStore 而不是 nil）
	sessStore := newDTLSSessionStore(h)
	// 保存到 Handler 中，以便在 sendCSTPConfig 中使用
	h.dtlsSessionStore = sessStore

	// 使用配置文件中的 MTU（与发送给客户端的 X-DTLS-MTU 保持一致）
	// DTLS MTU 需要考虑 IP 头（20字节）+ UDP 头（8字节）+ DTLS 头（约13字节）的开销
	// 但为了与客户端配置一致，直接使用配置的 MTU 值
	dtlsMTU := h.config.VPN.MTU
	if dtlsMTU <= 0 {
		// 如果配置中没有设置或为0，使用默认值
		dtlsMTU = BufferSize
		log.Printf("DTLS: MTU not configured, using default: %d", dtlsMTU)
	} else {
		log.Printf("DTLS: Using MTU from config: %d", dtlsMTU)
	}

	// 确保密码套件配置正确 - 只使用与客户端兼容的密码套件
	supportedCipherSuites := []dtls.CipherSuiteID{
		dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, // 0xC030
		dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // 0xC02F
	}

	log.Printf("DTLS: Configuring with cipher suites:")
	for i, cs := range supportedCipherSuites {
		log.Printf("DTLS:   [%d] 0x%04X", i, cs)
	}

	// DTLS 配置
	dtlsConfig := &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		ExtendedMasterSecret: dtls.DisableExtendedMasterSecret, // OpenConnect 兼容（必须禁用）
		CipherSuites:         supportedCipherSuites,            // 使用明确的密码套件列表
		LoggerFactory:        logf,
		MTU:                  dtlsMTU,   // 使用配置文件中的 MTU
		SessionStore:         sessStore, // 使用 session store
		// 设置握手超时（使用 5 秒）
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(context.Background(), 5*time.Second)
		},
		// 注意：以下选项使用默认值，让 pion/dtls 使用默认配置
		// - SRTPProtectionProfiles
		// - EllipticCurves
		// - SupportedProtocols
		// - FlightInterval
		// - SignatureSchemes
		// - ClientAuth（使用默认值 NoClientCert）
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

	log.Printf("DTLS: Creating DTLS listener on %s", udpAddr.String())

	// 注意：不能同时创建两个 UDP 监听器监听同一个端口
	// dtls.Listen() 会创建自己的 UDP 连接，所以这里不需要额外的调试监听器
	// 如果需要调试，可以使用 tcpdump 或 wireshark 来捕获 UDP 包

	// 使用 dtls.Listen 创建 DTLS 监听器
	ln, err := dtls.Listen("udp", udpAddr, dtlsConfig)
	if err != nil {
		log.Printf("DTLS: Failed to listen on UDP port %s: %v", dtlsPort, err)
		return fmt.Errorf("failed to listen on DTLS UDP port %s: %w", dtlsPort, err)
	}

	// 存储 listener
	h.dtlsListener = ln

	log.Printf("DTLS: UDP server started on %s", addr)

	// 启动接受连接的 goroutine
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("DTLS: Listener closed, exiting accept loop")
					return
				}
				log.Printf("DTLS: Accept error: %v", err)
				continue
			}

			log.Printf("DTLS: Handshake successful, connection from %s", conn.RemoteAddr())
			go h.handleDTLSConnection(conn)
		}
	}()

	return nil
}

// handleDTLSConnection 处理 DTLS 连接（优化版本）
func (h *Handler) handleDTLSConnection(conn net.Conn) {
	defer conn.Close()

	dtlsConn := conn.(*dtls.Conn)
	sessionID := hex.EncodeToString(dtlsConn.ConnectionState().SessionID)

	// 获取客户端地址
	remoteAddr := conn.RemoteAddr()
	udpAddr, ok := remoteAddr.(*net.UDPAddr)
	if !ok {
		log.Printf("DTLS: Invalid remote address type: %T", remoteAddr)
		return
	}

	h.dtlsLock.Lock()
	var matchedClient *TunnelClient
	var matchedClientKey string

	// 步骤1：优先使用DTLSSessionID进行快速匹配（最精确、最快速）
	if sessionID != "" {
		for vpnIP, clientInfo := range h.dtlsClients {
			if clientInfo != nil && clientInfo.DTLSSessionID == sessionID {
				matchedClient = clientInfo.Client
				matchedClientKey = vpnIP
				// 更新连接信息
				clientInfo.DTLSConn = conn
				clientInfo.UDPAddr = udpAddr
				clientInfo.LastSeen = time.Now()
				log.Printf("DTLS: 快速会话ID匹配成功 - 用户: %s, VPN IP: %s, 会话ID: %s",
					clientInfo.Client.User.Username, vpnIP, sessionID[:16]+"...")
				break
			}
		}
	}

	// 步骤2：如果会话ID匹配失败，回退到UDP地址匹配
	if matchedClient == nil {
		for vpnIP, clientInfo := range h.dtlsClients {
			if clientInfo != nil && clientInfo.UDPAddr != nil &&
				clientInfo.UDPAddr.IP.Equal(udpAddr.IP) && clientInfo.UDPAddr.Port == udpAddr.Port {
				matchedClient = clientInfo.Client
				matchedClientKey = vpnIP
				// 更新会话ID映射（如果还没有的话）
				if clientInfo.DTLSSessionID == "" && sessionID != "" {
					clientInfo.DTLSSessionID = sessionID
				}
				// 更新连接信息
				clientInfo.DTLSConn = conn
				clientInfo.UDPAddr = udpAddr
				clientInfo.LastSeen = time.Now()
				log.Printf("DTLS: UDP地址匹配成功 - 用户: %s, VPN IP: %s, 会话ID: %s",
					clientInfo.Client.User.Username, vpnIP, sessionID[:16]+"...")
				break
			}
		}
	}

	// 步骤3：如果地址匹配也失败，回退到第一个未连接客户端匹配
	if matchedClient == nil {
		for vpnIP, clientInfo := range h.dtlsClients {
			if clientInfo != nil && clientInfo.Client != nil && clientInfo.DTLSConn == nil {
				matchedClient = clientInfo.Client
				matchedClientKey = vpnIP
				// 建立会话ID映射（用于后续快速匹配）
				if sessionID != "" {
					clientInfo.DTLSSessionID = sessionID
				}
				// 更新连接信息
				clientInfo.DTLSConn = conn
				clientInfo.UDPAddr = udpAddr
				clientInfo.LastSeen = time.Now()
				log.Printf("DTLS: 回退匹配成功 - 用户: %s, VPN IP: %s, 会话ID: %s",
					clientInfo.Client.User.Username, vpnIP, sessionID[:16]+"...")
				break
			}
		}
	}

	// 步骤4：关键更新 - 更新VPNServer中的DTLSConn引用
	if matchedClient != nil && matchedClientKey != "" {
		if matchedClient.VPNServer != nil {
			if vpnClient, exists := matchedClient.VPNServer.GetClient(matchedClient.User.ID); exists && vpnClient != nil {
				vpnClient.DTLSConn = conn
				log.Printf("DTLS: 更新VPNClient DTLS连接 - 用户: %s (VPN IP: %s)",
					matchedClient.User.Username, matchedClient.IP.String())

				// 优化：DTLS 连接建立后，立即通过 DTLS 通道发送 DPD 响应
				// 这可以触发客户端路由生效，而不需要等待客户端发送 DPD 请求
				// 使用 goroutine 异步发送，避免阻塞 DTLS 连接处理
				go func() {
					// 等待一小段时间，确保 DTLS 连接已经完全建立
					time.Sleep(100 * time.Millisecond)
					// 通过 DTLS 通道发送 DPD 响应，触发客户端路由生效
					// 注意：DPD 响应通过 DTLS 通道发送，而不是 TCP 通道
					// 这样可以更快地触发客户端的路由生效
					if conn != nil {
						// 构建 DPD-RESP 包：第一个字节是包类型 (0x04)，后面是空的 payload
						dpdResp := []byte{PacketTypeDPDResp}
						if _, err := conn.Write(dpdResp); err != nil {
							log.Printf("DTLS: 通过 DTLS 通道发送 DPD 响应以触发路由生效失败: %v", err)
						} else {
							log.Printf("DTLS: 已通过 DTLS 通道发送 DPD 响应以触发客户端路由生效 - 用户: %s", matchedClient.User.Username)
						}
					}
				}()
			}
		}
	}
	h.dtlsLock.Unlock()

	// 步骤5：如果所有匹配都失败，记录错误并关闭连接
	if matchedClient == nil {
		log.Printf("DTLS: 所有匹配方法都失败 - 会话ID: %s, 远程地址: %s, 当前客户端数量: %d",
			sessionID[:16]+"...", udpAddr, len(h.dtlsClients))
		return
	}

	// 处理 DTLS 数据流
	// DTLS 数据包格式：第一个字节是包类型，后面是数据
	// 0x00 = DATA (IP包), 0x03 = DPD-REQ, 0x04 = DPD-RESP, 0x05 = DISCONNECT, 0x07 = KEEPALIVE, 0x08 = COMPRESSED
	readBufSize := 4096 // 单次读取缓冲区
	readBuf := make([]byte, readBufSize)

	// 获取 keepalive 配置，read timeout 应该略大于 keepalive 值（keepalive * 1.5）
	// 这样可以在客户端发送 keepalive 之前，服务端先检测到超时
	readTimeout := 30 * time.Second // 默认值
	if matchedClient != nil && matchedClient.VPNServer != nil {
		if cfg := matchedClient.VPNServer.GetConfig(); cfg != nil {
			cstpKeepalive := cfg.VPN.CSTPKeepalive
			if cstpKeepalive == 0 {
				cstpKeepalive = 20 // 默认值：20秒（AnyConnect 标准）
			}
			// read timeout = keepalive * 1.5，确保在客户端发送 keepalive 之前检测到超时
			readTimeout = time.Duration(cstpKeepalive) * time.Second * 3 / 2
		}
	}

	for {
		// 设置读取超时（基于 keepalive 配置）
		if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			log.Printf("DTLS: 设置读取超时失败: %v", err)
			return
		}

		// 从 DTLS 连接读取数据（已经解密）
		n, err := conn.Read(readBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 超时 - DTLS keepalive 由客户端处理，我们只需要继续
				continue
			}

			if err == io.EOF {
				log.Printf("DTLS: 客户端关闭DTLS连接 - 会话 %s", sessionID[:16]+"...")
				return
			}

			log.Printf("DTLS: 读取错误: %v", err)
			return
		}

		// 调试：记录读取到的原始数据（仅在必要时记录，减少日志开销）
		// 注释掉以减少延迟，需要调试时可以取消注释
		// if n > 0 {
		// 	previewLen := n
		// 	if previewLen > 32 {
		// 		previewLen = 32
		// 	}
		// 	log.Printf("DTLS: 从连接读取 %d 字节，前 %d 字节: %x", n, previewLen, readBuf[:previewLen])
		// }

		// DTLS 数据包格式
		// 第一个字节是包类型：
		// 0x00 = DATA (IP包)
		// 0x03 = DPD-REQ
		// 0x04 = DPD-RESP
		// 0x05 = DISCONNECT
		// 0x07 = KEEPALIVE
		// 0x08 = COMPRESSED DATA

		if n < 1 {
			continue
		}

		packetType := readBuf[0]

		switch packetType {
		case PacketTypeKeepalive: // 0x07
			// KEEPALIVE - do nothing
			// 减少日志以减少延迟
			continue

		case PacketTypeDisconnect: // 0x05
			// DISCONNECT - 客户端请求断开连接
			log.Printf("DTLS: 收到 DISCONNECT 包，客户端 %s 请求断开 DTLS 连接", matchedClient.User.Username)
			return

		case PacketTypeDPDReq: // 0x03
			// DPD-REQ - 死连接检测请求
			// 发送 DPD-RESP 响应（优化：直接修改第一个字节，避免复制）
			readBuf[0] = PacketTypeDPDResp
			if _, err := conn.Write(readBuf[:n]); err != nil {
				log.Printf("DTLS: 发送 DPD-RESP 失败: %v", err)
			}
			continue

		case PacketTypeDPDResp: // 0x04
			// DPD-RESP - 死连接检测响应
			// 减少日志以减少延迟
			continue

		case PacketTypeCompressed: // 0x08
			// COMPRESSED DATA - 压缩的数据包
			if n < 2 {
				continue
			}
			// TODO: 实现解压逻辑（如果启用了压缩）
			// 目前先尝试直接处理（可能客户端发送的是未压缩的数据）
			// 减少日志以减少延迟
			// 暂时当作 DATA 包处理（跳过第一个字节，直接使用剩余数据）
			// compressedData := readBuf[1:n] // 未使用，直接 fallthrough 到 DATA 处理
			fallthrough

		case PacketTypeData: // 0x00
			// DATA - IP 包（去掉第一个字节）
			if n < 2 {
				continue
			}
			// 优化：直接使用 readBuf[1:n] 作为 payload，避免内存分配和复制
			// 注意：processPacket 会复制数据，所以这里可以安全地传递切片
			payload := readBuf[1:n]

			// 处理 IP 包
			if err := matchedClient.processPacket(PacketTypeData, payload); err != nil {
				log.Printf("DTLS: 处理 DATA 包时出错: %v", err)
			}
			continue

		default:
			// 未知的包类型
			log.Printf("DTLS: 收到未知包类型: 0x%02x，长度: %d", packetType, n)
			continue
		}
	}
}

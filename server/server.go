package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/middleware"
	"github.com/fisker/zvpn/routes"
	"github.com/fisker/zvpn/vpn"
	"github.com/fisker/zvpn/vpn/openconnect"
	"github.com/fisker/zvpn/vpn/policy"
	"github.com/gin-gonic/gin"
)

// certManager 证书管理器，支持 SNI (Server Name Indication)
// 参考 anylink 的实现，支持为不同域名提供不同证书
type certManager struct {
	certs        map[string]*tls.Certificate // SNI 域名 -> 证书
	defaultCert  *tls.Certificate            // 默认证书（当 SNI 不匹配时使用）
	mu           sync.RWMutex                // 保护并发访问
	loggedSNIs   map[string]bool             // 已记录日志的SNI（避免重复日志）
	loggedSNIsMu sync.RWMutex                // 保护loggedSNIs的并发访问
}

// newCertManager 创建新的证书管理器
func newCertManager() *certManager {
	return &certManager{
		certs:      make(map[string]*tls.Certificate),
		loggedSNIs: make(map[string]bool),
	}
}

// LoadDefaultCert 加载默认证书
func (cm *certManager) LoadDefaultCert(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load default certificate: %w", err)
	}

	// 解析证书以获取域名信息
	if cert.Leaf == nil {
		if len(cert.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err == nil {
				cert.Leaf = leaf
			}
		}
	}

	cm.mu.Lock()
	cm.defaultCert = &cert
	cm.mu.Unlock()

	// 验证证书链是否正确加载
	if len(cert.Certificate) < 1 {
		return fmt.Errorf("certificate chain is empty")
	}

	// 记录证书链信息（用于调试）
	log.Printf("Certificate Manager: Certificate chain loaded - Server cert: %d bytes, Chain length: %d",
		len(cert.Certificate[0]), len(cert.Certificate))
	if len(cert.Certificate) > 1 {
		log.Printf("Certificate Manager: Intermediate cert: %d bytes", len(cert.Certificate[1]))
	}

	// 参考 anylink：简单记录，不做严格检查
	log.Printf("Certificate Manager: Loaded default certificate from %s, %s", certFile, keyFile)
	log.Printf("Certificate Manager: Certificate chain contains %d certificate(s)", len(cert.Certificate))
	if cert.Leaf != nil {
		log.Printf("Certificate Manager: Server cert CN: %s", cert.Leaf.Subject.CommonName)
		log.Printf("Certificate Manager: Certificate DNS Names: %v", cert.Leaf.DNSNames)

		// 检查证书有效期
		now := time.Now()
		daysUntilExpiry := int(cert.Leaf.NotAfter.Sub(now).Hours() / 24)
		log.Printf("Certificate Manager: Certificate valid until: %s (%d days remaining)",
			cert.Leaf.NotAfter.Format("2006-01-02 15:04:05"), daysUntilExpiry)

		if daysUntilExpiry < 0 {
			log.Printf("Certificate Manager: ⚠️  FATAL - Certificate has EXPIRED! TLS connections will fail.")
		} else if daysUntilExpiry <= 7 {
			log.Printf("Certificate Manager: ⚠️  WARNING - Certificate expires in %d days - renew immediately!", daysUntilExpiry)
		} else if daysUntilExpiry <= 30 {
			log.Printf("Certificate Manager: ⚠️  WARNING - Certificate expires in %d days - plan renewal soon", daysUntilExpiry)
		}
	}

	return nil
}

// AddCert 为指定 SNI 域名添加证书
func (cm *certManager) AddCert(sni string, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate for SNI %s: %w", sni, err)
	}

	// 解析证书以获取域名信息
	if cert.Leaf == nil {
		if len(cert.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err == nil {
				cert.Leaf = leaf
			}
		}
	}

	cm.mu.Lock()
	cm.certs[strings.ToLower(sni)] = &cert
	cm.mu.Unlock()

	log.Printf("Certificate Manager: Added certificate for SNI '%s' from %s, %s", sni, certFile, keyFile)
	if cert.Leaf != nil {
		log.Printf("Certificate Manager: SNI '%s' cert CN: %s, DNS Names: %v", sni, cert.Leaf.Subject.CommonName, cert.Leaf.DNSNames)
	}

	return nil
}

// matchDomain 检查域名是否匹配证书的 DNS Names（支持通配符和多域名）
func matchDomain(domain string, cert *tls.Certificate) bool {
	if cert == nil || cert.Leaf == nil {
		return false
	}

	domain = strings.ToLower(domain)

	// 检查 CN（Common Name）
	if cert.Leaf.Subject.CommonName != "" {
		cn := strings.ToLower(cert.Leaf.Subject.CommonName)
		if cn == domain {
			return true
		}
		// 支持通配符 CN（如 *.example.com）
		if strings.HasPrefix(cn, "*.") {
			wildcardDomain := cn[2:]
			if strings.HasSuffix(domain, "."+wildcardDomain) || domain == wildcardDomain {
				return true
			}
		}
	}

	// 检查 DNS Names（Subject Alternative Name）
	for _, dnsName := range cert.Leaf.DNSNames {
		dnsNameLower := strings.ToLower(dnsName)
		if dnsNameLower == domain {
			return true
		}
		// 支持通配符 DNS Name（如 *.example.com）
		if strings.HasPrefix(dnsNameLower, "*.") {
			wildcardDomain := dnsNameLower[2:]
			if strings.HasSuffix(domain, "."+wildcardDomain) || domain == wildcardDomain {
				return true
			}
		}
	}

	return false
}

// GetCertificateBySNI 根据 SNI 获取证书（用于 TLS GetCertificate 回调）
// 支持通配符和多域名证书匹配
func (cm *certManager) GetCertificateBySNI(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var cert *tls.Certificate

	// 如果提供了 SNI，尝试匹配
	if chi.ServerName != "" {
		sni := strings.ToLower(chi.ServerName)

		// 1. 精确匹配 SNI 配置的证书
		if c, ok := cm.certs[sni]; ok && c != nil {
			cert = c
		} else {
			// 2. 尝试匹配通配符配置的证书（如 *.example.com）
			for sniKey, c := range cm.certs {
				if strings.HasPrefix(sniKey, "*.") {
					domain := sniKey[2:]
					if strings.HasSuffix(sni, "."+domain) || sni == domain {
						if c != nil {
							cert = c
							break
						}
					}
				}
			}
		}

		// 3. 如果还没有找到，检查默认证书是否匹配域名
		if cert == nil && cm.defaultCert != nil {
			if matchDomain(sni, cm.defaultCert) {
				cert = cm.defaultCert
			}
		}

		// 4. 检查所有已配置的证书，看是否有匹配的（支持通配符和多域名）
		if cert == nil {
			for _, c := range cm.certs {
				if matchDomain(sni, c) {
					cert = c
					break
				}
			}
		}
	}

	// 如果没有找到匹配的证书，使用默认证书
	if cert == nil {
		cert = cm.defaultCert
	}

	// 如果证书为 nil，返回错误（这不应该发生，因为启动时已经验证过）
	if cert == nil {
		return nil, fmt.Errorf("no certificate available")
	}

	// 深拷贝证书以避免并发问题
	// Go 的 TLS 库要求 GetCertificate 返回的证书是只读的
	certCopy := &tls.Certificate{
		Certificate: make([][]byte, len(cert.Certificate)),
		PrivateKey:  cert.PrivateKey,
		Leaf:        cert.Leaf,
	}
	for i, certBytes := range cert.Certificate {
		certCopy.Certificate[i] = make([]byte, len(certBytes))
		copy(certCopy.Certificate[i], certBytes)
	}

	return certCopy, nil
}

// keepAliveResponseWriter 包装 http.ResponseWriter，强制设置 Connection: keep-alive
type keepAliveResponseWriter struct {
	http.ResponseWriter
	written bool
}

func (w *keepAliveResponseWriter) WriteHeader(code int) {
	if !w.written {
		// 强制设置 Connection: keep-alive
		w.Header().Set("Connection", "keep-alive")
		w.written = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *keepAliveResponseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Flush 实现 http.Flusher 接口
func (w *keepAliveResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack 实现 http.Hijacker 接口（用于 CONNECT 请求）
func (w *keepAliveResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("ResponseWriter does not implement http.Hijacker")
}

// connectHandler 自定义 HTTP Handler，用于拦截 CONNECT 请求
type connectHandler struct {
	ginHandler http.Handler
	ocHandler  *openconnect.Handler
}

// ServeHTTP 实现 http.Handler 接口
func (h *connectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 重要：对于 OpenConnect/AnyConnect 客户端，强制使用 keep-alive
	// 即使客户端没有明确发送 Connection: keep-alive，我们也应该保持连接打开
	// 这是 OpenConnect/AnyConnect 协议的要求：使用长连接进行多个请求

	// 参考 anylink 的实现，改进 VPN 客户端检测逻辑
	// 检测 VPN 客户端的方法：
	// 1. 通过 X-Aggregate-Auth 和 X-Transcend-Version 头部（AnyConnect 标准方法，最可靠）
	// 2. 通过 User-Agent（用于初始请求，此时可能还没有发送上述头部）
	xAggregateAuth := r.Header.Get("X-Aggregate-Auth")
	xTranscendVersion := r.Header.Get("X-Transcend-Version")
	userAgent := strings.ToLower(r.UserAgent())

	// 检测是否为 VPN 客户端（参考 anylink 的检测逻辑）
	// AnyConnect 客户端会发送 X-Aggregate-Auth: 1 和 X-Transcend-Version: 1
	isVPNClient := (xAggregateAuth == "1" && xTranscendVersion == "1") ||
		strings.Contains(userAgent, "anyconnect") ||
		strings.Contains(userAgent, "openconnect") ||
		strings.Contains(userAgent, "cisco secure client") ||
		strings.Contains(userAgent, "cisco anyconnect") ||
		(xAggregateAuth != "" && xTranscendVersion != "") // 即使不是 "1"，只要有这些头部就可能是 VPN 客户端

	if isVPNClient {
		// 参考 anylink 的实现，对于 VPN 客户端，强制使用 keep-alive
		// 注意：AnyConnect 客户端在初始请求时可能会发送 Connection: close
		// 这是正常行为，我们应该接受并强制设置为 keep-alive，而不是拒绝
		clientConnection := strings.ToLower(r.Header.Get("Connection"))
		if clientConnection == "close" {
			// 记录日志，但不拒绝请求
			// 对于初始请求（Path: /），AnyConnect 客户端可能会发送 Connection: close
			// 参考 anylink：我们应该接受并强制设置为 keep-alive
			log.Printf("OpenConnect: VPN client sent Connection: close, forcing keep-alive (Path: %s, User-Agent: %s)",
				r.URL.Path, r.UserAgent())
		}

		// 强制设置请求的 Connection header 为 keep-alive
		// 参考 anylink：这样即使客户端发送了 Connection: close，我们也会使用 keep-alive
		// 这对于 AnyConnect 协议的长连接至关重要
		r.Header.Set("Connection", "keep-alive")

		// 使用自定义的 ResponseWriter 包装，确保响应中也设置 Connection: keep-alive
		// 参考 anylink：确保响应头正确设置，客户端才能正确维持长连接
		w = &keepAliveResponseWriter{ResponseWriter: w}
	}

	// 所有请求都交给 Gin 处理
	h.ginHandler.ServeHTTP(w, r)
}

// Server 服务器管理器
type Server struct {
	cfg              *config.Config
	vpnServer        *vpn.VPNServer
	httpServer       *http.Server
	httpsServer      *http.Server
	ocHandler        *openconnect.Handler
	certManager      *certManager // SNI 证书管理器
	shutdownComplete chan struct{}
	ctx              context.Context
	cancel           context.CancelFunc
}

// New 创建新的服务器实例
func New(cfg *config.Config, vpnServer *vpn.VPNServer) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{
		cfg:              cfg,
		vpnServer:        vpnServer,
		certManager:      newCertManager(),
		shutdownComplete: make(chan struct{}),
		ctx:              ctx,
		cancel:           cancel,
	}

	// 加载默认证书
	if err := server.certManager.LoadDefaultCert(cfg.VPN.CertFile, cfg.VPN.KeyFile); err != nil {
		log.Printf("ERROR: Failed to load default certificate: %v", err)
		log.Printf("ERROR: Certificate file: %s, Key file: %s", cfg.VPN.CertFile, cfg.VPN.KeyFile)
		log.Printf("ERROR: Server will start but TLS connections will fail")
	} else {
		log.Printf("Certificate Manager: Successfully loaded default certificate")
	}

	return server
}

// Start 启动所有服务器
func (s *Server) Start() error {
	// 初始化 OpenConnect 处理器（默认启用）
	s.ocHandler = openconnect.NewHandler(s.cfg, s.vpnServer)

	// 启动定期刷新审计日志缓冲区的goroutine
	go s.startAuditLogFlusher()

	// 不再启动自定义VPN协议服务器

	// 启动 HTTP 管理 API 服务器
	s.startHTTPServer()

	// 启动 HTTPS OpenConnect 服务器（默认启用）
	s.startHTTPSServer()

	// 启动 DTLS UDP 服务器（如果启用）
	if s.cfg.VPN.EnableDTLS {
		if err := s.ocHandler.StartDTLSServer(); err != nil {
			log.Printf("Failed to start DTLS server: %v (clients will use SSL/TLS only)", err)
		} else {
			log.Printf("DTLS server started on UDP port %s", s.cfg.VPN.OpenConnectPort)
		}
	}

	// 等待中断信号
	s.waitForShutdown()

	return nil
}

// startAuditLogFlusher 启动定期刷新审计日志缓冲区的goroutine
func (s *Server) startAuditLogFlusher() {
	ticker := time.NewTicker(30 * time.Second) // 每30秒刷新一次
	defer ticker.Stop()

	// 刷新审计日志的辅助函数
	flushAuditLogs := func() {
		auditLogger := policy.GetAuditLogger()
		if auditLogger != nil {
			if err := auditLogger.Flush(); err != nil {
				log.Printf("Failed to flush audit logs: %v", err)
			}
		}
	}

	// 使用 for range 简化循环，同时监听关闭信号
	for {
		select {
		case <-ticker.C:
			flushAuditLogs()
		case <-s.ctx.Done():
			// 服务器关闭时，执行最后一次刷新确保数据不丢失
			flushAuditLogs()
			return
		}
	}
}

// startHTTPServer 启动 HTTP 管理 API 服务器
func (s *Server) startHTTPServer() {
	router := routes.SetupRouter(s.cfg, s.vpnServer)

	s.httpServer = &http.Server{
		Addr:    s.cfg.Server.Host + ":" + s.cfg.Server.Port,
		Handler: router,
	}

	go func() {
		log.Printf("HTTP server (Management API) starting on %s:%s", s.cfg.Server.Host, s.cfg.Server.Port)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()
}

// startHTTPSServer 启动 HTTPS OpenConnect 服务器
func (s *Server) startHTTPSServer() {
	router := gin.Default()
	// CORS 中间件
	router.Use(middleware.CorsMiddleware())

	// 注册 OpenConnect 路由
	s.ocHandler.SetupRoutes(router)

	router.NoRoute(func(c *gin.Context) {
		c.String(http.StatusNotFound, "Not Found")
	})

	// 创建自定义 HTTP Handler 来拦截 CONNECT 请求
	// 因为 Gin 可能不支持 CONNECT 方法，我们需要在 HTTP 层面处理
	customHandler := &connectHandler{
		ginHandler: router,
		ocHandler:  s.ocHandler,
	}

	// 配置 TLS - 参考 anylink 的简单配置方式
	// 修复 CVE-2016-2183: 使用所有可用的密码套件
	// https://segmentfault.com/a/1190000038486901
	cipherSuites := tls.CipherSuites()
	selectedCipherSuites := make([]uint16, 0, len(cipherSuites))
	for _, s := range cipherSuites {
		selectedCipherSuites = append(selectedCipherSuites, s.ID)
	}

	// 设置 TLS 配置 - 参考 anylink 的简单方式
	// 重要：不设置 CipherSuites，允许 TLS 1.3
	// TLS 1.3 使用固定的密码套件，不需要在 CipherSuites 中配置
	// 设置 CipherSuites 会禁用 TLS 1.3，只支持 TLS 1.2
	tlsConfig := &tls.Config{
		NextProtos: []string{"http/1.1"}, // OpenConnect VPN 只使用 HTTP/1.1，不需要 HTTP/2
		MinVersion: tls.VersionTLS12,
		// 不设置 MaxVersion，允许 TLS 1.3
		// 不设置 CipherSuites，允许 TLS 1.3 和 TLS 1.2
		// 如果只想支持 TLS 1.2，可以设置 MaxVersion: tls.VersionTLS12 和 CipherSuites: selectedCipherSuites
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// 详细记录客户端信息
			remoteAddr := chi.Conn.RemoteAddr().String()
			log.Printf("TLS: ClientHello from %s", remoteAddr)
			os.Stderr.Sync() // 强制刷新日志
			log.Printf("TLS:   - SNI: '%s'", chi.ServerName)
			log.Printf("TLS:   - Supported TLS versions: %v", chi.SupportedVersions)
			log.Printf("TLS:   - Cipher suites count: %d", len(chi.CipherSuites))
			if len(chi.CipherSuites) > 0 {
				log.Printf("TLS:   - First cipher suite: 0x%04x", chi.CipherSuites[0])
			}
			log.Printf("TLS:   - Supported curves: %v", chi.SupportedCurves)
			log.Printf("TLS:   - Supported points: %v", chi.SupportedPoints)

			cert, err := s.certManager.GetCertificateBySNI(chi)
			if err != nil {
				log.Printf("TLS: ERROR - GetCertificate failed for SNI '%s' from %s: %v", chi.ServerName, remoteAddr, err)
				return nil, err
			}
			if cert == nil {
				log.Printf("TLS: ERROR - No certificate available for SNI '%s' from %s", chi.ServerName, remoteAddr)
				return nil, fmt.Errorf("no certificate available for SNI '%s'", chi.ServerName)
			}

			// 记录证书信息
			log.Printf("TLS: Certificate selected for SNI '%s' from %s", chi.ServerName, remoteAddr)
			log.Printf("TLS:   - Certificate chain length: %d", len(cert.Certificate))
			if cert.Leaf != nil {
				log.Printf("TLS:   - Certificate CN: %s", cert.Leaf.Subject.CommonName)
				log.Printf("TLS:   - Certificate DNS Names: %v", cert.Leaf.DNSNames)
				log.Printf("TLS:   - Certificate Issuer: %s", cert.Leaf.Issuer.String())

				// 检查证书有效期
				now := time.Now()
				daysUntilExpiry := int(cert.Leaf.NotAfter.Sub(now).Hours() / 24)
				log.Printf("TLS:   - Certificate valid until: %s (%d days remaining)",
					cert.Leaf.NotAfter.Format("2006-01-02 15:04:05"), daysUntilExpiry)

				if daysUntilExpiry < 0 {
					log.Printf("TLS:   - ⚠️  WARNING: Certificate has EXPIRED!")
				} else if daysUntilExpiry <= 7 {
					log.Printf("TLS:   - ⚠️  WARNING: Certificate expires in %d days - renew soon!", daysUntilExpiry)
				} else if daysUntilExpiry <= 30 {
					log.Printf("TLS:   - ⚠️  WARNING: Certificate expires in %d days - plan renewal", daysUntilExpiry)
				}
			}

			return cert, nil
		},
		// 添加 VerifyConnection 回调以记录握手成功信息
		VerifyConnection: func(cs tls.ConnectionState) error {
			log.Printf("TLS: ✅ Handshake completed successfully")
			if len(cs.PeerCertificates) > 0 {
				log.Printf("TLS:   - Remote address: %s", cs.PeerCertificates[0].Subject.String())
			}
			log.Printf("TLS:   - TLS version: 0x%04x (%s)", cs.Version, tlsVersionString(cs.Version))
			log.Printf("TLS:   - Cipher suite: 0x%04x (%s)", cs.CipherSuite, tls.CipherSuiteName(cs.CipherSuite))
			log.Printf("TLS:   - SNI: '%s'", cs.ServerName)
			log.Printf("TLS:   - Negotiated protocol: %s", cs.NegotiatedProtocol)
			return nil
		},
		// 添加 GetConfigForClient 回调以记录服务器选择的配置
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			log.Printf("TLS: GetConfigForClient called for SNI '%s'", chi.ServerName)
			log.Printf("TLS:   - Will negotiate TLS version from: %v", chi.SupportedVersions)
			log.Printf("TLS:   - Server will use: MinVersion=%d (TLS 1.2), MaxVersion=0 (allow TLS 1.3)", tls.VersionTLS12)
			os.Stderr.Sync() // 强制刷新日志
			// 返回 nil 使用默认配置
			return nil, nil
		},
	}

	// 创建详细的错误日志记录器
	detailedLogger := &detailedTLSLogger{
		logger:   log.New(os.Stderr, "HTTPS Server: ", log.LstdFlags),
		certFile: s.cfg.VPN.CertFile,
	}
	errorLogger := log.New(detailedLogger, "HTTPS Server: ", log.LstdFlags)

	// 参考 anylink 的服务器配置
	s.httpsServer = &http.Server{
		Addr:         s.cfg.Server.Host + ":" + s.cfg.VPN.OpenConnectPort,
		Handler:      customHandler,
		TLSConfig:    tlsConfig,
		ErrorLog:     errorLogger,
		ReadTimeout:  100 * time.Second,
		WriteTimeout: 100 * time.Second,
	}

	go func() {
		log.Printf("HTTPS server (OpenConnect) starting on %s:%s", s.cfg.Server.Host, s.cfg.VPN.OpenConnectPort)
		log.Printf("Using default certificates: %s, %s", s.cfg.VPN.CertFile, s.cfg.VPN.KeyFile)
		log.Printf("SNI (Server Name Indication) support enabled - certificates can be configured per domain")

		// 验证默认证书是否加载成功
		s.certManager.mu.RLock()
		defaultCert := s.certManager.defaultCert
		s.certManager.mu.RUnlock()

		// 严格检查证书是否加载成功
		if defaultCert == nil {
			log.Fatalf("HTTPS: FATAL - Default certificate is nil! TLS connections will fail. Please check certificate files: %s, %s",
				s.cfg.VPN.CertFile, s.cfg.VPN.KeyFile)
		}

		// 验证证书链是否有效
		if len(defaultCert.Certificate) == 0 {
			log.Fatalf("HTTPS: FATAL - Default certificate chain is empty! Please check certificate file: %s",
				s.cfg.VPN.CertFile)
		}

		// 验证私钥是否有效
		if defaultCert.PrivateKey == nil {
			log.Fatalf("HTTPS: FATAL - Default certificate private key is nil! Please check key file: %s",
				s.cfg.VPN.KeyFile)
		}

		log.Printf("HTTPS: Default certificate verified - Chain length: %d, Has private key: %v",
			len(defaultCert.Certificate), defaultCert.PrivateKey != nil)

		// 参考 anylink：使用 ServeTLS 启动 HTTPS 服务器
		// 注意：certFile 和 keyFile 传入空字符串，因为证书通过 GetCertificate 回调提供
		addr := s.cfg.Server.Host + ":" + s.cfg.VPN.OpenConnectPort
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("HTTPS: Failed to listen on %s: %v", addr, err)
		}

		log.Printf("HTTPS: Listening on %s", addr)

		// 包装 listener 以记录所有连接
		wrappedListener := &connectionLoggingListener{
			Listener: listener,
		}

		// 使用 ServeTLS，传入空字符串因为证书通过 GetCertificate 回调提供
		// 这是 anylink 的做法，更简单且可靠
		if err := s.httpsServer.ServeTLS(wrappedListener, "", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS server error: %v", err)
		}
	}()
}

// startCustomVPNServer 已移除，不再使用自定义协议

// waitForShutdown 等待关闭信号
func (s *Server) waitForShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// 通知所有后台 goroutine 停止（包括审计日志刷新器）
	s.cancel()

	// 优雅关闭
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 关闭 HTTP 服务器
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Printf("HTTP server forced to shutdown: %v", err)
		}
	}

	// 关闭 HTTPS 服务器
	if s.httpsServer != nil {
		if err := s.httpsServer.Shutdown(ctx); err != nil {
			log.Printf("HTTPS server forced to shutdown: %v", err)
		}
	}

	// 关闭 VPN 服务器
	if err := s.vpnServer.Stop(); err != nil {
		log.Printf("VPN server shutdown error: %v", err)
	}

	log.Println("Server exited")
	close(s.shutdownComplete)
}

// AddSNICert 为指定 SNI 域名添加证书（公开方法，可用于动态添加证书）
// 示例用法：
//
//	server.AddSNICert("vpn1.example.com", "/path/to/cert1.pem", "/path/to/key1.pem")
//	server.AddSNICert("*.example.com", "/path/to/wildcard.pem", "/path/to/wildcard.key")
func (s *Server) AddSNICert(sni string, certFile, keyFile string) error {
	return s.certManager.AddCert(sni, certFile, keyFile)
}

// connectionLoggingListener 包装 net.Listener，记录所有连接
type connectionLoggingListener struct {
	net.Listener
}

func (l *connectionLoggingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	remoteAddr := conn.RemoteAddr().String()
	// 立即输出日志，不缓冲
	log.Printf("TLS: New TCP connection from %s", remoteAddr)
	os.Stderr.Sync() // 强制刷新日志

	return conn, nil
}

// errorLoggingListener 包装 net.Listener，记录连接错误
type errorLoggingListener struct {
	net.Listener
	serverName string
}

func (l *errorLoggingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		log.Printf("TLS: Accept error on %s: %v", l.serverName, err)
		return nil, err
	}

	// 记录新连接
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("TLS: New connection from %s", remoteAddr)

	// 包装连接以记录 TLS 握手错误
	return &errorLoggingConn{
		Conn:       conn,
		serverName: l.serverName,
		remoteAddr: remoteAddr,
	}, nil
}

// errorLoggingConn 包装 net.Conn，记录 TLS 握手错误
type errorLoggingConn struct {
	net.Conn
	serverName      string
	handshakeLogged bool
	remoteAddr      string
}

func (c *errorLoggingConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err != nil && !c.handshakeLogged {
		// 记录读取错误（可能是 TLS 握手失败）
		errStr := err.Error()
		if strings.Contains(errStr, "tls") ||
			strings.Contains(errStr, "handshake") ||
			strings.Contains(errStr, "certificate") ||
			strings.Contains(errStr, "EOF") {
			log.Printf("TLS: Connection error from %s: %v", c.RemoteAddr(), err)
			c.handshakeLogged = true
		}
	}
	return n, err
}

func (c *errorLoggingConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if err != nil && !c.handshakeLogged {
		// 记录写入错误（可能是 TLS 握手失败）
		errStr := err.Error()
		if strings.Contains(errStr, "tls") ||
			strings.Contains(errStr, "handshake") ||
			strings.Contains(errStr, "certificate") ||
			strings.Contains(errStr, "broken pipe") ||
			strings.Contains(errStr, "connection reset") {
			log.Printf("TLS: Write error to %s: %v", c.RemoteAddr(), err)
			// 如果是连接重置，提供更详细的诊断信息
			if strings.Contains(errStr, "connection reset") {
				log.Printf("TLS: Connection reset by peer - This may indicate:")
				log.Printf("TLS:   1. Client rejected the certificate chain (check certificate chain completeness)")
				log.Printf("TLS:   2. TLS version/cipher suite mismatch")
				log.Printf("TLS:   3. Network issue (firewall, load balancer, etc.)")
				log.Printf("TLS:   4. Client-side certificate validation failure")
			}
			c.handshakeLogged = true
		}
	}
	return n, err
}

// tlsVersionString 将 TLS 版本号转换为字符串
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// detailedTLSLogger 详细的 TLS 错误日志记录器
type detailedTLSLogger struct {
	logger   *log.Logger
	certFile string
}

func (l *detailedTLSLogger) Write(p []byte) (n int, err error) {
	msg := string(p)

	// 提取错误信息
	if strings.Contains(msg, "TLS handshake error") {
		// 解析错误信息 - 格式: "http: TLS handshake error from <ip>:<port>: <error>"
		// 例如: "http: TLS handshake error from 122.97.148.0:62044: write tcp 192.168.144.3:443->122.97.148.0:62044: write: connection reset by peer"
		remoteAddrStart := strings.Index(msg, "from ")
		if remoteAddrStart > 0 {
			afterFrom := msg[remoteAddrStart+5:]
			// 找到 IP:PORT 后的第一个 ": "（错误信息的开始）
			errorStart := strings.Index(afterFrom, ": ")
			if errorStart > 0 {
				remoteAddr := strings.TrimSpace(afterFrom[:errorStart])
				errorMsg := strings.TrimSpace(afterFrom[errorStart+2:])
				errorMsgLower := strings.ToLower(errorMsg)

				// 对于常见的 "connection reset" 错误，简化日志输出（通常是扫描/攻击尝试）
				// 这种错误在生产环境中很常见，不需要详细的诊断信息
				if strings.Contains(errorMsgLower, "connection reset") {
					// 简化日志：只记录一行基本信息，避免日志噪音
					l.logger.Printf("TLS handshake failed: connection reset by peer from %s (likely scan/attack attempt)", remoteAddr)
					// 不再输出详细的诊断信息，减少日志噪音
					return len(p), nil
				}

				// 对于其他错误（证书错误、握手错误等），输出详细的诊断信息
				// 这些错误可能表示配置问题，需要详细诊断
				l.logger.Printf("==========================================")
				l.logger.Printf("TLS Handshake Error Details:")
				l.logger.Printf("  Remote Address: %s", remoteAddr)
				l.logger.Printf("  Error: %s", errorMsg)
				l.logger.Printf("  Timestamp: %s", time.Now().Format("2006/01/02 15:04:05"))

				// 分析错误原因
				if strings.Contains(errorMsgLower, "certificate") {
					l.logger.Printf("  Possible Causes:")
					l.logger.Printf("    1. Certificate not found for SNI")
					l.logger.Printf("    2. Certificate file read error")
					l.logger.Printf("    3. Certificate format invalid")
				} else if strings.Contains(errorMsgLower, "handshake") {
					l.logger.Printf("  Possible Causes:")
					l.logger.Printf("    1. TLS version mismatch")
					l.logger.Printf("    2. Cipher suite mismatch")
					l.logger.Printf("    3. Protocol negotiation failure")
				}

				l.logger.Printf("  Troubleshooting Steps:")
				if l.certFile != "" {
					l.logger.Printf("    1. Check certificate file: %s", l.certFile)
				}
				l.logger.Printf("    2. Verify certificate matches SNI domain")
				l.logger.Printf("    3. Test with: openssl s_client -connect <host>:443 -servername <sni>")
				l.logger.Printf("    4. Check firewall/NAT/load balancer logs")
				l.logger.Printf("    5. Review server logs for 'TLS: GetCertificate' messages")
				l.logger.Printf("==========================================")
			}
		}
	} else {
		// 其他错误正常记录
		return l.logger.Writer().Write(p)
	}

	return len(p), nil
}

// tlsErrorFilter 过滤 TLS 扫描/攻击相关的错误日志
type tlsErrorFilter struct{}

func (f *tlsErrorFilter) Write(p []byte) (n int, err error) {
	msg := string(p)

	// 检查是否是证书相关错误（这些应该被记录，可能是配置问题）
	certErrorPatterns := []string{
		"certificate",
		"cert",
		"GetCertificate",
		"no certificate",
		"Certificate Manager",
	}
	msgLower := strings.ToLower(msg)
	for _, pattern := range certErrorPatterns {
		if strings.Contains(msgLower, strings.ToLower(pattern)) {
			// 证书相关错误应该被记录
			return os.Stderr.Write(p)
		}
	}

	// 过滤掉常见的扫描/攻击错误，避免日志噪音
	ignorePatterns := []string{
		"tls: client offered only unsupported versions",
		"tls: no cipher suite supported",
		"tls: client requested unsupported application protocols",
		"tls: unexpected message",
		"remote error: tls:",
		": EOF",
	}

	for _, pattern := range ignorePatterns {
		if strings.Contains(msg, pattern) {
			// 静默忽略这些错误（它们是端口扫描/攻击尝试）
			return len(p), nil
		}
	}

	// 其他错误正常记录到标准错误输出
	return os.Stderr.Write(p)
}


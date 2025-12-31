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

	log.Printf("Certificate Manager: Loaded default certificate from %s, %s", certFile, keyFile)
	if cert.Leaf != nil {
		// 记录详细的证书信息，包括颁发者信息（用于诊断证书验证问题）
		issuer := cert.Leaf.Issuer.String()
		log.Printf("Certificate Manager: Default cert CN: %s, DNS Names: %v", cert.Leaf.Subject.CommonName, cert.Leaf.DNSNames)
		log.Printf("Certificate Manager: Certificate Issuer: %s", issuer)

		// 检查是否是开发证书（mkcert 或其他自签名证书）
		if strings.Contains(issuer, "mkcert") ||
			strings.Contains(issuer, "development") ||
			strings.Contains(issuer, "self-signed") ||
			cert.Leaf.Issuer.String() == cert.Leaf.Subject.String() {
			log.Printf("Certificate Manager: WARNING - This appears to be a development/self-signed certificate")
			log.Printf("Certificate Manager: Clients may need to accept the certificate or install the CA certificate")
			log.Printf("Certificate Manager: For OpenConnect clients, use: --servercert=pin-sha256:<hash>")
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

// GetCertificateBySNI 根据 SNI 获取证书（用于 TLS GetCertificate 回调）
// 参考 anylink 的 GetCertificateBySNI 实现
func (cm *certManager) GetCertificateBySNI(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// 如果客户端提供了 SNI，尝试匹配
	if chi.ServerName != "" {
		sni := strings.ToLower(chi.ServerName)
		if cert, ok := cm.certs[sni]; ok {
			if cert == nil {
				// 错误情况：总是记录
				log.Printf("Certificate Manager: ERROR - Certificate for SNI '%s' is nil!", chi.ServerName)
				// 继续尝试使用默认证书
			} else {
				// 匹配成功：只在第一次记录
				cm.loggedSNIsMu.RLock()
				alreadyLogged := cm.loggedSNIs[sni]
				cm.loggedSNIsMu.RUnlock()
				if !alreadyLogged {
					log.Printf("Certificate Manager: Matched SNI '%s' to specific certificate", chi.ServerName)
					cm.loggedSNIsMu.Lock()
					cm.loggedSNIs[sni] = true
					cm.loggedSNIsMu.Unlock()
				}
				return cert, nil
			}
		}

		// 如果没有精确匹配，尝试匹配通配符域名
		// 例如：*.example.com 匹配 www.example.com
		for sniKey, cert := range cm.certs {
			if strings.HasPrefix(sniKey, "*.") {
				domain := sniKey[2:] // 移除 "*."
				if strings.HasSuffix(sni, "."+domain) || sni == domain {
					if cert == nil {
						log.Printf("Certificate Manager: ERROR - Wildcard certificate for '%s' is nil!", sniKey)
						continue
					}
					// 匹配成功：只在第一次记录
					cm.loggedSNIsMu.RLock()
					alreadyLogged := cm.loggedSNIs[sni]
					cm.loggedSNIsMu.RUnlock()
					if !alreadyLogged {
						log.Printf("Certificate Manager: Matched SNI '%s' to wildcard certificate '%s'", chi.ServerName, sniKey)
						cm.loggedSNIsMu.Lock()
						cm.loggedSNIs[sni] = true
						cm.loggedSNIsMu.Unlock()
					}
					return cert, nil
				}
			}
		}

		// 没有找到匹配的SNI证书，使用默认证书（只在第一次记录）
		cm.loggedSNIsMu.RLock()
		alreadyLogged := cm.loggedSNIs[sni]
		cm.loggedSNIsMu.RUnlock()
		if !alreadyLogged {
			log.Printf("Certificate Manager: No specific certificate found for SNI '%s', using default", chi.ServerName)
			cm.loggedSNIsMu.Lock()
			cm.loggedSNIs[sni] = true
			cm.loggedSNIsMu.Unlock()
		}
	} else {
		// 客户端没有提供SNI（只在第一次记录）
		cm.loggedSNIsMu.RLock()
		alreadyLogged := cm.loggedSNIs[""]
		cm.loggedSNIsMu.RUnlock()
		if !alreadyLogged {
			log.Printf("Certificate Manager: Client did not provide SNI, using default certificate")
			cm.loggedSNIsMu.Lock()
			cm.loggedSNIs[""] = true
			cm.loggedSNIsMu.Unlock()
		}
	}

	// 如果没有匹配的证书，使用默认证书
	if cm.defaultCert == nil {
		log.Printf("Certificate Manager: ERROR - Default certificate is nil! TLS handshake will fail.")
		return nil, fmt.Errorf("no certificate available for SNI '%s' and no default certificate configured", chi.ServerName)
	}

	return cm.defaultCert, nil
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
		log.Printf("Warning: Failed to load default certificate: %v", err)
		log.Printf("Server will start but TLS connections may fail")
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

	// 配置 TLS 以支持现代加密套件并兼容 AnyConnect 客户端
	// AnyConnect 客户端要求：
	// - TLS 1.2+ (AnyConnect 4.2+)
	// - TLS 1.3 (AnyConnect 5.0+)
	// - 支持 ECDHE 密码套件（推荐）和 RSA 密码套件（兼容性）
	// 注意：OpenConnect/AnyConnect 协议只使用 HTTP/1.1，不支持 HTTP/2
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // TLS 1.2+ (AnyConnect 4.2+ 要求)
		MaxVersion: tls.VersionTLS13, // TLS 1.3 (AnyConnect 5.0+ 支持)
		// 密码套件列表（按优先级排序）
		// 优先使用 ECDHE（前向保密），同时保留 RSA 套件以兼容旧版客户端
		CipherSuites: []uint16{
			// ECDHE 套件（推荐，支持前向保密）
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,   // 优先：256位 AES，更强的安全性
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,   // 128位 AES，性能更好
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, // ECDSA 证书
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // ECDSA 证书
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,    // ChaCha20-Poly1305（移动设备优化）
			// RSA 套件（兼容性，某些旧版客户端可能需要）
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384, // RSA 密钥交换（无前向保密，但兼容性好）
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256, // RSA 密钥交换
		},
		PreferServerCipherSuites: true, // 优先使用服务器选择的密码套件
		NextProtos:               []string{"http/1.1"},
		// SNI 支持：根据客户端提供的 ServerName 选择对应的证书
		// 参考 anylink 的 GetCertificateBySNI 实现
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.certManager.GetCertificateBySNI(chi)
		},
	}

	s.httpsServer = &http.Server{
		Addr:              s.cfg.Server.Host + ":" + s.cfg.VPN.OpenConnectPort,
		Handler:           customHandler,
		TLSConfig:         tlsConfig,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       300 * time.Second,
		ReadHeaderTimeout: 0,
		// 重要：确保启用 keep-alive，即使客户端没有明确请求
		// 这对于 OpenConnect/AnyConnect 协议是必需的
	}

	go func() {
		log.Printf("HTTPS server (OpenConnect) starting on %s:%s", s.cfg.Server.Host, s.cfg.VPN.OpenConnectPort)
		log.Printf("Using default certificates: %s, %s", s.cfg.VPN.CertFile, s.cfg.VPN.KeyFile)
		log.Printf("SNI (Server Name Indication) support enabled - certificates can be configured per domain")
		// 注意：当使用 GetCertificate 回调时，ListenAndServeTLS 的 certFile 和 keyFile 参数会被忽略
		// 但我们仍然需要提供它们作为后备（如果 GetCertificate 返回错误）
		if err := s.httpsServer.ListenAndServeTLS(s.cfg.VPN.CertFile, s.cfg.VPN.KeyFile); err != nil && err != http.ErrServerClosed {
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

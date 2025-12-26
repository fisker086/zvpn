package server

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

// connectHandler 自定义 HTTP Handler，用于拦截 CONNECT 请求
type connectHandler struct {
	ginHandler http.Handler
	ocHandler  *openconnect.Handler
}

// ServeHTTP 实现 http.Handler 接口
func (h *connectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	shutdownComplete chan struct{}
	ctx              context.Context
	cancel           context.CancelFunc
}

// New 创建新的服务器实例
func New(cfg *config.Config, vpnServer *vpn.VPNServer) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:              cfg,
		vpnServer:        vpnServer,
		shutdownComplete: make(chan struct{}),
		ctx:              ctx,
		cancel:           cancel,
	}
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
	}

	s.httpsServer = &http.Server{
		Addr:         s.cfg.Server.Host + ":" + s.cfg.VPN.OpenConnectPort,
		Handler:      customHandler,
		TLSConfig:    tlsConfig,
		ReadTimeout:  0,
		WriteTimeout: 0,
		IdleTimeout:  300 * time.Second,
	}

	go func() {
		log.Printf("HTTPS server (OpenConnect) starting on %s:%s", s.cfg.Server.Host, s.cfg.VPN.OpenConnectPort)
		log.Printf("Using certificates: %s, %s", s.cfg.VPN.CertFile, s.cfg.VPN.KeyFile)
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

// tlsErrorFilter 过滤 TLS 扫描/攻击相关的错误日志
type tlsErrorFilter struct{}

func (f *tlsErrorFilter) Write(p []byte) (n int, err error) {
	msg := string(p)
	// 过滤掉常见的扫描/攻击错误，避免日志噪音
	ignorePatterns := []string{
		"TLS handshake error",
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

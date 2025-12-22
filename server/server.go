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

// Server 服务器管理器
type Server struct {
	cfg              *config.Config
	vpnServer        *vpn.VPNServer
	httpServer       *http.Server
	httpsServer      *http.Server
	ocHandler        *openconnect.Handler
	shutdownComplete chan struct{}
}

// New 创建新的服务器实例
func New(cfg *config.Config, vpnServer *vpn.VPNServer) *Server {
	return &Server{
		cfg:              cfg,
		vpnServer:        vpnServer,
		shutdownComplete: make(chan struct{}),
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
		log.Printf("========================================")
		log.Printf("DTLS is enabled in config, attempting to start DTLS UDP server...")
		log.Printf("DTLS will listen on UDP port: %s (same as TCP port)", s.cfg.VPN.OpenConnectPort)
		if err := s.ocHandler.StartDTLSServer(); err != nil {
			log.Printf("ERROR: Failed to start DTLS server: %v", err)
			log.Printf("DTLS will be disabled. Clients will use SSL/TLS only.")
			log.Printf("========================================")
		} else {
			log.Printf("DTLS UDP server started successfully")
			log.Printf("DTLS is ready to accept connections on UDP port %s", s.cfg.VPN.OpenConnectPort)
			log.Printf("========================================")
		}
	} else {
		log.Printf("DTLS is disabled in config (enabledtls: false)")
	}

	// 等待中断信号
	s.waitForShutdown()

	return nil
}

// startAuditLogFlusher 启动定期刷新审计日志缓冲区的goroutine
func (s *Server) startAuditLogFlusher() {
	ticker := time.NewTicker(30 * time.Second) // 每30秒刷新一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			auditLogger := policy.GetAuditLogger()
			if auditLogger != nil {
				if err := auditLogger.Flush(); err != nil {
					log.Printf("Failed to flush audit logs: %v", err)
				}
			}
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

	// 我们不需要自定义处理器来处理CONNECT请求
	// 相反，我们应该在OpenConnect的路由设置中处理它
	// 让Gin处理所有请求，包括CONNECT请求
	// 我们会在OpenConnect的Handler中正确处理CONNECT请求
	customHandler := router

	// 配置 TLS 以支持现代加密套件并减少日志噪音
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // 只支持 TLS 1.2+
		MaxVersion: tls.VersionTLS13, // 支持 TLS 1.3
		// 使用 Go 默认的现代加密套件（安全且兼容性好）
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
		NextProtos:               []string{"h2", "http/1.1"}, // 支持 HTTP/2 和 HTTP/1.1
	}

	s.httpsServer = &http.Server{
		Addr:      s.cfg.Server.Host + ":" + s.cfg.VPN.OpenConnectPort,
		Handler:   customHandler,
		TLSConfig: tlsConfig,
		// 自定义错误日志处理器，过滤掉扫描/攻击相关的错误
		ErrorLog: log.New(&tlsErrorFilter{}, "", 0),
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

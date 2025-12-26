package openconnect

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fisker/zvpn/auth"
	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/vpn"
	"github.com/fisker/zvpn/vpn/policy"
	"github.com/fisker/zvpn/vpn/security"
	"github.com/gin-gonic/gin"
)

// DTLSClientInfo DTLS 客户端信息
type DTLSClientInfo struct {
	Client        *TunnelClient
	UDPAddr       *net.UDPAddr // 客户端的 UDP 地址
	DTLSConn      net.Conn     // DTLS 连接（用于发送数据）
	LastSeen      time.Time    // 最后活动时间
	DTLSSessionID string       // DTLS会话ID映射，用于快速客户端匹配
}

// Handler OpenConnect 处理器结构体
type Handler struct {
	config               *config.Config
	vpnServer            *vpn.VPNServer
	ldapAuthenticator    *auth.LDAPAuthenticator
	tunDevice            *vpn.TUNDevice
	dtlsListener         net.Listener // DTLS 监听器
	dtlsRawUDPConn       *net.UDPConn
	dtlsClients          map[string]*DTLSClientInfo // VPN IP -> DTLSClientInfo 映射，用于 DTLS
	dtlsLock             sync.RWMutex
	dtlsSessionStore     *dtlsSessionStore // DTLS session store（用于 session resumption）
	bruteforceProtection *security.BruteforceProtection
	clientDetector       ClientDetector // 客户端检测器（用于识别客户端类型）
}

// parseClientInfo extracts OS and client version from User-Agent heuristically.
func parseClientInfo(ua string) (osName string, version string) {
	lc := strings.ToLower(ua)

	switch {
	case strings.Contains(lc, "windows"):
		osName = "Windows"
	case strings.Contains(lc, "mac os") || strings.Contains(lc, "macintosh") || strings.Contains(lc, "darwin"):
		osName = "macOS"
	case strings.Contains(lc, "android"):
		osName = "Android"
	case strings.Contains(lc, "iphone") || strings.Contains(lc, "ipad") || strings.Contains(lc, "ios"):
		osName = "iOS"
	case strings.Contains(lc, "linux"):
		osName = "Linux"
	default:
		osName = ""
	}

	reClientVer := regexp.MustCompile(`(?i)(openconnect|anyconnect)[^0-9]*([0-9][0-9\\.\\-]+)`)
	if matches := reClientVer.FindStringSubmatch(ua); len(matches) == 3 {
		version = matches[2]
	}
	return
}

// getHeaderCaseInsensitive 获取 HTTP header，尝试多个可能的名称（大小写不敏感）
func getHeaderCaseInsensitive(c *gin.Context, names ...string) string {
	for _, name := range names {
		if value := c.GetHeader(name); value != "" {
			return value
		}
	}
	return ""
}

// NewHandler 创建 OpenConnect 处理器
func NewHandler(cfg *config.Config, vpnServer *vpn.VPNServer) *Handler {
	var ldapAuth *auth.LDAPAuthenticator
	if cfg.LDAP.Enabled {
		ldapConfig := &auth.LDAPConfig{
			Enabled:      cfg.LDAP.Enabled,
			Host:         cfg.LDAP.Host,
			Port:         cfg.LDAP.Port,
			BindDN:       cfg.LDAP.BindDN,
			BindPassword: cfg.LDAP.BindPassword,
			BaseDN:       cfg.LDAP.BaseDN,
			UserFilter:   cfg.LDAP.UserFilter,
			AdminGroup:   cfg.LDAP.AdminGroup,
		}
		ldapAuth = auth.NewLDAPAuthenticator(ldapConfig)
	}

	// 从 VPNServer 获取密码爆破防护实例（如果已初始化）
	var bruteforceProtection *security.BruteforceProtection
	if vpnServer != nil {
		if bpInterface := vpnServer.GetBruteforceProtection(); bpInterface != nil {
			if bp, ok := bpInterface.(*security.BruteforceProtection); ok {
				bruteforceProtection = bp
				log.Printf("OpenConnect: Using shared bruteforce protection instance from VPNServer")
			}
		}
	}

	// 如果 VPNServer 中没有，则创建新实例（向后兼容）
	if bruteforceProtection == nil && cfg.VPN.EnableBruteforceProtection {
		maxAttempts := cfg.VPN.MaxLoginAttempts
		if maxAttempts <= 0 {
			maxAttempts = 5 // 默认值
		}
		lockoutDuration := time.Duration(cfg.VPN.LoginLockoutDuration) * time.Second
		if lockoutDuration <= 0 {
			lockoutDuration = 15 * time.Minute // 默认15分钟
		}
		windowDuration := time.Duration(cfg.VPN.LoginAttemptWindow) * time.Second
		if windowDuration <= 0 {
			windowDuration = 5 * time.Minute // 默认5分钟
		}
		bruteforceProtection = security.NewBruteforceProtection(maxAttempts, lockoutDuration, windowDuration)
		// 如果 eBPF 程序可用，设置它
		if vpnServer != nil {
			if ebpfProg := vpnServer.GetEBPFProgram(); ebpfProg != nil {
				bruteforceProtection.SetEBPFProgram(ebpfProg)
			}
		}
		log.Printf("OpenConnect: Bruteforce protection enabled: max attempts=%d, lockout=%v, window=%v",
			maxAttempts, lockoutDuration, windowDuration)
	}

	handler := &Handler{
		config:               cfg,
		vpnServer:            vpnServer,
		ldapAuthenticator:    ldapAuth,
		dtlsClients:          make(map[string]*DTLSClientInfo),
		bruteforceProtection: bruteforceProtection,
		clientDetector:       NewClientDetector(), // 初始化客户端检测器
	}

	// Get the shared TUN device from VPNServer
	if vpnServer != nil {
		if tunDevice := vpnServer.GetTUNDevice(); tunDevice != nil {
			handler.tunDevice = tunDevice
			log.Printf("OpenConnect: Using shared TUN device: %s", cfg.VPN.InterfaceName)
		} else {
			log.Printf("OpenConnect: Warning - No TUN device available from VPNServer")
		}
	}

	return handler
}

// AuthMiddleware 处理认证状态检查的中间件
func (h *Handler) AuthMiddleware(c *gin.Context) {
	if c.Request.URL.Path == "/" || c.Request.URL.Path == "/auth" || c.Request.URL.Path == "/profile.xml" {
		c.Next()
		return
	}

	if c.GetBool("authenticated") {
		c.Next()
		return
	}

	sessionCookie, err := c.Cookie("webvpn")
	if err != nil || sessionCookie == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// 解析 session ID (格式: webvpn-username-userID)
	parts := strings.Split(sessionCookie, "-")
	if len(parts) != 3 {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	userID, err := strconv.Atoi(parts[2])
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// 验证用户是否存在且有效
	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// 检查用户是否被禁用
	if !user.IsActive {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	// 设置认证状态和用户信息
	c.Set("authenticated", true)
	c.Set("userID", userID)
	c.Set("username", user.Username)
	c.Set("vpnIP", user.VPNIP)

	c.Next()
}

// SetupRoutes 设置 OpenConnect 路由
func (h *Handler) SetupRoutes(router *gin.Engine) {
	// 添加全局认证中间件
	router.Use(h.AuthMiddleware)

	// CONNECT请求处理 - 必须在其他路由注册之后，避免路由冲突
	// 注意：CONNECT 请求的路径通常是 "/CSCOSSLC/tunnel"
	// 如果客户端使用其他路径，可以在 handleConnect 中处理
	router.Handle("CONNECT", "/CSCOSSLC/tunnel", h.handleConnect)

	// OpenConnect 协议端点
	router.GET("/", h.Index)
	router.POST("/", h.GetConfig) // OpenConnect 客户端首先 POST / 获取配置
	router.POST("/auth", h.Authenticate)
	router.GET("/profile.xml", h.GetProfile) // AnyConnect 客户端下载配置文件

	// 其他HTTP方法的路由（虽然OpenConnect主要使用CONNECT）
	tunnelGroup := router.Group("/CSCOSSLC")
	tunnelGroup.Use(h.ConnectMiddleware)
	tunnelGroup.GET("/tunnel", h.TunnelHandler)
	tunnelGroup.POST("/tunnel", h.TunnelHandler)
}

// handleConnect 处理CONNECT请求，这是OpenConnect协议的核心
func (h *Handler) handleConnect(c *gin.Context) {
	// 检查认证状态
	if !c.GetBool("authenticated") {
		log.Printf("OpenConnect: Unauthenticated CONNECT request from %s (Path: %s)", c.ClientIP(), c.Request.URL.Path)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	// 获取用户ID
	userID, exists := c.Get("userID")
	if !exists {
		log.Printf("OpenConnect: Cannot get userID from context")
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	// 获取完整用户信息
	var user models.User
	if err := database.DB.Preload("Groups.Policies.Routes").First(&user, userID).Error; err != nil {
		log.Printf("OpenConnect: Failed to get user info: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// 分配或校验 VPN IP（使用共享 IP 池）
	if h.vpnServer == nil {
		log.Printf("OpenConnect: VPN server not initialized for user %s", user.Username)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// 如果没有 IP，或已有 IP 被其他用户占用，则重新分配
	needAlloc := user.VPNIP == ""
	if !needAlloc {
		if uid, ok := h.vpnServer.GetVPNIPUser(user.VPNIP); ok && uid != user.ID {
			needAlloc = true
		}
	}
	if needAlloc {
		vpnIP, err := h.vpnServer.AllocateVPNIP()
		if err != nil {
			log.Printf("OpenConnect: Failed to allocate VPN IP for user %s: %v", user.Username, err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		user.VPNIP = vpnIP.String()
	}
	if user.VPNIP == "" {
		log.Printf("OpenConnect: User %s has no VPN IP after allocation", user.Username)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	// Reserve current IP in pool to avoid duplicate assignment (e.g., after restart)
	if ip := net.ParseIP(user.VPNIP); ip != nil {
		h.vpnServer.ReserveVPNIP(ip)
	}

	// 检测客户端类型
	clientType := h.clientDetector.Detect(c)
	clientName := h.clientDetector.GetClientName(clientType)
	log.Printf("OpenConnect: CONNECT request from %s (user: %s, VPN IP: %s, client: %s)",
		c.ClientIP(), user.Username, user.VPNIP, clientName)

	conn, _, err := c.Writer.Hijack()
	if err != nil {
		log.Printf("OpenConnect: Failed to hijack connection: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.SetNoDelay(true); err != nil {
			log.Printf("OpenConnect: Warning - Failed to set TCP_NODELAY: %v", err)
		}
	}

	// 关闭请求体
	if c.Request.Body != nil {
		c.Request.Body.Close()
	}

	if policy := user.GetPolicy(); policy != nil {
		user.PolicyID = policy.ID
		user.Policy = *policy
	}

	// 获取DNS服务器配置（从策略中获取，如果没有则使用默认DNS）
	userDNSServers := getDNSServers(user.GetPolicy())

	// 构建DNS服务器列表，顺序为：
	// 1. DNS拦截器（用于域名管理功能，走VPN）
	// 2. 用户配置的DNS（从策略中获取）
	// 注意：不通过CSTP下发公网DNS，让客户端使用系统默认DNS（不走VPN）
	// 这样可以避免OpenConnect客户端为公网DNS IP自动添加路由到VPN
	var dnsServers []string

	// 只添加DNS拦截器作为DNS服务器（用于域名管理功能）
	if h.vpnServer != nil && h.vpnServer.GetDNSInterceptor() != nil {
		var dnsInterceptorIP string
		if tunDevice := h.vpnServer.GetTUNDevice(); tunDevice != nil {
			if tunIP, err := tunDevice.GetIP(); err == nil {
				dnsInterceptorIP = tunIP.String()
			}
		}

		if dnsInterceptorIP == "" {
			_, ipNet, err := net.ParseCIDR(h.config.VPN.Network)
			if err == nil {
				gatewayIP := make(net.IP, len(ipNet.IP))
				copy(gatewayIP, ipNet.IP)
				gatewayIP[len(gatewayIP)-1] = 1
				dnsInterceptorIP = gatewayIP.String()
			}
		}

		if dnsInterceptorIP != "" {
			dnsServers = append(dnsServers, dnsInterceptorIP)
		}
	}

	if len(userDNSServers) > 0 {
		dnsServers = append(dnsServers, userDNSServers...)
	}

	// 发送CSTP配置响应（包含HTTP响应头）

	// 获取客户端请求的 DTLS 密码套件和 Master Secret
	clientCipherSuite := getHeaderCaseInsensitive(c, "X-Dtls12-Ciphersuite", "X-DTLS12-CipherSuite", "X-Dtls-Ciphersuite", "X-DTLS-CipherSuite")
	if clientCipherSuite == "PSK-NEGOTIATE" {
		// 服务器使用证书模式，不支持 PSK
		clientCipherSuite = ""
	}

	clientMasterSecret := getHeaderCaseInsensitive(c, "X-Dtls-Master-Secret", "X-DTLS-Master-Secret")

	if err := h.sendCSTPConfig(conn, &user, dnsServers, clientCipherSuite, clientMasterSecret, clientType, c); err != nil {
		log.Printf("OpenConnect: Failed to send CSTP config: %v", err)
		conn.Close()
		return
	}

	// 更新用户连接状态
	user.Connected = true
	now := time.Now()
	user.LastSeen = &now
	database.DB.Save(&user)

	// 记录VPN连接审计日志
	auditLogger := policy.GetAuditLogger()
	if auditLogger != nil {
		clientIP := c.ClientIP()
		auditLogger.LogAuthWithIP(user.ID, user.Username, models.AuditLogActionConnect, "success",
			fmt.Sprintf("VPN connection established. VPN IP: %s", user.VPNIP), clientIP, 0)
	}

	// 获取VPN IP
	vpnIP := net.ParseIP(user.VPNIP)
	if vpnIP == nil {
		log.Printf("OpenConnect: Invalid VPN IP: %s", user.VPNIP)
		conn.Close()
		return
	}

	// 获取TUN设备
	tunDevice := h.vpnServer.GetTUNDevice()
	if tunDevice == nil {
		log.Printf("OpenConnect: TUN device not available")
		conn.Close()
		return
	}

	// 创建策略钩子
	if err := h.vpnServer.CreatePolicyHooks(&user); err != nil {
		log.Printf("OpenConnect: Warning - Failed to create policy hooks: %v", err)
	}

	userPolicy := user.GetPolicy()
	if userPolicy != nil && len(userPolicy.Routes) > 0 {
		log.Printf("OpenConnect: Adding %d policy routes immediately for user %s (no need to wait for DPD)",
			len(userPolicy.Routes), user.Username)

		// 获取VPN网关IP（优先使用TUN设备IP，支持多服务器横向扩容）
		var gateway net.IP
		if h.vpnServer != nil {
			gateway = h.vpnServer.GetVPNGatewayIP()
		}
		if gateway == nil {
			// Fallback to configured gateway IP
			_, vpnNet, _ := net.ParseCIDR(h.config.VPN.Network)
			gateway = make(net.IP, len(vpnNet.IP))
			copy(gateway, vpnNet.IP)
			gateway[len(gateway)-1] = 1
		}

		// 获取路由管理器
		routeMgr := h.vpnServer.GetRouteManager()
		if routeMgr == nil {
			log.Printf("OpenConnect: Warning - RouteManager is nil, cannot add routes for user %s", user.Username)
		} else {
			addedCount := 0
			skippedCount := 0
			for _, route := range userPolicy.Routes {
				// 跳过VPN网络本身
				if route.Network == h.config.VPN.Network {
					skippedCount++
					continue
				}

				_, ipNet, err := net.ParseCIDR(route.Network)
				if err != nil {
					log.Printf("OpenConnect: Warning - Failed to parse route %s: %v", route.Network, err)
					continue
				}

				var routeGateway net.IP
				if route.Gateway != "" {
					routeGateway = net.ParseIP(route.Gateway)
				} else {
					routeGateway = gateway
				}

				// 添加到内核路由表（通过netlink）
				if err := routeMgr.AddRoute(ipNet, routeGateway, route.Metric); err != nil {
					// 路由可能已存在，这是正常的（例如多个用户共享同一路由）
					log.Printf("OpenConnect: Route %s via %s: %v (may already exist)",
						route.Network, routeGateway.String(), err)
				} else {
					log.Printf("OpenConnect: ✓ Added route %s via %s (metric: %d) for user %s",
						route.Network, routeGateway.String(), route.Metric, user.Username)
					addedCount++
				}
			}
		}
	}

	userAgent := c.Request.UserAgent()
	clientOS, clientVer := parseClientInfo(userAgent)
	tunnelClient := NewTunnelClient(&user, conn, vpnIP, h.vpnServer, tunDevice)

	// 注册 DTLS 客户端（如果启用 DTLS）
	if h.config.VPN.EnableDTLS {
		h.dtlsLock.Lock()
		h.dtlsClients[user.VPNIP] = &DTLSClientInfo{
			Client:   tunnelClient,
			UDPAddr:  nil, // 将在建立 DTLS 连接时设置
			DTLSConn: nil, // 将在建立 DTLS 连接时设置
			LastSeen: time.Now(),
		}
		h.dtlsLock.Unlock()
	}

	// 获取 WriteChan 缓冲区大小配置
	bufferSize := 100 // Default
	if cfg := h.vpnServer.GetConfig(); cfg != nil {
		if cfg.VPN.WriteChanBufferSize > 0 {
			bufferSize = cfg.VPN.WriteChanBufferSize
		}
	}

	// 注册客户端到VPN服务器
	vpnClient := &vpn.VPNClient{
		UserID:     user.ID,
		User:       &user,
		Conn:       conn,
		IP:         vpnIP,
		UserAgent:  userAgent,
		ClientOS:   clientOS,
		ClientVer:  clientVer,
		Connected:  true,
		WriteChan:  make(chan []byte, bufferSize), // Buffered channel with configurable size
		WriteClose: make(chan struct{}),
	}
	h.vpnServer.RegisterClient(user.ID, vpnClient)

	go vpnClient.WriteLoop()

	defer func() {
		if r := recover(); r != nil {
			log.Printf("OpenConnect: PANIC in HandleTunnelData for user %s: %v\n%s", user.Username, r, debug.Stack())
			if client, exists := h.vpnServer.GetClient(user.ID); exists && client != nil {
				select {
				case <-client.WriteClose:
				default:
					close(client.WriteClose)
				}
			}
			if conn != nil {
				conn.Close()
			}
		}
	}()

	if err := tunnelClient.HandleTunnelData(); err != nil {
		log.Printf("OpenConnect: HandleTunnelData returned error for user %s: %v", user.Username, err)
	}

	// 清理工作
	log.Printf("OpenConnect: Tunnel closed for user %s", user.Username)

	// CRITICAL: Stop WriteLoop before closing connection to prevent RST packets
	// This ensures graceful connection shutdown:
	// 1. Stop WriteLoop goroutine first (signal via WriteClose channel)
	// 2. Wait a moment for WriteLoop to finish any pending writes
	// 3. Properly close TLS session if it's a TLS connection (send close_notify)
	// 4. Then close the connection
	// This prevents the scenario where:
	// - Connection is closed (FIN sent)
	// - Client sends data after receiving FIN
	// - Server sends RST because connection is already closed
	client, exists := h.vpnServer.GetClient(user.ID)
	if exists && client != nil {
		// Signal WriteLoop to stop
		select {
		case <-client.WriteClose:
			// Already closed
		default:
			close(client.WriteClose)
			// Give WriteLoop a moment to finish any pending writes
			// This prevents RST packets when connection closes
			time.Sleep(50 * time.Millisecond)
		}
		// Close the connection after WriteLoop has stopped
		// This ensures graceful shutdown: FIN is sent only after all writes are complete
		if conn != nil {
			closeConnectionGracefully(conn)
		}
	} else if conn != nil {
		// Fallback: if client not found, close connection directly
		closeConnectionGracefully(conn)
	}

	// 移除策略钩子
	if err := h.vpnServer.RemovePolicyHooks(user.ID); err != nil {
		log.Printf("OpenConnect: Warning - Failed to remove policy hooks: %v", err)
	}

	// 注销客户端
	h.vpnServer.UnregisterClient(user.ID, user.VPNIP)

	// 注销 DTLS 客户端并关闭 DTLS 连接
	if h.config.VPN.EnableDTLS {
		h.dtlsLock.Lock()
		clientInfo, exists := h.dtlsClients[user.VPNIP]
		if exists && clientInfo != nil {
			// Close DTLS connection if it exists
			// This ensures DTLS connection is properly closed when TCP connection closes
			if clientInfo.DTLSConn != nil {
				log.Printf("OpenConnect: Closing DTLS connection for user %s (VPN IP: %s)", user.Username, user.VPNIP)
				// Close DTLS connection gracefully
				// For DTLS connections, Close() will send close_notify automatically
				if err := clientInfo.DTLSConn.Close(); err != nil {
					// Ignore "use of closed network connection" errors
					errStr := err.Error()
					if !strings.Contains(errStr, "use of closed network connection") &&
						!strings.Contains(errStr, "connection reset by peer") &&
						!strings.Contains(errStr, "broken pipe") {
						log.Printf("OpenConnect: Warning - Failed to close DTLS connection: %v", err)
					}
				}
				// Clear DTLS connection reference
				clientInfo.DTLSConn = nil
			}
			// Also clear VPNClient's DTLSConn reference
			if client, exists := h.vpnServer.GetClient(user.ID); exists && client != nil {
				client.DTLSConn = nil
			}
		}
		delete(h.dtlsClients, user.VPNIP)
		h.dtlsLock.Unlock()
		log.Printf("OpenConnect: Unregistered DTLS client for user %s (VPN IP: %s)", user.Username, user.VPNIP)
	}

	// 释放IP并重置用户状态
	if h.vpnServer != nil && user.VPNIP != "" {
		if ip := net.ParseIP(user.VPNIP); ip != nil {
			h.vpnServer.ReleaseVPNIP(ip)
		}
	}
	user.Connected = false
	user.VPNIP = ""
	if err := database.DB.Save(&user).Error; err != nil {
		log.Printf("OpenConnect: Failed to update user status on disconnect: %v", err)
	}

	// 记录VPN断开审计日志
	// 注意：此时连接已关闭，使用VPN IP作为源IP
	auditLogger2 := policy.GetAuditLogger()
	if auditLogger2 != nil {
		auditLogger2.LogAuthWithIP(user.ID, user.Username, models.AuditLogActionDisconnect, "success",
			fmt.Sprintf("VPN connection closed. VPN IP: %s", user.VPNIP), user.VPNIP, 0)
	}

	// 更新用户状态
	user.Connected = false
	database.DB.Save(&user)
}

// sendCSTPConfig 发送CSTP配置响应
// clientType 用于根据客户端类型调整配置（AnyConnect/OpenConnect 使用相同协议，但可能有细微差异）
// c 用于获取客户端请求的 header（如 X-CSTP-Base-MTU, X-Cstp-Accept-Encoding 等）
func (h *Handler) sendCSTPConfig(conn net.Conn, user *models.User, dnsServers []string, clientCipherSuite string, clientMasterSecret string, clientType ClientType, c *gin.Context) error {
	// 解析VPN网络配置
	_, ipNet, err := net.ParseCIDR(h.config.VPN.Network)
	if err != nil {
		return err
	}

	netmask := net.IP(ipNet.Mask).String()

	// 判断是否应该让所有DNS查询走VPN（智能DNS路由）
	hasDNSInterceptor := h.vpnServer != nil && h.vpnServer.GetDNSInterceptor() != nil
	tunnelAllDNS := shouldTunnelAllDNS(hasDNSInterceptor, dnsServers)

	if hasDNSInterceptor {
		log.Printf("OpenConnect: Smart DNS routing - DNS interceptor enabled, Tunnel-All-DNS=false, DNS interceptor (VPN gateway) will go through VPN via split-include route, public DNS will use direct connection")
	} else {
		log.Printf("OpenConnect: Smart DNS routing - DNS interceptor disabled, all DNS queries will use direct connection")
	}

	// 构建CSTP响应头
	// 这是服务端和客户端的协商过程：
	// 1. 服务端通过 HTTP header 发送配置参数（DPD、Keepalive 等）
	// 2. 客户端自动接收并使用这些参数
	// 3. 客户端无需手动配置，协议会自动处理 keep-alive 机制
	response := "HTTP/1.1 200 OK\r\n"
	response += "Content-Type: application/octet-stream\r\n"

	// 获取主机名（用于 X-CSTP-Hostname）
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "zvpn"
	}

	// 获取客户端请求的 header
	cstpBaseMTU := getHeaderCaseInsensitive(c, "X-CSTP-Base-MTU", "X-Cstp-Base-MTU")
	cstpAcceptEncoding := getHeaderCaseInsensitive(c, "X-Cstp-Accept-Encoding", "X-CSTP-Accept-Encoding")
	dtlsAcceptEncoding := getHeaderCaseInsensitive(c, "X-Dtls-Accept-Encoding", "X-DTLS-Accept-Encoding")

	// 检测是否是 AnyConnect 客户端
	userAgent := strings.ToLower(c.Request.UserAgent())
	xAggregateAuth := c.Request.Header.Get("X-Aggregate-Auth")
	xTranscendVersion := c.Request.Header.Get("X-Transcend-Version")
	isAnyConnectClient := clientType == ClientTypeAnyConnect ||
		strings.Contains(userAgent, "anyconnect") ||
		strings.Contains(userAgent, "cisco secure client") ||
		(xAggregateAuth != "" && xTranscendVersion != "")

	response += "X-CSTP-Version: 1\r\n"
	response += "X-CSTP-Server-Name: ZVPN 1.0\r\n"
	response += "X-CSTP-Protocol: Copyright (c) 2004 Cisco Systems, Inc.\r\n"

	// cisco-client-compat: 启用与旧版 Cisco AnyConnect 客户端的兼容性
	// 支持预发布版本的 DTLS，不要求客户端在每次 TLS 连接时都提供证书
	// 如果配置中启用了 cisco-client-compat，或者检测到 AnyConnect 客户端，则启用
	ciscoClientCompat := h.config.VPN.CiscoClientCompat
	if !ciscoClientCompat && isAnyConnectClient {
		ciscoClientCompat = true // 对于 AnyConnect 客户端，默认启用兼容性
	}
	if ciscoClientCompat {
		response += "X-Cisco-Client-Compat: 1\r\n"
	}

	response += "X-CSTP-Address: " + user.VPNIP + "\r\n"
	response += "X-CSTP-Netmask: " + netmask + "\r\n"
	response += "X-CSTP-Hostname: " + hostname + "\r\n"
	if cstpBaseMTU != "" {
		response += "X-CSTP-Base-MTU: " + cstpBaseMTU + "\r\n"
	}
	response += "X-CSTP-MTU: " + strconv.Itoa(h.config.VPN.MTU) + "\r\n"
	// DPD 和 Keepalive 配置（服务端发送给客户端，客户端自动使用）
	// DPD (Dead Peer Detection): 检测死连接，终止隧道（但不终止会话），客户端会重新建立隧道
	// Keepalive: 防止 NAT/防火墙/代理设备关闭连接，默认 20 秒（AnyConnect 标准）
	// 注意：DPD 不会终止会话，只是终止隧道。Keepalive 有助于防止 NAT 设备关闭连接
	// 客户端会自动使用这些参数，无需手动配置
	cstpDPD := h.config.VPN.CSTPDPD
	if cstpDPD == 0 {
		cstpDPD = 30 // 默认值：30秒
	}
	cstpKeepalive := h.config.VPN.CSTPKeepalive
	if cstpKeepalive == 0 {
		cstpKeepalive = 20 // 默认值：20秒（AnyConnect 标准）
	}
	response += fmt.Sprintf("X-CSTP-DPD: %d\r\n", cstpDPD)
	response += fmt.Sprintf("X-CSTP-Keepalive: %d\r\n", cstpKeepalive)
	response += "X-CSTP-Lease-Duration: 1209600\r\n" // IP 地址租期：14天
	response += "X-CSTP-Session-Timeout: none\r\n"   // 会话超时：无限制
	response += "X-CSTP-Session-Timeout-Alert-Interval: 60\r\n"
	response += "X-CSTP-Session-Timeout-Remaining: none\r\n"
	response += "X-CSTP-Idle-Timeout: 0\r\n"             // 空闲超时：0 表示禁用
	response += "X-CSTP-Disconnected-Timeout: 18000\r\n" // 断开超时：5小时
	response += "X-CSTP-Keep: true\r\n"                  // 保持连接
	response += "X-CSTP-Rekey-Time: 86400\r\n"           // 重密钥时间：24小时
	response += "X-CSTP-Rekey-Method: new-tunnel\r\n"    // 重密钥方法：新建隧道
	response += "X-CSTP-MSIE-Proxy-Lockdown: true\r\n"
	response += "X-CSTP-Smartcard-Removal-Disconnect: true\r\n"
	response += "X-CSTP-License: accept\r\n"
	response += "X-CSTP-Routing-Filtering-Ignore: false\r\n"
	response += "X-CSTP-Quarantine: false\r\n"
	response += "X-CSTP-Disable-Always-On-VPN: false\r\n"
	response += "X-CSTP-Client-Bypass-Protocol: true\r\n"
	response += "X-CSTP-TCP-Keepalive: false\r\n"
	if tunnelAllDNS {
		response += "X-CSTP-Tunnel-All-DNS: true\r\n"
	} else {
		response += "X-CSTP-Tunnel-All-DNS: false\r\n"
	}
	response += "X-CSTP-Tunnel-All-Networks: false\r\n" // 使用split-tunnel模式

	// 压缩编码配置（如果客户端支持且服务端启用）
	if h.config.VPN.EnableCompression && cstpAcceptEncoding != "" {
		compressionType := getCompressionType(h.config)
		if compressionType != "none" {
			// 检查客户端是否支持该压缩类型
			if strings.Contains(strings.ToLower(cstpAcceptEncoding), strings.ToLower(compressionType)) {
				response += "X-CSTP-Content-Encoding: " + compressionType + "\r\n"
			}
		}
	}

	// 添加DTLS支持（如果启用）
	if h.config.VPN.EnableDTLS {
		// OpenConnect客户端需要看到DTLS相关头部才会尝试建立DTLS连接
		// 需要设置以下头部：
		// X-DTLS-Session-ID - DTLS会话ID（用于会话恢复）
		// X-DTLS-Port - DTLS端口（UDP端口，通常与TCP端口相同）
		// X-DTLS-DPD - DTLS死连接检测间隔（秒）
		// X-DTLS-Keepalive - DTLS保活间隔（秒）
		// X-DTLS12-CipherSuite - DTLS 1.2密码套件列表

		// 生成DTLS Session ID（32字节，64个十六进制字符）
		// 在初始连接时生成一个临时ID，客户端可以用它来恢复会话
		sessionIDBytes := make([]byte, 32)
		if _, err := rand.Read(sessionIDBytes); err != nil {
			log.Printf("OpenConnect: Warning - Failed to generate DTLS session ID: %v", err)
			// 如果生成失败，使用零值（客户端会进行新的握手）
			sessionIDBytes = make([]byte, 32)
		}
		dtlsSessionID := hex.EncodeToString(sessionIDBytes)

		// DTLS端口（使用与TCP相同的端口，但使用UDP协议）
		dtlsPort := h.config.VPN.OpenConnectPort
		if h.config.VPN.DTLSPort != "" && h.config.VPN.DTLSPort != h.config.VPN.OpenConnectPort {
			// 如果配置了不同的DTLS端口，使用配置的端口
			dtlsPort = h.config.VPN.DTLSPort
		}

		// DTLS DPD和Keepalive（使用与CSTP相同的值）
		// 确保 DTLS 和 CSTP 使用相同的超时值，这样两个隧道的行为一致
		// 这对于 Idle-Timeout 很重要：必须两个隧道都空闲才会断开
		cstpDPD := h.config.VPN.CSTPDPD
		if cstpDPD == 0 {
			cstpDPD = 30 // 默认值：30秒
		}
		cstpKeepalive := h.config.VPN.CSTPKeepalive
		if cstpKeepalive == 0 {
			cstpKeepalive = 20 // 默认值：20秒（AnyConnect 标准）
		}
		dtlsDPD := strconv.Itoa(cstpDPD)             // 与X-CSTP-DPD一致
		dtlsKeepalive := strconv.Itoa(cstpKeepalive) // 与X-CSTP-Keepalive一致

		// DTLS 密码套件（使用标准 TLS 密码套件名称）
		// 使用 checkDtls12Ciphersuite 函数验证和选择客户端请求的密码套件
		// 如果客户端请求了密码套件，验证并选择支持的密码套件；否则使用默认值（ECDHE-RSA-AES256-GCM-SHA384）
		cipherSuiteHeader := checkDtls12Ciphersuite(clientCipherSuite)
		// 记录密码套件配置
		if clientCipherSuite != "" {
			log.Printf("OpenConnect: DTLS cipher suites: %s (client requested: %s)", cipherSuiteHeader, clientCipherSuite)
		} else {
			log.Printf("OpenConnect: DTLS cipher suites: %s (using default)", cipherSuiteHeader)
		}

		response += "X-DTLS-Session-ID: " + dtlsSessionID + "\r\n"
		response += "X-DTLS-Port: " + dtlsPort + "\r\n"
		response += "X-DTLS-MTU: " + strconv.Itoa(h.config.VPN.MTU) + "\r\n" // DTLS MTU（与CSTP MTU相同）
		response += "X-DTLS-DPD: " + dtlsDPD + "\r\n"
		response += "X-DTLS-Keepalive: " + dtlsKeepalive + "\r\n"
		response += "X-DTLS-Rekey-Time: 86400\r\n"                        // DTLS 重密钥时间：24小时
		response += "X-DTLS-Rekey-Method: new-tunnel\r\n"                 // DTLS 重密钥方法：新建隧道
		response += "X-DTLS-CipherSuite: " + cipherSuiteHeader + "\r\n"   // DTLS 1.0/1.2 通用（单个短名称）
		response += "X-DTLS12-CipherSuite: " + cipherSuiteHeader + "\r\n" // DTLS 1.2 专用（单个短名称）- 注意：必须使用连字符

		// dtls-legacy: 启用旧版 DTLS 协议支持
		// OpenConnect 和 AnyConnect 客户端都支持此头部，用于兼容旧版 DTLS 协议
		// 默认启用（除非明确禁用），因为现代客户端都兼容此模式
		dtlsLegacy := h.config.VPN.DTLSLegacy
		// 如果 cisco-client-compat 启用，默认启用 dtls-legacy（ocserv 行为）
		if !dtlsLegacy && ciscoClientCompat {
			dtlsLegacy = true
		}
		// 发送 legacy DTLS 支持头部（OpenConnect 和 AnyConnect 都支持）
		if dtlsLegacy {
			response += "X-DTLS-Legacy: 1\r\n"
		}

		// DTLS 压缩编码配置（如果客户端支持且服务端启用）
		if h.config.VPN.EnableCompression && dtlsAcceptEncoding != "" {
			compressionType := getCompressionType(h.config)
			if compressionType != "none" {
				// 检查客户端是否支持该压缩类型
				if strings.Contains(strings.ToLower(dtlsAcceptEncoding), strings.ToLower(compressionType)) {
					response += "X-DTLS-Content-Encoding: " + compressionType + "\r\n"
				}
			}
		}

		// 如果客户端提供了 master secret，将其存储到 session store 中
		// 这样在 DTLS 握手时可以使用它进行 session resumption
		if clientMasterSecret != "" && h.dtlsSessionStore != nil {
			if err := h.dtlsSessionStore.StoreMasterSecret(dtlsSessionID, clientMasterSecret); err != nil {
				log.Printf("OpenConnect: Warning - Failed to store master secret: %v", err)
			} else {
				log.Printf("OpenConnect: Stored master secret for session ID: %s", dtlsSessionID)
			}
		}

		log.Printf("OpenConnect: CSTP config - DTLS enabled:")
		log.Printf("OpenConnect:   - Session ID: %s", dtlsSessionID)
		log.Printf("OpenConnect:   - Port: %s (UDP)", dtlsPort)
		log.Printf("OpenConnect:   - DPD: %s seconds", dtlsDPD)
		log.Printf("OpenConnect:   - Keepalive: %s seconds", dtlsKeepalive)
		log.Printf("OpenConnect:   - Cipher Suites: %s", cipherSuiteHeader)
	}

	// 添加DNS服务器
	for _, dns := range dnsServers {
		if dns != "" {
			response += "X-CSTP-DNS: " + dns + "\r\n"
		}
	}

	// 添加路由配置（split-include）
	// 构建路由列表（根据用户策略）
	var splitIncludeRoutes []string

	// 始终包含VPN网络本身，确保客户端可以访问VPN服务器和其他VPN客户端
	splitIncludeRoutes = append(splitIncludeRoutes, h.config.VPN.Network)

	// 添加策略路由
	if user.PolicyID != 0 && len(user.Policy.Routes) > 0 {
		for _, route := range user.Policy.Routes {
			// 避免重复添加VPN网络
			if route.Network != "" && route.Network != h.config.VPN.Network {
				splitIncludeRoutes = append(splitIncludeRoutes, route.Network)
			}
		}
		log.Printf("OpenConnect: CSTP config - User %s split-include routes: %v", user.Username, splitIncludeRoutes)
	} else {
		log.Printf("OpenConnect: CSTP config - User %s has no policy routes, using VPN network only", user.Username)
	}

	// 添加所有路由到HTTP头（每个路由一行）
	for _, route := range splitIncludeRoutes {
		response += "X-CSTP-Split-Include: " + route + "\r\n"
	}

	// 结束HTTP响应头（必须是两个CRLF）
	response += "\r\n"

	// 记录发送的 CSTP 配置（用于调试）
	log.Printf("OpenConnect: Sending CSTP config for user %s (IP: %s, MTU: %d, DNS: %v, Routes: %d)",
		user.Username, user.VPNIP, h.config.VPN.MTU, dnsServers, len(splitIncludeRoutes))
	if vpn.ShouldLogPacket() {
		// 只记录前 500 字节，避免日志过长
		previewLen := len(response)
		if previewLen > 500 {
			previewLen = 500
		}
		log.Printf("OpenConnect: CSTP response preview (first %d bytes):\n%s", previewLen, response[:previewLen])
	}

	// 发送响应
	if _, err = conn.Write([]byte(response)); err != nil {
		return fmt.Errorf("failed to write CSTP config: %w", err)
	}

	log.Printf("OpenConnect: CSTP config sent for user %s (IP: %s, MTU: %d)", user.Username, user.VPNIP, h.config.VPN.MTU)
	return nil
}

// ConnectMiddleware 处理 OpenConnect 隧道连接的中间件
func (h *Handler) ConnectMiddleware(c *gin.Context) {
	// 检查客户端是否已经认证
	if !c.GetBool("authenticated") {
		log.Printf("OpenConnect: Unauthenticated connection attempt")
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	// 从上下文获取用户信息
	userID, exists := c.Get("userID")
	if !exists {
		log.Printf("OpenConnect: Cannot get userID")
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	// 获取完整用户信息（包含策略）并存储到上下文中
	var user models.User
	if err := database.DB.Preload("Groups.Policies.Routes").First(&user, userID).Error; err != nil {
		log.Printf("OpenConnect: Failed to get user info: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// 将完整的用户信息存储到上下文中，以便 TunnelHandler 使用
	c.Set("user", user)

	// 继续执行下一个处理器（TunnelHandler）
	c.Next()
}

// TunnelHandler 处理非CONNECT方法的隧道请求（GET/POST）
func (h *Handler) TunnelHandler(c *gin.Context) {
	// OpenConnect主要使用CONNECT方法，GET/POST通常不应该到达这里
	log.Printf("OpenConnect: Non-CONNECT tunnel request: %s %s", c.Request.Method, c.Request.URL.Path)
	c.AbortWithStatus(http.StatusMethodNotAllowed)
}

// StartDTLSServer 启动 DTLS UDP 服务器
// 使用真正的 DTLS 实现（基于 pion/dtls）
func (h *Handler) StartDTLSServer() error {
	return h.startRealDTLSServer()
}

// handleDTLSPackets 处理 DTLS UDP 数据包（已废弃，使用真正的 DTLS 实现）
// 此函数保留用于向后兼容，但不会被调用
func (h *Handler) handleDTLSPackets(conn *net.UDPConn) {
	buf := make([]byte, 65535)
	log.Printf("DTLS: Packet handler started, waiting for UDP packets...")

	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("DTLS: Error reading UDP packet: %v", err)
			// 如果连接关闭，退出循环
			if strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("DTLS: UDP connection closed, exiting handler")
				return
			}
			continue
		}

		// 限制日志显示的字节数
		hexLen := n
		if hexLen > 32 {
			hexLen = 32
		}
		log.Printf("DTLS: Received %d bytes from %s (hex: %x)", n, clientAddr, buf[:hexLen])

		// DTLS 数据包可能有多种格式：
		// 1. 标准 CSTP 格式：version(1) + length(2) + type(1) + reserved(1) + payload (无 STF 前缀)
		// 2. 可能包含 STF 前缀的格式
		// 3. 初始握手/探测包

		var packetType byte
		var payload []byte
		var length uint16

		// CRITICAL: 过滤 DTLS 协议层数据包，只处理 CSTP 协议数据包
		// DTLS 数据包格式: ContentType(1) + Version(2) + Epoch(2) + Sequence(6) + Length(2) + Fragment
		// ContentType: 20=change_cipher_spec, 21=alert, 22=handshake, 23=application_data
		// 应用数据包的 ContentType 是 23 (0x17)

		if n < 5 {
			log.Printf("DTLS: Packet too short: %d bytes, ignoring", n)
			continue
		}

		// 检查是否是 DTLS 应用数据包 (ContentType = 23 = 0x17)
		if n >= 13 && buf[0] == 0x17 { // 0x17 = DTLS application data
			// 这是一个 DTLS 应用数据包，继续解析 CSTP
			log.Printf("DTLS: DTLS application data packet (ContentType=0x17)")

			// DTLS header: ContentType(1) + Version(2) + Epoch(2) + Sequence(6) + Length(2)
			// 跳过 DTLS header (13 bytes)，获取应用数据
			dtlsData := buf[13:n]

			if len(dtlsData) < 5 {
				log.Printf("DTLS: CSTP data too short after DTLS header: %d bytes", len(dtlsData))
				continue
			}

			// 现在解析 CSTP 数据包
			if len(dtlsData) >= 8 && dtlsData[0] == 'S' && dtlsData[1] == 'T' && dtlsData[2] == 'F' {
				// 有 STF 前缀的格式
				packetType = dtlsData[6]
				length = binary.BigEndian.Uint16(dtlsData[4:6])
				if int(length)+8 > len(dtlsData) {
					log.Printf("DTLS: Invalid packet length with STF: declared=%d, actual=%d", int(length)+8, len(dtlsData))
					continue
				}
				payload = dtlsData[8:]
				log.Printf("DTLS: CSTP packet with STF prefix, type=0x%02x, length=%d", packetType, length)
			} else {
				// 标准 CSTP 格式：version(1) + length(2) + type(1) + reserved(1) + payload
				packetType = dtlsData[3]
				length = binary.BigEndian.Uint16(dtlsData[1:3])

				if int(length)+5 != len(dtlsData) {
					log.Printf("DTLS: Invalid CSTP packet length: declared=%d, actual=%d, packet type=0x%02x", int(length)+5, len(dtlsData), packetType)
					if len(dtlsData) >= 5 {
						payload = dtlsData[5:]
					} else {
						continue
					}
				} else {
					payload = dtlsData[5:]
				}
				log.Printf("DTLS: Standard CSTP packet, type=0x%02x, length=%d", packetType, length)
			}
		} else {
			// 这不是 DTLS 应用数据包，可能是 DTLS 握手或其他协议消息
			// 跳过这些数据包，不记录为错误
			if n >= 2 {
				contentType := buf[0]
				log.Printf("DTLS: Non-application DTLS packet (ContentType=0x%02x), length=%d - skipping", contentType, n)
			} else {
				log.Printf("DTLS: Unknown packet format, length=%d - skipping", n)
			}
			continue
		}

		// 查找匹配的客户端
		h.dtlsLock.Lock()
		var matchedClient *TunnelClient
		var matchedVPNIP string

		// 首先尝试通过 UDP 地址匹配（最准确）
		for vpnIP, clientInfo := range h.dtlsClients {
			if clientInfo.UDPAddr != nil && clientInfo.UDPAddr.IP.Equal(clientAddr.IP) && clientInfo.UDPAddr.Port == clientAddr.Port {
				matchedClient = clientInfo.Client
				matchedVPNIP = vpnIP
				clientInfo.LastSeen = time.Now()
				break
			}
		}

		// 如果没有通过地址匹配，尝试通过数据包内容匹配
		if matchedClient == nil {
			// 对于数据包类型，尝试通过源 IP 匹配
			if packetType == PacketTypeData && len(payload) >= 20 {
				// 从数据包中提取源 IP
				srcIP := net.IP(payload[12:16])
				for vpnIP, clientInfo := range h.dtlsClients {
					if clientInfo.Client != nil && clientInfo.Client.IP != nil && srcIP.Equal(clientInfo.Client.IP) {
						matchedClient = clientInfo.Client
						matchedVPNIP = vpnIP
						// 更新客户端地址信息
						clientInfo.UDPAddr = clientAddr
						clientInfo.LastSeen = time.Now()
						log.Printf("DTLS: Matched client by source IP %s (VPN IP: %s)", srcIP.String(), vpnIP)
						break
					}
				}
			}

			// 对于 keepalive 或其他控制包，如果只有一个客户端，可以尝试匹配
			if matchedClient == nil && (packetType == PacketTypeKeepalive || packetType == PacketTypeDPD) {
				if len(h.dtlsClients) == 1 {
					// 只有一个客户端，直接匹配
					for vpnIP, clientInfo := range h.dtlsClients {
						if clientInfo.Client != nil {
							matchedClient = clientInfo.Client
							matchedVPNIP = vpnIP
							clientInfo.UDPAddr = clientAddr
							clientInfo.LastSeen = time.Now()
							log.Printf("DTLS: Matched single client for control packet (VPN IP: %s)", vpnIP)
							break
						}
					}
				}
			}
		}

		// 如果仍然没有匹配，记录详细信息并跳过
		if matchedClient == nil {
			h.dtlsLock.Unlock()
			log.Printf("DTLS: No matching client found for packet from %s (type: 0x%02x, size: %d bytes)", clientAddr, packetType, n)
			log.Printf("DTLS: Available clients: %d", len(h.dtlsClients))
			for vpnIP, clientInfo := range h.dtlsClients {
				if clientInfo.Client != nil && clientInfo.Client.IP != nil {
					log.Printf("DTLS:   - VPN IP: %s, Client IP: %s, UDP Addr: %v", vpnIP, clientInfo.Client.IP.String(), clientInfo.UDPAddr)
				}
			}
			continue
		}

		// 更新客户端地址（如果还没有设置）
		if h.dtlsClients[matchedVPNIP].UDPAddr == nil {
			h.dtlsClients[matchedVPNIP].UDPAddr = clientAddr
		}

		// 复制客户端引用，避免在锁内处理
		clientToProcess := matchedClient
		h.dtlsLock.Unlock()

		// 处理数据包（在锁外处理，避免阻塞）
		go func(packetType byte, payload []byte, client *TunnelClient) {
			if err := client.processPacket(packetType, payload); err != nil {
				log.Printf("DTLS: Error processing packet: %v", err)
			}
		}(packetType, payload, clientToProcess)
	}
}

// SendDTLSPacket 通过 DTLS 通道发送数据包（使用真正的 DTLS 连接）
func (h *Handler) SendDTLSPacket(vpnIP string, packetType byte, data []byte) error {
	if !h.config.VPN.EnableDTLS {
		return fmt.Errorf("DTLS not enabled")
	}

	h.dtlsLock.RLock()
	clientInfo, exists := h.dtlsClients[vpnIP]
	h.dtlsLock.RUnlock()

	if !exists || clientInfo == nil || clientInfo.Client == nil {
		return fmt.Errorf("DTLS client not found for VPN IP: %s", vpnIP)
	}

	if clientInfo.DTLSConn == nil {
		return fmt.Errorf("DTLS connection not established for VPN IP: %s", vpnIP)
	}

	// 构建 CSTP 数据包（带 STF 前缀，与 TCP 连接保持一致）
	// STF(3) + Version(1) + Length(2) + Type(1) + Reserved(1) + Payload
	stfLen := 3
	headerLen := 5
	payloadLen := uint16(len(data))
	fullPacket := make([]byte, stfLen+headerLen+len(data))

	// STF 前缀
	fullPacket[0] = 'S'
	fullPacket[1] = 'T'
	fullPacket[2] = 'F'

	// CSTP header
	fullPacket[3] = 0x01 // Version
	binary.BigEndian.PutUint16(fullPacket[4:6], payloadLen)
	fullPacket[6] = packetType
	fullPacket[7] = 0x00 // Reserved

	// Payload
	if len(data) > 0 {
		copy(fullPacket[8:], data)
	}

	// 通过 DTLS 连接发送
	_, err := clientInfo.DTLSConn.Write(fullPacket)
	if err != nil {
		return fmt.Errorf("failed to send DTLS packet: %w", err)
	}

	return nil
}

// Index 返回初始页面或配置
// GET / 返回 HTML（用于浏览器访问）
// OpenConnect/AnyConnect 客户端使用 POST / 获取 XML 配置
func (h *Handler) Index(c *gin.Context) {
	// 检查 Connection: close 和 User-Agent
	// 如果是 anyconnect/openconnect 客户端且 Connection 是 close，拒绝连接
	connection := strings.ToLower(c.GetHeader("Connection"))
	userAgent := strings.ToLower(c.GetHeader("User-Agent"))
	if connection == "close" && (strings.Contains(userAgent, "anyconnect") || strings.Contains(userAgent, "openconnect")) {
		c.Header("Connection", "close")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// 检查 Accept 头，如果明确请求 XML，返回 XML 配置
	accept := c.GetHeader("Accept")
	isXMLRequest := strings.Contains(accept, "text/xml") ||
		strings.Contains(accept, "application/xml") ||
		strings.Contains(userAgent, "anyconnect") ||
		strings.Contains(userAgent, "openconnect") ||
		strings.Contains(userAgent, "cisco")

	// 如果请求 XML 或者是 VPN 客户端，返回 XML 配置
	if isXMLRequest {
		// 调用 GetConfig 处理（它会调用 sendAuthForm 返回 XML）
		h.GetConfig(c)
		return
	}

	// 默认返回 HTML 登录表单
	html := `<!DOCTYPE html>
<html>
<head>
    <title>ZVPN - OpenConnect</title>
</head>
<body>
    <h2>ZVPN SSL VPN Login</h2>
    <form method="POST" action="/auth">
        <label>Username: <input type="text" name="username" required /></label><br/>
        <label>Password: <input type="password" name="password" required /></label><br/>
        <input type="submit" value="Login" />
    </form>
</body>
</html>`
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

// closeConnectionGracefully properly closes a connection, handling TLS connections correctly
// For TLS connections, this ensures close_notify is sent before closing the underlying connection
func closeConnectionGracefully(conn net.Conn) {
	// Check if this is a TLS connection
	if tlsConn, ok := conn.(*tls.Conn); ok {
		// For TLS connections, we need to properly close the TLS session
		// The tls.Conn.Close() method will automatically send close_notify
		// However, we need to ensure the client has time to receive it

		// Try to read any remaining data (including close_notify from client if they sent it first)
		// Set a short deadline to avoid blocking
		tlsConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

		// Read any remaining data (this will fail quickly if there's nothing to read)
		buf := make([]byte, 1)
		tlsConn.Read(buf) // Ignore errors, we're just trying to drain the connection

		// Reset read deadline before closing
		tlsConn.SetReadDeadline(time.Time{})

		// Close the TLS connection (this will send close_notify if not already sent)
		// The Close() method on tls.Conn will properly close the TLS session
		if err := tlsConn.Close(); err != nil {
			// Ignore "use of closed network connection" errors as they're expected
			errStr := err.Error()
			if !strings.Contains(errStr, "use of closed network connection") &&
				!strings.Contains(errStr, "connection reset by peer") &&
				!strings.Contains(errStr, "broken pipe") {
				log.Printf("OpenConnect: Warning - Failed to close TLS connection: %v", err)
			}
		}
	} else {
		// For non-TLS connections, just close normally
		if err := conn.Close(); err != nil {
			// Ignore "use of closed network connection" errors as they're expected
			errStr := err.Error()
			if !strings.Contains(errStr, "use of closed network connection") &&
				!strings.Contains(errStr, "connection reset by peer") &&
				!strings.Contains(errStr, "broken pipe") {
				log.Printf("OpenConnect: Warning - Failed to close connection: %v", err)
			}
		}
	}
}

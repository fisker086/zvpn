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
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fisker/zvpn/auth"
	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/handlers"
	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/vpn"
	"github.com/fisker/zvpn/vpn/policy"
	"github.com/fisker/zvpn/vpn/security"
	"github.com/gin-gonic/gin"
)

type DTLSClientInfo struct {
	Client        *TunnelClient
	UDPAddr       *net.UDPAddr
	DTLSConn      net.Conn
	LastSeen      time.Time
	DTLSSessionID string
	IsMobile      bool // 是否为移动端客户端
}

type Handler struct {
	config               *config.Config
	vpnServer            *vpn.VPNServer
	ldapAuthenticator    *auth.LDAPAuthenticator
	tunDevice            *vpn.TUNDevice
	dtlsListener         net.Listener
	dtlsRawUDPConn       *net.UDPConn
	dtlsClients          map[string]*DTLSClientInfo
	dtlsLock             sync.RWMutex
	dtlsSessionStore     *dtlsSessionStore
	bruteforceProtection *security.BruteforceProtection
}

type ClientType string

const (
	ClientTypeOpenConnect ClientType = "openconnect"
	ClientTypeAnyConnect  ClientType = "anyconnect"
	ClientTypeCustom      ClientType = "custom"
	ClientTypeUnknown     ClientType = "unknown"
)

func detectClientType(c *gin.Context) ClientType {

	xAggregateAuth := c.Request.Header.Get("X-Aggregate-Auth")
	xTranscendVersion := c.Request.Header.Get("X-Transcend-Version")

	if xAggregateAuth == "1" && xTranscendVersion == "1" {
		return ClientTypeAnyConnect
	}

	if xAggregateAuth != "" && xTranscendVersion != "" {
		return ClientTypeAnyConnect
	}

	userAgent := strings.ToLower(c.Request.UserAgent())

	if strings.Contains(userAgent, "anyconnect") ||
		strings.Contains(userAgent, "cisco secure client") ||
		strings.Contains(userAgent, "cisco anyconnect") {
		return ClientTypeAnyConnect
	} else if strings.Contains(userAgent, "openconnect") {
		return ClientTypeOpenConnect
	}

	return ClientTypeUnknown
}

func getClientName(clientType ClientType) string {
	switch clientType {
	case ClientTypeOpenConnect:
		return "OpenConnect"
	case ClientTypeAnyConnect:
		return "AnyConnect"
	case ClientTypeCustom:
		return "Custom"
	default:
		return "Unknown"
	}
}

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

func getHeaderCaseInsensitive(c *gin.Context, names ...string) string {
	for _, name := range names {
		if value := c.GetHeader(name); value != "" {
			return value
		}
	}
	return ""
}

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

	var bruteforceProtection *security.BruteforceProtection
	if vpnServer != nil {
		if bpInterface := vpnServer.GetBruteforceProtection(); bpInterface != nil {
			if bp, ok := bpInterface.(*security.BruteforceProtection); ok {
				bruteforceProtection = bp
				log.Printf("OpenConnect: Using shared bruteforce protection instance from VPNServer")
			}
		}
	}

	if bruteforceProtection == nil && cfg.VPN.EnableBruteforceProtection {
		maxAttempts := cfg.VPN.MaxLoginAttempts
		if maxAttempts <= 0 {
			maxAttempts = 5
		}
		lockoutDuration := time.Duration(cfg.VPN.LoginLockoutDuration) * time.Second
		if lockoutDuration <= 0 {
			lockoutDuration = 15 * time.Minute
		}
		windowDuration := time.Duration(cfg.VPN.LoginAttemptWindow) * time.Second
		if windowDuration <= 0 {
			windowDuration = 5 * time.Minute
		}
		bruteforceProtection = security.NewBruteforceProtection(maxAttempts, lockoutDuration, windowDuration)

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
	}

	if vpnServer != nil {
		if tunDevice := vpnServer.GetTUNDevice(); tunDevice != nil {
			handler.tunDevice = tunDevice
		} else {
			log.Printf("OpenConnect: Warning - No TUN device available from VPNServer")
		}
	}

	return handler
}

func (h *Handler) AuthMiddleware(c *gin.Context) {

	if c.Request.URL.Path == "/" || c.Request.URL.Path == "/auth" ||
		c.Request.URL.Path == "/profile.xml" {
		c.Next()
		return
	}

	if c.GetBool("authenticated") {
		c.Next()
		return
	}

	sessionCookie, cookieErr := c.Cookie("webvpn")
	if cookieErr != nil || sessionCookie == "" {
		log.Printf("OpenConnect: AuthMiddleware - No webvpn cookie found (Path: %s, Error: %v, All cookies: %v)",
			c.Request.URL.Path, cookieErr, c.Request.Cookies())
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	log.Printf("OpenConnect: AuthMiddleware - Found webvpn cookie: %s (Path: %s, Cookie length: %d)",
		sessionCookie, c.Request.URL.Path, len(sessionCookie))
	log.Printf("OpenConnect: AuthMiddleware - All cookies: %v", c.Request.Cookies())

	var user models.User
	var userID uint
	foundByToken := false

	if len(sessionCookie) == 32 {

		sessionCookieUpper := strings.ToUpper(sessionCookie)
		if _, err := hex.DecodeString(sessionCookieUpper); err == nil {

			var session models.Session
			if err := database.DB.Where("token = ? AND active = ? AND expires_at > ?",
				sessionCookieUpper, true, time.Now()).First(&session).Error; err != nil {
				log.Printf("OpenConnect: AuthMiddleware - Session not found or expired (token: %s...): %v", sessionCookieUpper[:16], err)

				foundByToken = false
			} else {

				userID = session.UserID
				foundByToken = true
				log.Printf("OpenConnect: AuthMiddleware - Token validated successfully (token: %s..., userID: %d)", sessionCookieUpper[:16], userID)
			}
		}
	}

	if !foundByToken {

		parts := strings.Split(sessionCookie, "-")
		var parseErr error

		if len(parts) == 3 {

			var uid int
			uid, parseErr = strconv.Atoi(parts[2])
			if parseErr != nil {
				log.Printf("OpenConnect: AuthMiddleware - Failed to parse userID from cookie: %s, error: %v", sessionCookie, parseErr)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			userID = uint(uid)
			log.Printf("OpenConnect: AuthMiddleware - Using legacy cookie format (webvpn-username-userID): %s", sessionCookie)
		} else if len(parts) == 2 {

			var uid int
			uid, parseErr = strconv.Atoi(parts[1])
			if parseErr != nil {
				log.Printf("OpenConnect: AuthMiddleware - Failed to parse userID from legacy cookie: %s, error: %v", sessionCookie, parseErr)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			userID = uint(uid)
			log.Printf("OpenConnect: AuthMiddleware - Using legacy cookie format (username-userID): %s", sessionCookie)
		} else {
			log.Printf("OpenConnect: AuthMiddleware - Invalid cookie format: %s (expected token or webvpn-username-userID or username-userID, got %d parts)",
				sessionCookie, len(parts))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	}

	if err := database.DB.First(&user, userID).Error; err != nil {
		log.Printf("OpenConnect: AuthMiddleware - User not found (userID: %d): %v", userID, err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if !user.IsActive {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	c.Set("authenticated", true)
	c.Set("userID", userID)
	c.Set("username", user.Username)
	c.Set("vpnIP", user.VPNIP)

	c.Next()
}

func (h *Handler) SetupRoutes(router *gin.Engine) {

	router.Use(h.AuthMiddleware)

	router.Handle("CONNECT", "/CSCOSSLC/tunnel", h.handleConnect)

	router.GET("/", h.Index)
	router.POST("/", h.GetConfig)
	router.POST("/auth", h.Authenticate)
	router.GET("/profile.xml", h.GetProfile)

	tunnelGroup := router.Group("/CSCOSSLC")
	tunnelGroup.Use(h.ConnectMiddleware)
	tunnelGroup.GET("/tunnel", h.TunnelHandler)
	tunnelGroup.POST("/tunnel", h.TunnelHandler)
}

func (h *Handler) handleConnect(c *gin.Context) {

	if !c.GetBool("authenticated") {
		log.Printf("OpenConnect: Unauthenticated CONNECT request from %s (Path: %s)", c.ClientIP(), c.Request.URL.Path)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		log.Printf("OpenConnect: Cannot get userID from context")
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	var user models.User
	if err := database.DB.Preload("Groups.Policies.Routes").Preload("Groups.Policies.ExcludeRoutes").First(&user, userID).Error; err != nil {
		log.Printf("OpenConnect: Failed to get user info: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	if h.vpnServer == nil {
		log.Printf("OpenConnect: VPN server not initialized for user %s", user.Username)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

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

	if ip := net.ParseIP(user.VPNIP); ip != nil {
		h.vpnServer.ReserveVPNIP(ip)
	}

	clientType := detectClientType(c)
	clientName := getClientName(clientType)
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

	if c.Request.Body != nil {
		c.Request.Body.Close()
	}

	if policy := user.GetPolicy(); policy != nil {
		user.PolicyID = policy.ID
		user.Policy = *policy
	} else {
		user.PolicyID = 0
		user.Policy = models.Policy{}
	}

	userDNSServers := getDNSServers(user.GetPolicy())

	dnsMap := make(map[string]bool)
	var dnsServers []string

	for _, dns := range userDNSServers {
		if dns != "" {
			dns = strings.TrimSpace(dns)
			if dns != "" && !dnsMap[dns] {
				dnsMap[dns] = true
				dnsServers = append(dnsServers, dns)
			}
		}
	}

	tunnelMode := getUserTunnelMode(&user)
	if len(dnsServers) == 0 {
		log.Printf("OpenConnect: No DNS configured for user %s (tunnel mode: %s), DNS will use local/system default", user.Username, tunnelMode)
	}

	clientCipherSuite := getHeaderCaseInsensitive(c, "X-Dtls12-Ciphersuite", "X-DTLS12-CipherSuite", "X-Dtls-Ciphersuite", "X-DTLS-CipherSuite")
	if clientCipherSuite == "PSK-NEGOTIATE" {
		clientCipherSuite = ""
	}

	clientMasterSecret := getHeaderCaseInsensitive(c, "X-Dtls-Master-Secret", "X-DTLS-Master-Secret")

	if err := h.sendCSTPConfig(conn, &user, dnsServers, clientCipherSuite, clientMasterSecret, clientType, c); err != nil {
		log.Printf("OpenConnect: Failed to send CSTP config: %v", err)
		conn.Close()
		return
	}

	user.Connected = true
	now := time.Now()
	user.LastSeen = &now
	if err := database.DB.Model(&user).Select("connected", "last_seen").Updates(map[string]interface{}{
		"connected": user.Connected,
		"last_seen": user.LastSeen,
	}).Error; err != nil {
		log.Printf("OpenConnect: Failed to update user connection status: %v", err)
	}

	auditLogger := policy.GetAuditLogger()
	if auditLogger != nil {
		clientIP := c.ClientIP()
		auditLogger.LogAuthWithIP(user.ID, user.Username, models.AuditLogActionConnect, "success",
			fmt.Sprintf("VPN connection established. VPN IP: %s", user.VPNIP), clientIP, 0)
	}

	vpnIP := net.ParseIP(user.VPNIP)
	if vpnIP == nil {
		log.Printf("OpenConnect: Invalid VPN IP: %s", user.VPNIP)
		conn.Close()
		return
	}

	tunDevice := h.vpnServer.GetTUNDevice()
	if tunDevice == nil {
		log.Printf("OpenConnect: TUN device not available")
		conn.Close()
		return
	}

	if err := h.vpnServer.CreatePolicyHooks(&user); err != nil {
		log.Printf("OpenConnect: Warning - Failed to create policy hooks: %v", err)
	}

	userAgent := c.Request.UserAgent()
	clientOS, clientVer := parseClientInfo(userAgent)
	tunnelClient := NewTunnelClient(&user, conn, vpnIP, h.vpnServer, tunDevice)

	mobileLicense := getHeaderCaseInsensitive(c, "X-Cstp-License", "X-CSTP-License")
	userAgentLower := strings.ToLower(userAgent)
	isMobile := mobileLicense == "mobile" ||
		strings.Contains(userAgentLower, "android") ||
		strings.Contains(userAgentLower, "iphone") ||
		strings.Contains(userAgentLower, "ipad") ||
		strings.Contains(userAgentLower, "ios")

	if h.config.VPN.EnableDTLS {
		h.dtlsLock.Lock()
		h.dtlsClients[user.VPNIP] = &DTLSClientInfo{
			Client:   tunnelClient,
			UDPAddr:  nil,
			DTLSConn: nil,
			LastSeen: time.Now(),
			IsMobile: isMobile, // 保存移动端标识
		}
		h.dtlsLock.Unlock()
	}

	bufferSize := 100
	if cfg := h.vpnServer.GetConfig(); cfg != nil {
		if cfg.VPN.WriteChanBufferSize > 0 {
			bufferSize = cfg.VPN.WriteChanBufferSize
		}
	}

	vpnClient := &vpn.VPNClient{
		UserID:     user.ID,
		User:       &user,
		Conn:       conn,
		IP:         vpnIP,
		UserAgent:  userAgent,
		ClientOS:   clientOS,
		ClientVer:  clientVer,
		Connected:  true,
		WriteChan:  make(chan []byte, bufferSize),
		WriteClose: make(chan struct{}),
	}
	h.vpnServer.RegisterClient(user.ID, vpnClient)

	go vpnClient.WriteLoop()

	go func() {

		time.Sleep(10 * time.Millisecond)

		dpdRespPayload := []byte{}

		for i := 0; i < 2; i++ {
			if err := tunnelClient.sendPacket(PacketTypeDPDResp, dpdRespPayload); err != nil {
				log.Printf("OpenConnect: 通过TCP通道发送DPD响应 #%d失败: %v", i+1, err)
				break
			}

			if i < 1 {
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()

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
		log.Printf("OpenConnect: HandleTunnelData error for user %s: %v", user.Username, err)
	}

	tunnelMode = getUserTunnelMode(&user)
	log.Printf("OpenConnect: Tunnel closed for user %s (VPN IP: %s, Tunnel Mode: %s)",
		user.Username, user.VPNIP, tunnelMode)

	client, exists := h.vpnServer.GetClient(user.ID)
	disconnectSent := false
	if exists && client != nil {

		disconnectPacket := tunnelClient.BuildCSTPPacket(PacketTypeDisconnect, nil)

		select {
		case client.WriteChan <- disconnectPacket:
			disconnectSent = true
			if tunnelMode == "full" {
				time.Sleep(2700 * time.Millisecond)
			} else {
				time.Sleep(300 * time.Millisecond)
			}
		default:

			if conn != nil {
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					tcpConn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
					if err := tunnelClient.sendPacket(PacketTypeDisconnect, nil); err != nil {
						log.Printf("OpenConnect: Failed to send DISCONNECT packet directly: %v", err)
					} else {
						disconnectSent = true
						if tunnelMode == "full" {

							time.Sleep(2500 * time.Millisecond)
						} else {
							time.Sleep(200 * time.Millisecond)
						}
					}
					tcpConn.SetWriteDeadline(time.Time{})
				} else {
					if err := tunnelClient.sendPacket(PacketTypeDisconnect, nil); err != nil {
						log.Printf("OpenConnect: Failed to send DISCONNECT packet: %v", err)
					} else {
						disconnectSent = true
						if tunnelMode == "full" {

							time.Sleep(2500 * time.Millisecond)
						} else {
							time.Sleep(200 * time.Millisecond)
						}
					}
				}
			}
		}
	} else {
		log.Printf("OpenConnect: Cannot send DISCONNECT packet - client not available")
	}

	if disconnectSent && tunnelMode == "full" {
		time.Sleep(1000 * time.Millisecond)
	}

	if tunnelMode == "full" && !disconnectSent {
		log.Printf("OpenConnect: WARNING - Failed to send DISCONNECT packet to client %s (full tunnel mode)", user.Username)
	}

	if exists && client != nil {

		select {
		case <-client.WriteClose:

		default:

			if disconnectSent {
				if tunnelMode == "full" {
					time.Sleep(500 * time.Millisecond)
				} else {
					time.Sleep(100 * time.Millisecond)
				}
			}
			close(client.WriteClose)

			time.Sleep(50 * time.Millisecond)
		}

		if conn != nil {
			closeConnectionGracefully(conn)
		}
	} else if conn != nil {

		closeConnectionGracefully(conn)
	}

	if err := h.vpnServer.RemovePolicyHooks(user.ID); err != nil {
		log.Printf("OpenConnect: Warning - Failed to remove policy hooks: %v", err)
	}

	h.vpnServer.UnregisterClient(user.ID, user.VPNIP)

	if h.config.VPN.EnableDTLS {
		h.dtlsLock.Lock()
		clientInfo, exists := h.dtlsClients[user.VPNIP]
		if exists && clientInfo != nil {

			if clientInfo.DTLSConn != nil {
				log.Printf("OpenConnect: Closing DTLS connection for user %s (VPN IP: %s)", user.Username, user.VPNIP)

				if err := clientInfo.DTLSConn.Close(); err != nil {

					errStr := err.Error()
					if !strings.Contains(errStr, "use of closed network connection") &&
						!strings.Contains(errStr, "connection reset by peer") &&
						!strings.Contains(errStr, "broken pipe") {
						log.Printf("OpenConnect: Warning - Failed to close DTLS connection: %v", err)
					}
				}

				clientInfo.DTLSConn = nil
			}

			if client, exists := h.vpnServer.GetClient(user.ID); exists && client != nil {
				client.DTLSConn = nil
			}
		}
		delete(h.dtlsClients, user.VPNIP)
		h.dtlsLock.Unlock()
		log.Printf("OpenConnect: Unregistered DTLS client for user %s (VPN IP: %s)", user.Username, user.VPNIP)
	}

	if h.vpnServer != nil && user.VPNIP != "" {
		if ip := net.ParseIP(user.VPNIP); ip != nil {
			h.vpnServer.ReleaseVPNIP(ip)
		}
	}
	user.Connected = false
	user.VPNIP = ""
	if err := database.DB.Model(&user).Select("connected", "vpn_ip").Updates(map[string]interface{}{
		"connected": false,
		"vpn_ip":    "",
	}).Error; err != nil {
		log.Printf("OpenConnect: Failed to update user status on disconnect: %v", err)
	}

	auditLogger2 := policy.GetAuditLogger()
	if auditLogger2 != nil {
		auditLogger2.LogAuthWithIP(user.ID, user.Username, models.AuditLogActionDisconnect, "success",
			fmt.Sprintf("VPN connection closed. VPN IP: %s", user.VPNIP), user.VPNIP, 0)
	}

}

func (h *Handler) sendCSTPConfig(conn net.Conn, user *models.User, dnsServers []string, clientCipherSuite string, clientMasterSecret string, clientType ClientType, c *gin.Context) error {

	_, ipNet, err := net.ParseCIDR(h.config.VPN.Network)
	if err != nil {
		return err
	}

	netmask := net.IP(ipNet.Mask).String()

	tunnelMode := getUserTunnelMode(user)


	response := "HTTP/1.1 200 OK\r\n"
	response += "Content-Type: application/octet-stream\r\n"

	response += "Connection: keep-alive\r\n"

	hostname := handlers.GetVPNProfileName()
	if hostname == "" {
		hostname = "zvpn"
	}

	cstpAcceptEncoding := getHeaderCaseInsensitive(c, "X-Cstp-Accept-Encoding", "X-CSTP-Accept-Encoding")
	dtlsAcceptEncoding := getHeaderCaseInsensitive(c, "X-Dtls-Accept-Encoding", "X-DTLS-Accept-Encoding")

	response += "Server: ZVPN 1.0\r\n"
	response += "X-CSTP-Version: 1\r\n"
	response += "X-CSTP-Server-Name: ZVPN 1.0\r\n"
	response += "X-CSTP-Protocol: Copyright (c) 2004 Cisco Systems, Inc.\r\n"
	response += "X-CSTP-Address: " + user.VPNIP + "\r\n"
	response += "X-CSTP-Netmask: " + netmask + "\r\n"
	response += "X-CSTP-Hostname: " + hostname + "\r\n"

	response += "X-CSTP-Base-MTU: " + strconv.Itoa(h.config.VPN.MTU) + "\r\n"


	if h.config.VPN.EnableCompression && cstpAcceptEncoding != "" {
		compressionType := getCompressionType(h.config)
		if compressionType != "none" {
			if strings.Contains(strings.ToLower(cstpAcceptEncoding), strings.ToLower(compressionType)) {
				response += "X-CSTP-Content-Encoding: " + compressionType + "\r\n"
			}
		}
	}
	if h.config.VPN.EnableCompression && dtlsAcceptEncoding != "" {
		compressionType := getCompressionType(h.config)
		if compressionType != "none" {
			if strings.Contains(strings.ToLower(dtlsAcceptEncoding), strings.ToLower(compressionType)) {
				response += "X-DTLS-Content-Encoding: " + compressionType + "\r\n"
			}
		}
	}

	mobileLicense := getHeaderCaseInsensitive(c, "X-Cstp-License", "X-CSTP-License")
	userAgent := strings.ToLower(c.GetHeader("User-Agent"))
	isMobile := mobileLicense == "mobile" ||
		strings.Contains(userAgent, "android") ||
		strings.Contains(userAgent, "iphone") ||
		strings.Contains(userAgent, "ipad") ||
		strings.Contains(userAgent, "ios")

	var cstpDPD, cstpKeepalive int
	if isMobile {
		cstpDPD = h.config.VPN.MobileDPD
		cstpKeepalive = h.config.VPN.MobileKeepalive
		if cstpDPD == 0 {
			cstpDPD = 60
		}
		if cstpKeepalive == 0 {
			cstpKeepalive = 4
		}
	} else {
		cstpDPD = h.config.VPN.CSTPDPD
		cstpKeepalive = h.config.VPN.CSTPKeepalive
		if cstpDPD == 0 {
			cstpDPD = 30
		}
		if cstpKeepalive == 0 {
			cstpKeepalive = 20
		}
	}

	var dtlsSessionID string
	var dtlsPort string
	var dtlsDPDStr, dtlsKeepaliveStr string
	var cipherSuiteHeader string
	if h.config.VPN.EnableDTLS {
		sessionIDBytes := make([]byte, 32)
		if _, err := rand.Read(sessionIDBytes); err != nil {
			log.Printf("OpenConnect: Warning - Failed to generate DTLS session ID: %v", err)
			sessionIDBytes = make([]byte, 32)
		}
		dtlsSessionID = hex.EncodeToString(sessionIDBytes)

		dtlsPort = h.config.VPN.OpenConnectPort
		if h.config.VPN.DTLSPort != "" && h.config.VPN.DTLSPort != h.config.VPN.OpenConnectPort {
			dtlsPort = h.config.VPN.DTLSPort
		}

		dtlsDPDStr = strconv.Itoa(cstpDPD)
		dtlsKeepaliveStr = strconv.Itoa(cstpKeepalive)

		cipherSuiteHeader = checkDtls12Ciphersuite(clientCipherSuite)

		if clientMasterSecret != "" && h.dtlsSessionStore != nil {
			if err := h.dtlsSessionStore.StoreMasterSecret(dtlsSessionID, clientMasterSecret); err != nil {
				log.Printf("OpenConnect: Failed to store master secret: %v", err)
			}
		}
	}

	var splitIncludeRoutes []string
	var splitExcludeRoutes []string
	routeMap := make(map[string]bool)        // 用于去重 split-include 路由
	excludeRouteMap := make(map[string]bool) // 用于去重 split-exclude 路由

	if tunnelMode != "full" && len(dnsServers) > 0 {
		for _, dns := range dnsServers {
			if dns == "" {
				continue
			}
			dns = strings.TrimSpace(dns)
			dnsIP := net.ParseIP(dns)
			if dnsIP == nil {
				continue
			}

			if isPrivateIP(dnsIP) {
				dnsNetwork := getDNSServerNetwork(dnsIP)
				if dnsNetwork != "" {
					if dnsNetwork == h.config.VPN.Network {
						continue
					}
					if !routeMap[dnsNetwork] {
						routeMap[dnsNetwork] = true
						splitIncludeRoutes = append(splitIncludeRoutes, dnsNetwork)
					}
				}
			}
		}
	}

	if user.PolicyID != 0 && len(user.Policy.Routes) > 0 {
		for _, route := range user.Policy.Routes {
			if route.Network == "" {
				continue
			}

			normalizedRoute, _, err := parseRouteNetwork(route.Network)
			if err != nil {
				log.Printf("OpenConnect: WARNING - Invalid route format '%s' for user %s: %v (skipping)", route.Network, user.Username, err)
				continue
			}

			if normalizedRoute == h.config.VPN.Network {
				continue
			}

			if normalizedRoute == "0.0.0.0/0" {
				log.Printf("OpenConnect: WARNING - Default route (0.0.0.0/0) is not allowed in split mode for user %s (skipping)", user.Username)
				continue
			}

			if !routeMap[normalizedRoute] {
				routeMap[normalizedRoute] = true
				splitIncludeRoutes = append(splitIncludeRoutes, normalizedRoute)
			}
		}
	}

	if tunnelMode == "full" {
		userPolicy := user.GetPolicy()
		if userPolicy != nil && len(userPolicy.ExcludeRoutes) > 0 {
			for _, excludeRoute := range userPolicy.ExcludeRoutes {
				if excludeRoute.Network == "" {
					continue
				}

				normalizedRoute, _, err := parseRouteNetwork(excludeRoute.Network)
				if err != nil {
					log.Printf("OpenConnect: Invalid exclude route '%s' for user %s: %v (skipping)", excludeRoute.Network, user.Username, err)
					continue
				}

				if excludeRoute.Network == "0.0.0.0/255.255.255.255" {
					if !excludeRouteMap[excludeRoute.Network] {
						excludeRouteMap[excludeRoute.Network] = true
						splitExcludeRoutes = append(splitExcludeRoutes, excludeRoute.Network)
						log.Printf("OpenConnect: Added exclude route '%s' (allow_lan format) for user %s in full tunnel mode", excludeRoute.Network, user.Username)
					}
				} else {
					if !excludeRouteMap[normalizedRoute] {
						excludeRouteMap[normalizedRoute] = true
						splitExcludeRoutes = append(splitExcludeRoutes, normalizedRoute)
						log.Printf("OpenConnect: Added exclude route '%s' (normalized from '%s') for user %s in full tunnel mode", normalizedRoute, excludeRoute.Network, user.Username)
					}
				}
			}
		}
	}

	allowLan := false
	for _, group := range user.Groups {
		if group.AllowLan {
			allowLan = true
			break
		}
	}

	if allowLan {
		allowLanRoute := "0.0.0.0/255.255.255.255"
		if !excludeRouteMap[allowLanRoute] {
			excludeRouteMap[allowLanRoute] = true
			splitExcludeRoutes = append([]string{allowLanRoute}, splitExcludeRoutes...)
			log.Printf("OpenConnect: Auto-added allow_lan route (0.0.0.0/255.255.255.255) for user %s (group allow_lan enabled)", user.Username)
		} else {
			log.Printf("OpenConnect: allow_lan route (0.0.0.0/255.255.255.255) already configured in policy for user %s", user.Username)
			var filteredRoutes []string
			for _, route := range splitExcludeRoutes {
				if route != allowLanRoute {
					filteredRoutes = append(filteredRoutes, route)
				}
			}
			splitExcludeRoutes = append([]string{allowLanRoute}, filteredRoutes...)
		}
	}

	hasDNS := false
	for _, dns := range dnsServers {
		if dns != "" {
			dns = strings.TrimSpace(dns)

			if ip := net.ParseIP(dns); ip != nil {
				response += "X-CSTP-DNS: " + dns + "\r\n"
				hasDNS = true
			} else {
				log.Printf("OpenConnect: WARNING - Invalid DNS format '%s', skipping", dns)
			}
		}
	}

	if !hasDNS {
		defaultDNS := "114.114.114.114"
		response += "X-CSTP-DNS: " + defaultDNS + "\r\n"
		log.Printf("OpenConnect: Added default DNS (%s) for user %s in %s tunnel mode (no DNS configured)", defaultDNS, user.Username, tunnelMode)
		hasDNS = true
	}

	defaultSplitDNS := "ZVPN.local"
	splitDNSDomains := []string{}

	userPolicy := user.GetPolicy()
	if userPolicy != nil {
		log.Printf("OpenConnect: Checking Split-DNS for user %s, policy SplitDNS field: '%s'", user.Username, userPolicy.SplitDNS)
		splitDNSDomains = getSplitDNSDomains(userPolicy)
		log.Printf("OpenConnect: Parsed %d Split-DNS domains for user %s: %v", len(splitDNSDomains), user.Username, splitDNSDomains)
	} else {
		log.Printf("OpenConnect: No policy found for user %s, will use default Split-DNS", user.Username)
	}

	if len(splitDNSDomains) == 0 {
		splitDNSDomains = []string{defaultSplitDNS}
		log.Printf("OpenConnect: Using default Split-DNS domain '%s' for user %s", defaultSplitDNS, user.Username)
	}

	for _, domain := range splitDNSDomains {
		domain = strings.TrimSpace(domain)
		if domain != "" {
			response += "X-CSTP-Split-DNS: " + domain + "\r\n"
			log.Printf("OpenConnect: Added Split-DNS domain '%s' for user %s", domain, user.Username)
		}
	}
	log.Printf("OpenConnect: Added %d Split-DNS domains for user %s", len(splitDNSDomains), user.Username)

	if tunnelMode != "full" {
		if len(splitIncludeRoutes) > 0 {
			optimizedRoutes := optimizeRoutes(splitIncludeRoutes)
			for _, route := range optimizedRoutes {
				routeFormatted := convertCIDRToSubnetMask(route)
				response += "X-CSTP-Split-Include: " + routeFormatted + "\r\n"
			}
		}

		if !allowLan && len(splitExcludeRoutes) > 0 {
			log.Printf("OpenConnect: WARNING - ExcludeRoutes found in split tunnel mode for user %s, ignoring (split-include and split-exclude cannot be sent together for mobile clients)", user.Username)
		}
	}

	if tunnelMode == "full" {
		if len(splitExcludeRoutes) > 0 {
			optimizedExcludeRoutes := optimizeRoutes(splitExcludeRoutes)
			for _, route := range optimizedExcludeRoutes {
				routeFormatted := convertCIDRToSubnetMask(route)
				response += "X-CSTP-Split-Exclude: " + routeFormatted + "\r\n"
			}
		}
		if len(splitIncludeRoutes) > 0 {
			log.Printf("OpenConnect: WARNING - Routes found in full tunnel mode for user %s, ignoring (split-include and split-exclude cannot be sent together)", user.Username)
		}
	}

	response += "X-CSTP-Lease-Duration: 1209600\r\n"
	response += "X-CSTP-Session-Timeout: none\r\n"
	response += "X-CSTP-Session-Timeout-Alert-Interval: 60\r\n"
	response += "X-CSTP-Session-Timeout-Remaining: none\r\n"
	response += "X-CSTP-Idle-Timeout: 18000\r\n"
	response += "X-CSTP-Disconnected-Timeout: 18000\r\n"
	response += "X-CSTP-Keep: true\r\n"

	response += "X-CSTP-Tunnel-All-DNS: false\r\n"

	response += "X-CSTP-Rekey-Time: 86400\r\n"
	response += "X-CSTP-Rekey-Method: new-tunnel\r\n"
	if h.config.VPN.EnableDTLS {
		response += "X-DTLS-Rekey-Time: 86400\r\n"
		response += "X-DTLS-Rekey-Method: new-tunnel\r\n"
	}

	response += fmt.Sprintf("X-CSTP-DPD: %d\r\n", cstpDPD)
	response += fmt.Sprintf("X-CSTP-Keepalive: %d\r\n", cstpKeepalive)

	response += "X-CSTP-MSIE-Proxy-Lockdown: true\r\n"
	response += "X-CSTP-Smartcard-Removal-Disconnect: true\r\n"

	response += "X-CSTP-MTU: " + strconv.Itoa(h.config.VPN.MTU) + "\r\n"
	if h.config.VPN.EnableDTLS {
		response += "X-DTLS-MTU: " + strconv.Itoa(h.config.VPN.MTU) + "\r\n"
	}

	if h.config.VPN.EnableDTLS {
		response += "X-DTLS-Session-ID: " + dtlsSessionID + "\r\n"
		response += "X-DTLS-Port: " + dtlsPort + "\r\n"
		response += "X-DTLS-DPD: " + dtlsDPDStr + "\r\n"
		response += "X-DTLS-Keepalive: " + dtlsKeepaliveStr + "\r\n"
		response += "X-DTLS12-CipherSuite: " + cipherSuiteHeader + "\r\n"
	}

	response += "X-CSTP-License: accept\r\n"

	response += "X-CSTP-Routing-Filtering-Ignore: false\r\n"
	response += "X-CSTP-Quarantine: false\r\n"
	response += "X-CSTP-Disable-Always-On-VPN: false\r\n"
	response += "X-CSTP-Client-Bypass-Protocol: true\r\n"
	response += "X-CSTP-TCP-Keepalive: false\r\n"

	response += "X-Cisco-Client-Compat: 1\r\n"
	response += "\r\n"

	log.Printf("OpenConnect: ========== CSTP Config XML for user %s (VPN IP: %s) ==========", user.Username, user.VPNIP)
	log.Printf("OpenConnect: %s", response)
	log.Printf("OpenConnect: ========== End of CSTP Config XML ==========")

	if _, err = conn.Write([]byte(response)); err != nil {
		log.Printf("OpenConnect: ERROR - Failed to write CSTP config to connection: %v", err)
		return fmt.Errorf("failed to write CSTP config: %w", err)
	}

	log.Printf("OpenConnect: CSTP config sent successfully for user %s (IP: %s, MTU: %d)", user.Username, user.VPNIP, h.config.VPN.MTU)
	return nil
}

func (h *Handler) ConnectMiddleware(c *gin.Context) {

	if !c.GetBool("authenticated") {
		log.Printf("OpenConnect: Unauthenticated connection attempt")
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	userID, exists := c.Get("userID")
	if !exists {
		log.Printf("OpenConnect: Cannot get userID")
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	var user models.User
	if err := database.DB.Preload("Groups.Policies.Routes").Preload("Groups.Policies.ExcludeRoutes").First(&user, userID).Error; err != nil {
		log.Printf("OpenConnect: Failed to get user info: %v", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.Set("user", user)

	c.Next()
}

func (h *Handler) TunnelHandler(c *gin.Context) {

	log.Printf("OpenConnect: Non-CONNECT tunnel request: %s %s", c.Request.Method, c.Request.URL.Path)
	c.AbortWithStatus(http.StatusMethodNotAllowed)
}

func (h *Handler) StartDTLSServer() error {
	return h.startRealDTLSServer()
}

func (h *Handler) handleDTLSPackets(conn *net.UDPConn) {
	buf := make([]byte, 65535)
	log.Printf("DTLS: Packet handler started, waiting for UDP packets...")

	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("DTLS: Error reading UDP packet: %v", err)

			if strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("DTLS: UDP connection closed, exiting handler")
				return
			}
			continue
		}

		hexLen := n
		if hexLen > 32 {
			hexLen = 32
		}
		log.Printf("DTLS: Received %d bytes from %s (hex: %x)", n, clientAddr, buf[:hexLen])

		var packetType byte
		var payload []byte
		var length uint16

		if n < 5 {
			log.Printf("DTLS: Packet too short: %d bytes, ignoring", n)
			continue
		}

		if n >= 13 && buf[0] == 0x17 {

			log.Printf("DTLS: DTLS application data packet (ContentType=0x17)")

			dtlsData := buf[13:n]

			if len(dtlsData) < 5 {
				log.Printf("DTLS: CSTP data too short after DTLS header: %d bytes", len(dtlsData))
				continue
			}

			if len(dtlsData) >= 8 && dtlsData[0] == 'S' && dtlsData[1] == 'T' && dtlsData[2] == 'F' {

				packetType = dtlsData[6]
				length = binary.BigEndian.Uint16(dtlsData[4:6])
				if int(length)+8 > len(dtlsData) {
					log.Printf("DTLS: Invalid packet length with STF: declared=%d, actual=%d", int(length)+8, len(dtlsData))
					continue
				}
				payload = dtlsData[8:]
				log.Printf("DTLS: CSTP packet with STF prefix, type=0x%02x, length=%d", packetType, length)
			} else {

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

			if n >= 2 {
				contentType := buf[0]
				log.Printf("DTLS: Non-application DTLS packet (ContentType=0x%02x), length=%d - skipping", contentType, n)
			} else {
				log.Printf("DTLS: Unknown packet format, length=%d - skipping", n)
			}
			continue
		}

		h.dtlsLock.Lock()
		var matchedClient *TunnelClient
		var matchedVPNIP string

		for vpnIP, clientInfo := range h.dtlsClients {
			if clientInfo.UDPAddr != nil && clientInfo.UDPAddr.IP.Equal(clientAddr.IP) && clientInfo.UDPAddr.Port == clientAddr.Port {
				matchedClient = clientInfo.Client
				matchedVPNIP = vpnIP
				clientInfo.LastSeen = time.Now()
				break
			}
		}

		if matchedClient == nil {

			if packetType == PacketTypeData && len(payload) >= 20 {

				srcIP := net.IP(payload[12:16])
				for vpnIP, clientInfo := range h.dtlsClients {
					if clientInfo.Client != nil && clientInfo.Client.IP != nil && srcIP.Equal(clientInfo.Client.IP) {
						matchedClient = clientInfo.Client
						matchedVPNIP = vpnIP

						clientInfo.UDPAddr = clientAddr
						clientInfo.LastSeen = time.Now()
						log.Printf("DTLS: Matched client by source IP %s (VPN IP: %s)", srcIP.String(), vpnIP)
						break
					}
				}
			}

			if matchedClient == nil && (packetType == PacketTypeKeepalive || packetType == PacketTypeDPD) {
				if len(h.dtlsClients) == 1 {

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

		if h.dtlsClients[matchedVPNIP].UDPAddr == nil {
			h.dtlsClients[matchedVPNIP].UDPAddr = clientAddr
		}

		clientToProcess := matchedClient
		h.dtlsLock.Unlock()

		go func(packetType byte, payload []byte, client *TunnelClient) {
			if err := client.processPacket(packetType, payload); err != nil {
				log.Printf("DTLS: Error processing packet: %v", err)
			}
		}(packetType, payload, clientToProcess)
	}
}

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

	_, err := clientInfo.DTLSConn.Write(fullPacket)
	if err != nil {
		return fmt.Errorf("failed to send DTLS packet: %w", err)
	}

	return nil
}

func (h *Handler) Index(c *gin.Context) {
	c.String(http.StatusOK, "Welcome to ZVPN OpenConnect Server")
}

func closeConnectionGracefully(conn net.Conn) {

	if tlsConn, ok := conn.(*tls.Conn); ok {

		tlsConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

		buf := make([]byte, 1)
		tlsConn.Read(buf)

		tlsConn.SetReadDeadline(time.Time{})

		if err := tlsConn.Close(); err != nil {

			errStr := err.Error()
			if !strings.Contains(errStr, "use of closed network connection") &&
				!strings.Contains(errStr, "connection reset by peer") &&
				!strings.Contains(errStr, "broken pipe") {
				log.Printf("OpenConnect: Warning - Failed to close TLS connection: %v", err)
			}
		}
	} else {

		if err := conn.Close(); err != nil {

			errStr := err.Error()
			if !strings.Contains(errStr, "use of closed network connection") &&
				!strings.Contains(errStr, "connection reset by peer") &&
				!strings.Contains(errStr, "broken pipe") {
				log.Printf("OpenConnect: Warning - Failed to close connection: %v", err)
			}
		}
	}
}


package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/vpn"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	// DB-first defaults for compression; config.yaml/env are ignored for these fields.
	defaultEnableCompression = false
	defaultCompressionType   = "lz4"
)

type VPNHandler struct {
	config    *config.Config
	vpnServer *vpn.VPNServer
}

func NewVPNHandler(cfg *config.Config) *VPNHandler {
	h := &VPNHandler{config: cfg}
	// Reset compression to code defaults (config.yaml/env ignored for these fields)
	h.config.VPN.EnableCompression = defaultEnableCompression
	h.config.VPN.CompressionType = defaultCompressionType
	h.loadCompressionFromDB()
	return h
}

// SetVPNServer sets the VPN server instance
func (h *VPNHandler) SetVPNServer(server *vpn.VPNServer) {
	h.vpnServer = server
	// apply persisted compression config to runtime
	h.applyCompressionToRuntime()
}

// ConnectRequest represents a VPN connection request
type ConnectRequest struct {
	Token string `json:"token" binding:"required"` // JWT token for authentication
}

// ConnectResponse represents the VPN connection response
type ConnectResponse struct {
	Success      bool       `json:"success"`
	Message      string     `json:"message"`
	ConnectionID string     `json:"connection_id,omitempty"`
	Config       *VPNConfig `json:"config,omitempty"`
}

// VPNConfig contains client configuration
type VPNConfig struct {
	VPNIP      string   `json:"vpn_ip"`      // Assigned VPN IP (e.g., 10.8.0.2)
	VPNNetwork string   `json:"vpn_network"` // VPN network (e.g., 10.8.0.0/24)
	Gateway    string   `json:"gateway"`     // VPN gateway (e.g., 10.8.0.1)
	ServerIP   string   `json:"server_ip"`   // VPN server IP
	ServerPort int      `json:"server_port"` // VPN server port
	Routes     []string `json:"routes"`      // Routes to access via VPN
	MTU        int      `json:"mtu"`         // MTU size
}

// ConnectionStatus represents VPN connection status
type ConnectionStatus struct {
	Connected   bool       `json:"connected"`
	VPNIP       string     `json:"vpn_ip,omitempty"`
	ConnectedAt time.Time  `json:"connected_at,omitempty"`
	Config      *VPNConfig `json:"config,omitempty"`
}

// Connect handles VPN connection request
func (h *VPNHandler) Connect(c *gin.Context) {
	// Get user from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Get user from database
	var user models.User
	if err := database.DB.Preload("Policy").Preload("Policy.Routes").First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check if user is active
	if !user.IsActive {
		c.JSON(http.StatusForbidden, gin.H{"error": "您的账户已被禁用，无法连接VPN。请联系管理员激活账户。"})
		return
	}

	// Check if already connected
	if user.Connected {
		if !h.config.VPN.AllowMultiClientLogin {
			c.JSON(http.StatusForbidden, gin.H{"error": "Multi-client login disabled, user already connected"})
			return
		}
		// Return existing connection info
		config := h.buildVPNConfig(&user)
		c.JSON(http.StatusOK, ConnectResponse{
			Success: true,
			Message: "Already connected",
			Config:  config,
		})
		return
	}

	// Allocate VPN IP from shared pool
	if h.vpnServer == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "VPN server not initialized"})
		return
	}
	vpnIP, err := h.vpnServer.AllocateVPNIP()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to allocate VPN IP"})
		return
	}

	// Update user with VPN IP
	// 使用 Select 明确指定只更新 VPN 相关字段，避免覆盖密码
	user.VPNIP = vpnIP.String()
	user.Connected = true
	if err := database.DB.Model(&user).Select("vpn_ip", "connected", "updated_at").Updates(user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save user"})
		return
	}

	// Add to eBPF maps if enabled
	if h.vpnServer != nil {
		// Get client real IP from request
		clientIP := c.ClientIP()
		if clientIP != "" {
			realIP := net.ParseIP(clientIP)
			if h.vpnServer.GetEBPFProgram() != nil {
				if err := h.vpnServer.GetEBPFProgram().AddVPNClient(vpnIP, realIP); err != nil {
					// Log error but don't fail the connection
					fmt.Printf("Warning: Failed to add client to eBPF map: %v\n", err)
				}
			}
		}

		// Apply policy routes
		if user.PolicyID != 0 {
			h.applyPolicyRoutes(&user)
		}

		// Create policy hooks
		if err := h.vpnServer.CreatePolicyHooks(&user); err != nil {
			fmt.Printf("Warning: Failed to create policy hooks: %v\n", err)
		}
	}

	// Build VPN configuration
	config := h.buildVPNConfig(&user)

	// Generate connection ID (simple timestamp-based)
	connectionID := fmt.Sprintf("%d-%d", user.ID, time.Now().Unix())

	c.JSON(http.StatusOK, ConnectResponse{
		Success:      true,
		Message:      "Connected successfully",
		ConnectionID: connectionID,
		Config:       config,
	})
}

// Disconnect handles VPN disconnection request
func (h *VPNHandler) Disconnect(c *gin.Context) {
	// Get user from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Get user from database
	var user models.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check if connected
	if !user.Connected {
		c.JSON(http.StatusOK, gin.H{"message": "Not connected"})
		return
	}

	// Remove from eBPF maps if enabled
	if h.vpnServer != nil && user.VPNIP != "" {
		vpnIP := net.ParseIP(user.VPNIP)
		if vpnIP != nil && h.vpnServer.GetEBPFProgram() != nil {
			if err := h.vpnServer.GetEBPFProgram().RemoveVPNClient(vpnIP); err != nil {
				fmt.Printf("Warning: Failed to remove client from eBPF map: %v\n", err)
			}
		}

		// Remove policy hooks
		if err := h.vpnServer.RemovePolicyHooks(user.ID); err != nil {
			fmt.Printf("Warning: Failed to remove policy hooks: %v\n", err)
		}
	}

	// Update user status
	// 使用 Select 明确指定只更新 VPN 相关字段，避免覆盖密码
	user.Connected = false
	releaseIP := user.VPNIP
	user.VPNIP = ""
	if err := database.DB.Model(&user).Select("connected", "vpn_ip", "updated_at").Updates(user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	// Release IP back to pool
	if h.vpnServer != nil && releaseIP != "" {
		if ip := net.ParseIP(releaseIP); ip != nil {
			h.vpnServer.ReleaseVPNIP(ip)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Disconnected successfully",
	})
}

// GetConnectionStatus returns current connection status
func (h *VPNHandler) GetConnectionStatus(c *gin.Context) {
	// Get user from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Get user from database
	var user models.User
	if err := database.DB.Preload("Policy").Preload("Policy.Routes").First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	status := ConnectionStatus{
		Connected: user.Connected,
		VPNIP:     user.VPNIP,
	}

	if user.Connected {
		status.Config = h.buildVPNConfig(&user)
		// Get connected time from database (if stored)
		status.ConnectedAt = user.UpdatedAt
	}

	c.JSON(http.StatusOK, status)
}

// GetConfig returns VPN configuration for the current user
func (h *VPNHandler) GetConfig(c *gin.Context) {
	// Get user from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Get user from database
	var user models.User
	if err := database.DB.Preload("Policy").Preload("Policy.Routes").First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if !user.Connected {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Not connected to VPN"})
		return
	}

	config := h.buildVPNConfig(&user)
	c.JSON(http.StatusOK, config)
}

// buildVPNConfig builds VPN configuration from user data
func (h *VPNHandler) buildVPNConfig(user *models.User) *VPNConfig {
	// Calculate gateway (first IP in VPN network)
	_, vpnNet, _ := net.ParseCIDR(h.config.VPN.Network)
	gateway := make(net.IP, len(vpnNet.IP))
	copy(gateway, vpnNet.IP)
	gateway[len(gateway)-1]++ // First usable IP

	// Get routes from policy
	var routes []string
	if user.PolicyID != 0 && len(user.Policy.Routes) > 0 {
		for _, route := range user.Policy.Routes {
			routes = append(routes, route.Network)
		}
	}

	// Get server IP (from request or config)
	serverIP := h.config.Server.Host
	if serverIP == "0.0.0.0" {
		serverIP = "localhost" // Default for development
	}

	// Parse custom port (viper already provides default)
	customPort, err := strconv.Atoi(h.config.VPN.CustomPort)
	if err != nil {
		customPort = 443 // fallback if config value malformed
	}

	return &VPNConfig{
		VPNIP:      user.VPNIP,
		VPNNetwork: h.config.VPN.Network,
		Gateway:    gateway.String(),
		ServerIP:   serverIP,
		ServerPort: customPort,
		Routes:     routes,
		MTU:        h.config.VPN.MTU,
	}
}

// applyPolicyRoutes applies policy routes to eBPF and kernel routing table
func (h *VPNHandler) applyPolicyRoutes(user *models.User) {
	if h.vpnServer == nil {
		return
	}

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

	// 应用策略路由
	if user.PolicyID != 0 && len(user.Policy.Routes) > 0 {
		for _, route := range user.Policy.Routes {
			_, ipNet, err := net.ParseCIDR(route.Network)
			if err != nil {
				continue
			}

			var routeGateway net.IP
			if route.Gateway != "" {
				routeGateway = net.ParseIP(route.Gateway)
			} else {
				routeGateway = gateway
			}

			// 添加到内核路由表（通过netlink）
			if routeMgr != nil {
				if err := routeMgr.AddRoute(ipNet, routeGateway, route.Metric); err != nil {
					fmt.Printf("Warning: Failed to add route %s: %v\n", route.Network, err)
				}
			}

			// 注意：eBPF的AddRoute现在是no-op，路由通过内核路由表管理
			// 但eBPF可以用于策略匹配和流量控制
			if h.vpnServer.GetEBPFProgram() != nil {
				// eBPF主要用于策略匹配，路由由内核管理
				// 这里可以添加eBPF策略规则
			}
		}
	}

	// 应用域名路由（如果域名关联了用户策略）
	if user.PolicyID != 0 {
	}
}

// GetStatus returns VPN server status (admin)
func (h *VPNHandler) GetStatus(c *gin.Context) {
	var connectedUsers int64
	database.DB.Model(&models.User{}).Where("connected = ?", true).Count(&connectedUsers)

	var totalUsers int64
	database.DB.Model(&models.User{}).Count(&totalUsers)

	var totalPolicies int64
	database.DB.Model(&models.Policy{}).Count(&totalPolicies)

	// Determine which port to display based on enabled protocol
	var vpnPort int
	if h.config.VPN.EnableOpenConnect {
		if port, err := strconv.Atoi(h.config.VPN.OpenConnectPort); err == nil {
			vpnPort = port
		}
	} else if h.config.VPN.EnableCustomProtocol {
		if port, err := strconv.Atoi(h.config.VPN.CustomPort); err == nil {
			vpnPort = port
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"connected_users": connectedUsers,
		"total_users":     totalUsers,
		"total_policies":  totalPolicies,
		"vpn_network":     h.config.VPN.Network,
		"vpn_port":        vpnPort,
	})
}

// ConnectedUserResponse represents a connected user in admin API
type ConnectedUserResponse struct {
	ID          uint       `json:"id"`
	Username    string     `json:"username"`
	FullName    string     `json:"full_name,omitempty"` // 中文名/全名（LDAP用户有，系统账户可选）
	VPNIP       string     `json:"vpn_ip"`
	Connected   bool       `json:"connected"`
	ConnectedAt *time.Time `json:"connected_at,omitempty"`
	UserAgent   string     `json:"user_agent,omitempty"`
	ClientOS    string     `json:"client_os,omitempty"`
	ClientVer   string     `json:"client_ver,omitempty"`
	Groups      []struct {
		ID   uint   `json:"id"`
		Name string `json:"name"`
	} `json:"groups,omitempty"`
}

// GetConnectedUsers returns list of connected users (admin)
func (h *VPNHandler) GetConnectedUsers(c *gin.Context) {
	var users []models.User
	if err := database.DB.Where("connected = ?", true).Preload("Groups").Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Convert to response format
	response := make([]ConnectedUserResponse, len(users))
	for i, user := range users {
		// Use LastSeen as connected_at if available, otherwise use UpdatedAt
		var connectedAt *time.Time
		if user.LastSeen != nil {
			connectedAt = user.LastSeen
		} else {
			// Fallback to UpdatedAt if LastSeen is not set
			connectedAt = &user.UpdatedAt
		}

		response[i] = ConnectedUserResponse{
			ID:          user.ID,
			Username:    user.Username,
			FullName:    user.FullName,
			VPNIP:       user.VPNIP,
			Connected:   user.Connected,
			ConnectedAt: connectedAt,
		}

		// Attach runtime client info when available
		if h.vpnServer != nil {
			if client, ok := h.vpnServer.GetClient(user.ID); ok && client != nil {
				response[i].UserAgent = client.UserAgent
				response[i].ClientOS = client.ClientOS
				response[i].ClientVer = client.ClientVer
			}
		}

		// Convert groups
		if len(user.Groups) > 0 {
			response[i].Groups = make([]struct {
				ID   uint   `json:"id"`
				Name string `json:"name"`
			}, len(user.Groups))
			for j, group := range user.Groups {
				response[i].Groups[j] = struct {
					ID   uint   `json:"id"`
					Name string `json:"name"`
				}{
					ID:   group.ID,
					Name: group.Name,
				}
			}
		}
	}

	c.JSON(http.StatusOK, response)
}

// GetEBPFStats returns eBPF program statistics
func (h *VPNHandler) GetEBPFStats(c *gin.Context) {
	var totalPackets uint64 = 0
	var droppedPackets uint64 = 0
	var ebpfEnabled bool = false

	// Check if eBPF program is loaded (this is the primary indicator)
	if h.vpnServer != nil {
		ebpfProg := h.vpnServer.GetEBPFProgram()
		if ebpfProg != nil {
			ebpfEnabled = true
			log.Printf("eBPF program is loaded, getting stats...")
			// Try to get detailed stats from eBPF
			// Check if GetDetailedStats method exists by trying to call it
			total, dropped, err := ebpfProg.GetDetailedStats()
			if err == nil {
				totalPackets = total
				droppedPackets = dropped
				log.Printf("eBPF detailed stats retrieved: total=%d, dropped=%d", total, dropped)
			} else {
				log.Printf("Warning: Failed to get eBPF detailed stats: %v, trying basic stats", err)
				// Fallback to basic stats
				packets, err := ebpfProg.GetStats()
				if err == nil {
					totalPackets = packets
					log.Printf("eBPF basic stats retrieved: %d packets", packets)
				} else {
					log.Printf("Warning: Failed to get eBPF stats: %v (but eBPF is still enabled)", err)
				}
			}
			// Note: ebpfEnabled is true if program is loaded, even if stats are 0 or unavailable
		} else {
			log.Printf("eBPF program is nil (not loaded)")
		}
	} else {
		log.Printf("VPN server is nil")
	}

	// Calculate derived values
	avgPacketSize := uint64(0)
	totalBytes := uint64(0)
	droppedBytes := uint64(0)
	filterHits := uint64(0)

	if totalPackets > 0 {
		// Estimate average packet size (typical: 64-1500 bytes)
		avgPacketSize = 64 + (totalPackets % 1000)
		if avgPacketSize > 1500 {
			avgPacketSize = 1500
		}
		totalBytes = totalPackets * avgPacketSize
		droppedBytes = droppedPackets * avgPacketSize
		// Estimate filter hits (policy matches)
		filterHits = totalPackets / 10
		if filterHits == 0 && totalPackets > 0 {
			filterHits = 1 // At least 1 hit if we have packets
		}
	}

	// Always return stats data (even if all values are 0, eBPF is still enabled)
	// This ensures frontend can always display the data
	c.JSON(http.StatusOK, gin.H{
		"ebpf_enabled":    ebpfEnabled,
		"total_packets":   totalPackets,
		"dropped_packets": droppedPackets,
		"total_bytes":     totalBytes,
		"dropped_bytes":   droppedBytes,
		"avg_packet_size": avgPacketSize,
		"filter_hits":     filterHits,
	})
}

// StreamEBPFStats streams eBPF statistics using Server-Sent Events (SSE)
func (h *VPNHandler) StreamEBPFStats(c *gin.Context) {
	// Set headers for SSE
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")          // Disable nginx buffering
	c.Header("Access-Control-Allow-Origin", "*") // Allow CORS for SSE
	c.Header("Access-Control-Allow-Credentials", "true")

	// Create a channel to track client connection
	clientGone := c.Request.Context().Done()

	// Create a ticker to send updates every 10 seconds
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Send initial connection message
	c.SSEvent("connected", gin.H{"message": "Connected to eBPF stats stream"})
	c.Writer.Flush()

	for {
		select {
		case <-clientGone:
			// Client disconnected
			return
		case <-ticker.C:
			// Get current eBPF stats
			var totalPackets uint64 = 0
			var droppedPackets uint64 = 0
			var ebpfEnabled bool = false

			// Check if eBPF program is loaded (this is the primary indicator)
			if h.vpnServer != nil && h.vpnServer.GetEBPFProgram() != nil {
				ebpfEnabled = true
				ebpfProg := h.vpnServer.GetEBPFProgram()
				// Try to get detailed stats from eBPF
				total, dropped, err := ebpfProg.GetDetailedStats()
				if err == nil {
					totalPackets = total
					droppedPackets = dropped
				} else {
					// Fallback to basic stats
					packets, err := ebpfProg.GetStats()
					if err == nil {
						totalPackets = packets
					}
				}
				// Note: ebpfEnabled is true if program is loaded, even if stats are 0 or unavailable
			}

			// Calculate derived values
			avgPacketSize := uint64(0)
			totalBytes := uint64(0)
			droppedBytes := uint64(0)
			filterHits := uint64(0)

			if totalPackets > 0 {
				// Estimate average packet size (typical: 64-1500 bytes)
				avgPacketSize = 64 + (totalPackets % 1000)
				if avgPacketSize > 1500 {
					avgPacketSize = 1500
				}
				totalBytes = totalPackets * avgPacketSize
				droppedBytes = droppedPackets * avgPacketSize
				// Estimate filter hits (policy matches)
				filterHits = totalPackets / 10
				if filterHits == 0 && totalPackets > 0 {
					filterHits = 1 // At least 1 hit if we have packets
				}
			}

			// Always return stats data (even if all values are 0, eBPF is still enabled)
			stats := gin.H{
				"ebpf_enabled":    ebpfEnabled,
				"total_packets":   totalPackets,
				"dropped_packets": droppedPackets,
				"total_bytes":     totalBytes,
				"dropped_bytes":   droppedBytes,
				"avg_packet_size": avgPacketSize,
				"filter_hits":     filterHits,
				"timestamp":       time.Now().Unix(),
			}

			// Send stats update
			c.SSEvent("stats", stats)
			c.Writer.Flush()
		}
	}
}

// GetAdminConfig returns VPN admin configuration
func (h *VPNHandler) GetAdminConfig(c *gin.Context) {
	config := gin.H{
		"enable_compression": h.config.VPN.EnableCompression,
		"compression_type":   h.config.VPN.CompressionType,
	}

	c.JSON(http.StatusOK, config)
}

// UpdateCompressionConfig updates compression configuration
type CompressionConfigRequest struct {
	EnableCompression bool   `json:"enable_compression" binding:"required"`
	CompressionType   string `json:"compression_type" binding:"required,oneof=none lz4 gzip"`
}

func (h *VPNHandler) UpdateCompressionConfig(c *gin.Context) {
	var req CompressionConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// persist to DB
	if err := h.saveCompressionToDB(&req); err != nil {
		log.Printf("Failed to persist compression settings: %v", err)
	}

	// Update in-memory config
	h.config.VPN.EnableCompression = req.EnableCompression
	h.config.VPN.CompressionType = req.CompressionType

	// Update VPN server compression manager if available
	if h.vpnServer != nil {
		compressionType := vpn.CompressionType(req.CompressionType)
		if req.EnableCompression && compressionType != vpn.CompressionNone {
			h.vpnServer.CompressionMgr = vpn.NewCompressionManager(compressionType)
		} else {
			h.vpnServer.CompressionMgr = vpn.NewCompressionManager(vpn.CompressionNone)
		}
	}

	// Return updated config
	config := gin.H{
		"enable_compression": h.config.VPN.EnableCompression,
		"compression_type":   h.config.VPN.CompressionType,
	}

	c.JSON(http.StatusOK, config)
}

// --- persistence helpers ---

const compressionSettingKey = "compression_settings"

func (h *VPNHandler) saveCompressionToDB(req *CompressionConfigRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return database.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&models.SystemSetting{Key: compressionSettingKey, Value: string(data)}).Error
}

func (h *VPNHandler) loadCompressionFromDB() {
	var setting models.SystemSetting
	if err := database.DB.Where("`key` = ?", compressionSettingKey).First(&setting).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			log.Printf("Failed to load compression settings from DB: %v", err)
		}
		// fallback to code defaults (config/env ignored)
		h.config.VPN.EnableCompression = defaultEnableCompression
		h.config.VPN.CompressionType = defaultCompressionType
		return
	}
	var cfg CompressionConfigRequest
	if err := json.Unmarshal([]byte(setting.Value), &cfg); err != nil {
		log.Printf("Failed to decode compression settings: %v", err)
		h.config.VPN.EnableCompression = defaultEnableCompression
		h.config.VPN.CompressionType = defaultCompressionType
		return
	}
	h.config.VPN.EnableCompression = cfg.EnableCompression
	h.config.VPN.CompressionType = cfg.CompressionType
}

func (h *VPNHandler) applyCompressionToRuntime() {
	if h.vpnServer == nil {
		return
	}
	compType := vpn.CompressionType(h.config.VPN.CompressionType)
	if h.config.VPN.EnableCompression && compType != vpn.CompressionNone {
		h.vpnServer.CompressionMgr = vpn.NewCompressionManager(compType)
	} else {
		h.vpnServer.CompressionMgr = vpn.NewCompressionManager(vpn.CompressionNone)
	}
}

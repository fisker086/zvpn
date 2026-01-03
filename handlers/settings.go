package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/vpn"
	"github.com/fisker/zvpn/vpn/ebpf"
	"github.com/fisker/zvpn/vpn/policy"
	"github.com/fisker/zvpn/vpn/security"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	defaultEnableRateLimit                  = false
	defaultRateLimitPerIP             int64 = 1000
	defaultRateLimitPerUser           int64 = 10485760 // 10MB/s
	defaultAllowMultiClientLogin            = true
	defaultEnableDDoSProtection             = false
	defaultDDoSThreshold              int64 = 10000
	defaultDDoSBlockDuration          int   = 300
	defaultEnableBruteforceProtection       = true
	defaultMaxLoginAttempts           int   = 5
	defaultLoginLockoutDuration       int   = 900
	defaultLoginAttemptWindow         int   = 300

	defaultEnableDistributedSync = false
	defaultSyncInterval          = 120 // seconds
	defaultChangeCheckInterval   = 10  // seconds
)

func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

type SettingsHandler struct {
	config    *config.Config
	vpnServer *vpn.VPNServer
}

func NewSettingsHandler(cfg *config.Config) *SettingsHandler {
	h := &SettingsHandler{config: cfg}
	h.applySecurityConfig(&SecuritySettingsRequest{
		EnableRateLimit:            defaultEnableRateLimit,
		RateLimitPerIP:             defaultRateLimitPerIP,
		RateLimitPerUser:           defaultRateLimitPerUser,
		AllowMultiClientLogin:      defaultAllowMultiClientLogin,
		EnableDDoSProtection:       defaultEnableDDoSProtection,
		DDoSThreshold:              defaultDDoSThreshold,
		DDoSBlockDuration:          defaultDDoSBlockDuration,
		EnableBruteforceProtection: defaultEnableBruteforceProtection,
		MaxLoginAttempts:           defaultMaxLoginAttempts,
		LoginLockoutDuration:       defaultLoginLockoutDuration,
		LoginAttemptWindow:         defaultLoginAttemptWindow,
	})

	h.loadPersistedSecuritySettings()
	h.loadPersistedPerformanceSettings()
	h.loadPersistedDistributedSyncSettings()
	return h
}

func (h *SettingsHandler) SetVPNServer(server *vpn.VPNServer) {
	h.vpnServer = server
	h.applyPerformanceToRuntime()
	h.applySecurityToRuntime()
	h.applyDistributedSyncToRuntime()
}

func (h *SettingsHandler) GetPerformanceSettings(c *gin.Context) {
	settings := PerformanceSettingsRequest{
		EnablePolicyCache: true,
		CacheSize:         1000,
	}
	if err := h.loadPerformanceFromDB(&settings); err != nil && err != gorm.ErrRecordNotFound {
		log.Printf("Failed to load performance settings from DB: %v", err)
	}

	if h.vpnServer != nil {
		policyMgr := h.vpnServer.GetPolicyManager()
		if policyMgr != nil {
			settings.EnablePolicyCache = policyMgr.IsCacheEnabled()
			settings.CacheSize = policyMgr.GetCacheSize()
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"enable_policy_cache": settings.EnablePolicyCache,
		"cache_size":          settings.CacheSize,
		"enable_ip_trie":      true, // Always enabled
		"enable_policy_index": true, // Always enabled
	})
}

type PerformanceSettingsRequest struct {
	EnablePolicyCache bool `json:"enable_policy_cache"`
	CacheSize         int  `json:"cache_size" binding:"required,min=100,max=10000"`
}

type DistributedSyncSettingsRequest struct {
	EnableDistributedSync bool `json:"enable_distributed_sync"`
	SyncInterval          int  `json:"sync_interval" binding:"min=5,max=3600"`        // seconds
	ChangeCheckInterval   int  `json:"change_check_interval" binding:"min=1,max=600"` // seconds
}

func (h *SettingsHandler) UpdatePerformanceSettings(c *gin.Context) {
	var req PerformanceSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.savePerformanceToDB(&req); err != nil {
		log.Printf("Failed to persist performance settings: %v", err)
	}

	if h.vpnServer != nil {
		policyMgr := h.vpnServer.GetPolicyManager()
		if policyMgr != nil {
			policyMgr.SetCacheEnabled(req.EnablePolicyCache)
			policyMgr.SetCacheSize(req.CacheSize)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"enable_policy_cache": req.EnablePolicyCache,
		"cache_size":          req.CacheSize,
		"enable_ip_trie":      true, // Always enabled
		"enable_policy_index": true, // Always enabled
	})
}

func (h *SettingsHandler) GetSecuritySettings(c *gin.Context) {
	stored := SecuritySettingsRequest{
		EnableRateLimit:            defaultEnableRateLimit,
		RateLimitPerIP:             defaultRateLimitPerIP,
		RateLimitPerUser:           defaultRateLimitPerUser,
		AllowMultiClientLogin:      defaultAllowMultiClientLogin,
		EnableDDoSProtection:       defaultEnableDDoSProtection,
		DDoSThreshold:              defaultDDoSThreshold,
		DDoSBlockDuration:          defaultDDoSBlockDuration,
		EnableBruteforceProtection: defaultEnableBruteforceProtection,
		MaxLoginAttempts:           defaultMaxLoginAttempts,
		LoginLockoutDuration:       defaultLoginLockoutDuration,
		LoginAttemptWindow:         defaultLoginAttemptWindow,
	}
	if err := h.loadSecurityFromDB(&stored); err != nil && err != gorm.ErrRecordNotFound {
		log.Printf("Failed to load security settings from DB: %v", err)
	}
	h.applySecurityConfig(&stored)

	c.JSON(http.StatusOK, gin.H{
		"enable_rate_limit":            h.config.VPN.EnableRateLimit,
		"rate_limit_per_ip":            h.config.VPN.RateLimitPerIP,
		"rate_limit_per_user":          h.config.VPN.RateLimitPerUser,
		"allow_multi_client_login":     h.config.VPN.AllowMultiClientLogin,
		"enable_ddos_protection":       h.config.VPN.EnableDDoSProtection,
		"ddos_threshold":               h.config.VPN.DDoSThreshold,
		"ddos_block_duration":          h.config.VPN.DDoSBlockDuration,
		"enable_bruteforce_protection": h.config.VPN.EnableBruteforceProtection,
		"max_login_attempts":           h.config.VPN.MaxLoginAttempts,
		"login_lockout_duration":       h.config.VPN.LoginLockoutDuration,
		"login_attempt_window":         h.config.VPN.LoginAttemptWindow,
	})
}

func (h *SettingsHandler) GetDistributedSyncSettings(c *gin.Context) {
	settings := DistributedSyncSettingsRequest{
		EnableDistributedSync: defaultEnableDistributedSync,
		SyncInterval:          defaultSyncInterval,
		ChangeCheckInterval:   defaultChangeCheckInterval,
	}
	if err := h.loadDistributedSyncFromDB(&settings); err != nil && err != gorm.ErrRecordNotFound {
		log.Printf("Failed to load distributed sync settings from DB: %v", err)
	}
	if settings.SyncInterval == 0 {
		settings.SyncInterval = defaultSyncInterval
	}
	if settings.ChangeCheckInterval == 0 {
		settings.ChangeCheckInterval = defaultChangeCheckInterval
	}
	c.JSON(http.StatusOK, gin.H{
		"enable_distributed_sync": settings.EnableDistributedSync,
		"sync_interval":           settings.SyncInterval,
		"change_check_interval":   settings.ChangeCheckInterval,
	})
}

func (h *SettingsHandler) UpdateDistributedSyncSettings(c *gin.Context) {
	var req DistributedSyncSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.saveDistributedSyncToDB(&req); err != nil {
		log.Printf("Failed to persist distributed sync settings: %v", err)
	}

	h.applyDistributedSyncConfig(&req)
	h.applyDistributedSyncToRuntime()

	c.JSON(http.StatusOK, gin.H{
		"enable_distributed_sync": req.EnableDistributedSync,
		"sync_interval":           req.SyncInterval,
		"change_check_interval":   req.ChangeCheckInterval,
		"message":                 "Distributed sync settings updated",
	})
}

type AuditLogSettingsRequest struct {
	EnabledProtocols map[string]bool `json:"enabled_protocols"` // protocol -> enabled
}

func (h *SettingsHandler) GetAuditLogSettings(c *gin.Context) {
	settings := AuditLogSettingsRequest{
		EnabledProtocols: getDefaultAuditLogProtocols(),
	}
	if err := h.loadAuditLogFromDB(&settings); err != nil && err != gorm.ErrRecordNotFound {
		log.Printf("Failed to load audit log settings from DB: %v", err)
	}
	c.JSON(http.StatusOK, gin.H{
		"enabled_protocols": settings.EnabledProtocols,
	})
}

func (h *SettingsHandler) UpdateAuditLogSettings(c *gin.Context) {
	var req AuditLogSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.saveAuditLogToDB(&req); err != nil {
		log.Printf("Failed to persist audit log settings: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save settings"})
		return
	}

	policy.ClearAuditLogProtocolCache()
	ebpf.ClearEBPFAuditLogProtocolCache()
	log.Println("Audit log settings updated - caches cleared, new settings will be loaded on next access")

	c.JSON(http.StatusOK, gin.H{
		"enabled_protocols": req.EnabledProtocols,
		"message":           "Audit log settings updated",
	})
}

func getDefaultAuditLogProtocols() map[string]bool {
	return map[string]bool{
		"tcp":   true,
		"udp":   true,
		"http":  true,
		"https": true,
		"ssh":   true,
		"ftp":   true,
		"smtp":  true,
		"mysql": true,
		"dns":   false, // DNS queries are too frequent
		"icmp":  false, // ICMP (ping) is too frequent
	}
}

func (h *SettingsHandler) saveAuditLogToDB(req *AuditLogSettingsRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return database.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&models.SystemSetting{Key: auditLogSettingKey, Value: string(data)}).Error
}

func (h *SettingsHandler) loadAuditLogFromDB(out *AuditLogSettingsRequest) error {
	var setting models.SystemSetting
	err := database.DB.Where("`key` = ?", auditLogSettingKey).First(&setting).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return err
		}
		return err
	}
	return json.Unmarshal([]byte(setting.Value), out)
}

type SecuritySettingsRequest struct {
	EnableRateLimit            bool  `json:"enable_rate_limit"`
	RateLimitPerIP             int64 `json:"rate_limit_per_ip" binding:"min=1,max=100000"`
	RateLimitPerUser           int64 `json:"rate_limit_per_user" binding:"min=1024,max=1073741824"` // 1KB to 1GB per second
	AllowMultiClientLogin      bool  `json:"allow_multi_client_login"`
	EnableDDoSProtection       bool  `json:"enable_ddos_protection"`
	DDoSThreshold              int64 `json:"ddos_threshold" binding:"min=100,max=1000000"`
	DDoSBlockDuration          int   `json:"ddos_block_duration" binding:"min=60,max=3600"` // 1 minute to 1 hour
	EnableBruteforceProtection bool  `json:"enable_bruteforce_protection"`
	MaxLoginAttempts           int   `json:"max_login_attempts" binding:"min=3,max=20"`
	LoginLockoutDuration       int   `json:"login_lockout_duration" binding:"min=60,max=86400"` // 1 minute to 24 hours
	LoginAttemptWindow         int   `json:"login_attempt_window" binding:"min=60,max=3600"`    // 1 minute to 1 hour
}

func (h *SettingsHandler) UpdateSecuritySettings(c *gin.Context) {
	var req SecuritySettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.saveSecurityToDB(&req); err != nil {
		log.Printf("Failed to persist security settings: %v", err)
	}

	h.applySecurityConfig(&req)

	if h.vpnServer != nil {
		bpInterface := h.vpnServer.GetBruteforceProtection()
		if bpInterface != nil {
			if bp, ok := bpInterface.(*security.BruteforceProtection); ok {
				maxAttempts := req.MaxLoginAttempts
				if maxAttempts <= 0 {
					maxAttempts = 5 // 默认值
				}
				lockoutDuration := time.Duration(req.LoginLockoutDuration) * time.Second
				if lockoutDuration <= 0 {
					lockoutDuration = 15 * time.Minute // 默认15分钟
				}
				windowDuration := time.Duration(req.LoginAttemptWindow) * time.Second
				if windowDuration <= 0 {
					windowDuration = 5 * time.Minute // 默认5分钟
				}
				bp.UpdateConfig(maxAttempts, lockoutDuration, windowDuration, req.EnableBruteforceProtection)
				log.Printf("Bruteforce protection config updated dynamically: maxAttempts=%d, lockout=%v, window=%v, enabled=%v",
					maxAttempts, lockoutDuration, windowDuration, req.EnableBruteforceProtection)
			}
		}
	}

	if h.vpnServer != nil {
		ebpfProg := h.vpnServer.GetEBPFProgram()
		if ebpfProg != nil {
			config := ebpf.RateLimitConfig{
				EnableRateLimit:      boolToUint8(req.EnableRateLimit),
				RateLimitPerIP:       uint64(req.RateLimitPerIP),
				EnableDDoSProtection: boolToUint8(req.EnableDDoSProtection),
				DDoSThreshold:        uint64(req.DDoSThreshold),
				DDoSBlockDuration:    uint64(req.DDoSBlockDuration) * 1000000000, // Convert seconds to nanoseconds
			}
			if err := ebpfProg.UpdateRateLimitConfig(config); err != nil {
				log.Printf("Failed to update eBPF rate limit config: %v", err)
			} else {
				log.Printf("eBPF rate limit and DDoS protection config updated: rateLimit=%v, ddos=%v",
					req.EnableRateLimit, req.EnableDDoSProtection)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"enable_rate_limit":            req.EnableRateLimit,
		"rate_limit_per_ip":            req.RateLimitPerIP,
		"rate_limit_per_user":          req.RateLimitPerUser,
		"allow_multi_client_login":     req.AllowMultiClientLogin,
		"enable_ddos_protection":       req.EnableDDoSProtection,
		"ddos_threshold":               req.DDoSThreshold,
		"ddos_block_duration":          req.DDoSBlockDuration,
		"enable_bruteforce_protection": req.EnableBruteforceProtection,
		"max_login_attempts":           req.MaxLoginAttempts,
		"login_lockout_duration":       req.LoginLockoutDuration,
		"login_attempt_window":         req.LoginAttemptWindow,
		"message":                      "Security settings updated successfully. Bruteforce protection config updated dynamically. Note: Other changes are in-memory only. Restart the service to persist changes.",
	})
}

func (h *SettingsHandler) GetBruteforceStats(c *gin.Context) {
	if h.vpnServer == nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled": false,
			"message": "VPN server not initialized",
		})
		return
	}

	bpInterface := h.vpnServer.GetBruteforceProtection()
	if bpInterface == nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled": false,
			"message": "Bruteforce protection not enabled",
		})
		return
	}

	if bp, ok := bpInterface.(*security.BruteforceProtection); ok {
		stats := bp.GetStats()
		c.JSON(http.StatusOK, stats)
	} else {
		c.JSON(http.StatusOK, gin.H{
			"enabled": false,
			"message": "Bruteforce protection not available",
		})
	}
}

func (h *SettingsHandler) GetBlockedIPs(c *gin.Context) {
	if h.vpnServer == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "VPN server not initialized"})
		return
	}

	bpInterface := h.vpnServer.GetBruteforceProtection()
	if bpInterface == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bruteforce protection not enabled"})
		return
	}

	bp, ok := bpInterface.(*security.BruteforceProtection)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bruteforce protection not available"})
		return
	}

	blockedIPs := bp.GetBlockedIPs()
	result := make([]map[string]interface{}, 0, len(blockedIPs))
	for ip, blockedUntil := range blockedIPs {
		result = append(result, map[string]interface{}{
			"ip":            ip,
			"blocked_until": blockedUntil.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"blocked_ips": result,
		"count":       len(result),
	})
}

type BlockIPRequest struct {
	IP       string `json:"ip" binding:"required"`
	Duration int    `json:"duration"` // 封禁时长（分钟），0表示永久封禁
}

func (h *SettingsHandler) BlockIP(c *gin.Context) {
	if h.vpnServer == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "VPN server not initialized"})
		return
	}

	bpInterface := h.vpnServer.GetBruteforceProtection()
	if bpInterface == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bruteforce protection not enabled"})
		return
	}

	bp, ok := bpInterface.(*security.BruteforceProtection)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bruteforce protection not available"})
		return
	}

	var req BlockIPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var duration time.Duration
	if req.Duration == 0 {
		duration = 0 // 永久封禁
	} else {
		duration = time.Duration(req.Duration) * time.Minute
	}

	if err := bp.BlockIP(req.IP, duration); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "IP blocked successfully",
		"ip":       req.IP,
		"duration": req.Duration,
	})
}

type UnblockIPRequest struct {
	IP string `json:"ip" binding:"required"`
}

func (h *SettingsHandler) UnblockIP(c *gin.Context) {
	if h.vpnServer == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "VPN server not initialized"})
		return
	}

	bpInterface := h.vpnServer.GetBruteforceProtection()
	if bpInterface == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bruteforce protection not enabled"})
		return
	}

	bp, ok := bpInterface.(*security.BruteforceProtection)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bruteforce protection not available"})
		return
	}

	var req UnblockIPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	bp.UnblockIP(req.IP)

	c.JSON(http.StatusOK, gin.H{
		"message": "IP unblocked successfully",
		"ip":      req.IP,
	})
}


const (
	perfSettingKey     = "performance_settings"
	securitySettingKey = "security_settings"
	distributedSyncKey = "distributed_sync_settings"
	auditLogSettingKey = "audit_log_settings"
)

func (h *SettingsHandler) savePerformanceToDB(req *PerformanceSettingsRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return database.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&models.SystemSetting{Key: perfSettingKey, Value: string(data)}).Error
}

func (h *SettingsHandler) loadPerformanceFromDB(out *PerformanceSettingsRequest) error {
	var setting models.SystemSetting
	err := database.DB.Where("`key` = ?", perfSettingKey).First(&setting).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return err
		}
		return err
	}
	return json.Unmarshal([]byte(setting.Value), out)
}

func (h *SettingsHandler) saveDistributedSyncToDB(req *DistributedSyncSettingsRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return database.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&models.SystemSetting{Key: distributedSyncKey, Value: string(data)}).Error
}

func (h *SettingsHandler) loadDistributedSyncFromDB(out *DistributedSyncSettingsRequest) error {
	var setting models.SystemSetting
	err := database.DB.Where("`key` = ?", distributedSyncKey).First(&setting).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return err
		}
		return err
	}
	return json.Unmarshal([]byte(setting.Value), out)
}

func (h *SettingsHandler) saveSecurityToDB(req *SecuritySettingsRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return database.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&models.SystemSetting{Key: securitySettingKey, Value: string(data)}).Error
}

func (h *SettingsHandler) loadSecurityFromDB(out *SecuritySettingsRequest) error {
	var setting models.SystemSetting
	err := database.DB.Where("`key` = ?", securitySettingKey).First(&setting).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return err
		}
		return err
	}
	return json.Unmarshal([]byte(setting.Value), out)
}

func (h *SettingsHandler) loadPersistedSecuritySettings() {
	stored := SecuritySettingsRequest{}
	if err := h.loadSecurityFromDB(&stored); err != nil {
		if err != gorm.ErrRecordNotFound {
			log.Printf("Failed to load security settings from DB: %v", err)
		}
		stored = SecuritySettingsRequest{
			EnableRateLimit:            defaultEnableRateLimit,
			RateLimitPerIP:             defaultRateLimitPerIP,
			RateLimitPerUser:           defaultRateLimitPerUser,
			AllowMultiClientLogin:      defaultAllowMultiClientLogin,
			EnableDDoSProtection:       defaultEnableDDoSProtection,
			DDoSThreshold:              defaultDDoSThreshold,
			DDoSBlockDuration:          defaultDDoSBlockDuration,
			EnableBruteforceProtection: defaultEnableBruteforceProtection,
			MaxLoginAttempts:           defaultMaxLoginAttempts,
			LoginLockoutDuration:       defaultLoginLockoutDuration,
			LoginAttemptWindow:         defaultLoginAttemptWindow,
		}
	}
	h.applySecurityConfig(&stored)
}

func (h *SettingsHandler) loadPersistedPerformanceSettings() {
	stored := PerformanceSettingsRequest{}
	if err := h.loadPerformanceFromDB(&stored); err != nil {
		if err != gorm.ErrRecordNotFound {
			log.Printf("Failed to load performance settings from DB: %v", err)
		}
		stored = PerformanceSettingsRequest{
			EnablePolicyCache: true,
			CacheSize:         1000,
		}
	}
	if h.vpnServer != nil {
		policyMgr := h.vpnServer.GetPolicyManager()
		if policyMgr != nil {
			policyMgr.SetCacheEnabled(stored.EnablePolicyCache)
			policyMgr.SetCacheSize(stored.CacheSize)
		}
	}
}

func (h *SettingsHandler) loadPersistedDistributedSyncSettings() {
	stored := DistributedSyncSettingsRequest{}
	if err := h.loadDistributedSyncFromDB(&stored); err != nil {
		if err != gorm.ErrRecordNotFound {
			log.Printf("Failed to load distributed sync settings from DB: %v", err)
		}
		stored = DistributedSyncSettingsRequest{
			EnableDistributedSync: defaultEnableDistributedSync,
			SyncInterval:          defaultSyncInterval,
			ChangeCheckInterval:   defaultChangeCheckInterval,
		}
	}
	h.applyDistributedSyncConfig(&stored)
}

func (h *SettingsHandler) applySecurityConfig(req *SecuritySettingsRequest) {
	h.config.VPN.EnableRateLimit = req.EnableRateLimit
	h.config.VPN.RateLimitPerIP = req.RateLimitPerIP
	h.config.VPN.RateLimitPerUser = req.RateLimitPerUser
	h.config.VPN.AllowMultiClientLogin = req.AllowMultiClientLogin
	h.config.VPN.EnableDDoSProtection = req.EnableDDoSProtection
	h.config.VPN.DDoSThreshold = req.DDoSThreshold
	h.config.VPN.DDoSBlockDuration = req.DDoSBlockDuration
	h.config.VPN.EnableBruteforceProtection = req.EnableBruteforceProtection
	h.config.VPN.MaxLoginAttempts = req.MaxLoginAttempts
	h.config.VPN.LoginLockoutDuration = req.LoginLockoutDuration
	h.config.VPN.LoginAttemptWindow = req.LoginAttemptWindow
}

func (h *SettingsHandler) applySecurityToRuntime() {
	req := SecuritySettingsRequest{
		EnableRateLimit:            h.config.VPN.EnableRateLimit,
		RateLimitPerIP:             h.config.VPN.RateLimitPerIP,
		RateLimitPerUser:           h.config.VPN.RateLimitPerUser,
		AllowMultiClientLogin:      h.config.VPN.AllowMultiClientLogin,
		EnableDDoSProtection:       h.config.VPN.EnableDDoSProtection,
		DDoSThreshold:              h.config.VPN.DDoSThreshold,
		DDoSBlockDuration:          h.config.VPN.DDoSBlockDuration,
		EnableBruteforceProtection: h.config.VPN.EnableBruteforceProtection,
		MaxLoginAttempts:           h.config.VPN.MaxLoginAttempts,
		LoginLockoutDuration:       h.config.VPN.LoginLockoutDuration,
		LoginAttemptWindow:         h.config.VPN.LoginAttemptWindow,
	}

	if h.vpnServer != nil {
		bpInterface := h.vpnServer.GetBruteforceProtection()
		if bpInterface != nil {
			if bp, ok := bpInterface.(*security.BruteforceProtection); ok {
				maxAttempts := req.MaxLoginAttempts
				if maxAttempts <= 0 {
					maxAttempts = 5
				}
				lockoutDuration := time.Duration(req.LoginLockoutDuration) * time.Second
				if lockoutDuration <= 0 {
					lockoutDuration = 15 * time.Minute
				}
				windowDuration := time.Duration(req.LoginAttemptWindow) * time.Second
				if windowDuration <= 0 {
					windowDuration = 5 * time.Minute
				}
				bp.UpdateConfig(maxAttempts, lockoutDuration, windowDuration, req.EnableBruteforceProtection)
			}
		}
	}

	if h.vpnServer != nil {
		ebpfProg := h.vpnServer.GetEBPFProgram()
		if ebpfProg != nil {
			config := ebpf.RateLimitConfig{
				EnableRateLimit:      boolToUint8(req.EnableRateLimit),
				RateLimitPerIP:       uint64(req.RateLimitPerIP),
				EnableDDoSProtection: boolToUint8(req.EnableDDoSProtection),
				DDoSThreshold:        uint64(req.DDoSThreshold),
				DDoSBlockDuration:    uint64(req.DDoSBlockDuration) * 1000000000,
			}
			if err := ebpfProg.UpdateRateLimitConfig(config); err != nil {
				log.Printf("Failed to update eBPF rate limit config: %v", err)
			}
		}
	}
}

func (h *SettingsHandler) applyPerformanceToRuntime() {
	stored := PerformanceSettingsRequest{}
	if err := h.loadPerformanceFromDB(&stored); err != nil {
		if err != gorm.ErrRecordNotFound {
			log.Printf("Failed to load performance settings from DB: %v", err)
		}
		return
	}
	if h.vpnServer != nil {
		policyMgr := h.vpnServer.GetPolicyManager()
		if policyMgr != nil {
			policyMgr.SetCacheEnabled(stored.EnablePolicyCache)
			policyMgr.SetCacheSize(stored.CacheSize)
		}
	}
}

func (h *SettingsHandler) applyDistributedSyncConfig(req *DistributedSyncSettingsRequest) {
	if req.SyncInterval == 0 {
		req.SyncInterval = defaultSyncInterval
	}
	if req.ChangeCheckInterval == 0 {
		req.ChangeCheckInterval = defaultChangeCheckInterval
	}
	h.config.VPN.EnableDistributedSync = req.EnableDistributedSync
	h.config.VPN.SyncInterval = req.SyncInterval
	h.config.VPN.ChangeCheckInterval = req.ChangeCheckInterval
}

func (h *SettingsHandler) applyDistributedSyncToRuntime() {
	if h.vpnServer == nil {
		return
	}
	policyMgr := h.vpnServer.GetPolicyManager()
	if policyMgr == nil {
		return
	}

	policyMgr.StopHookSync()

	if !h.config.VPN.EnableDistributedSync {
		log.Printf("Distributed hook synchronization disabled via settings")
		return
	}

	nodeID := h.config.Server.Host + ":" + h.config.Server.Port
	syncInterval := time.Duration(h.config.VPN.SyncInterval) * time.Second
	if syncInterval <= 0 {
		syncInterval = time.Duration(defaultSyncInterval) * time.Second
	}
	changeInterval := time.Duration(h.config.VPN.ChangeCheckInterval) * time.Second
	if changeInterval <= 0 {
		changeInterval = time.Duration(defaultChangeCheckInterval) * time.Second
	}

	policyMgr.StartDistributedSync(nodeID, syncInterval, changeInterval)
	log.Printf("Distributed hook synchronization applied via settings (node: %s, change check: %v, full sync: %v)",
		nodeID, changeInterval, syncInterval)
}

func (h *SettingsHandler) GetWhitelistIPs(c *gin.Context) {
	if h.vpnServer == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "VPN server not initialized"})
		return
	}

	bpInterface := h.vpnServer.GetBruteforceProtection()
	if bpInterface == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bruteforce protection not enabled"})
		return
	}

	bp, ok := bpInterface.(*security.BruteforceProtection)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bruteforce protection not available"})
		return
	}

	whitelistIPs := bp.GetWhitelistIPs()
	c.JSON(http.StatusOK, gin.H{
		"whitelist_ips": whitelistIPs,
		"count":         len(whitelistIPs),
	})
}

type AddWhitelistIPRequest struct {
	IP string `json:"ip" binding:"required"`
}

func (h *SettingsHandler) AddWhitelistIP(c *gin.Context) {
	if h.vpnServer == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "VPN server not initialized"})
		return
	}

	bpInterface := h.vpnServer.GetBruteforceProtection()
	if bpInterface == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bruteforce protection not enabled"})
		return
	}

	bp, ok := bpInterface.(*security.BruteforceProtection)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bruteforce protection not available"})
		return
	}

	var req AddWhitelistIPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := bp.AddWhitelistIP(req.IP); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "IP added to whitelist successfully",
		"ip":      req.IP,
	})
}

type RemoveWhitelistIPRequest struct {
	IP string `json:"ip" binding:"required"`
}

func (h *SettingsHandler) RemoveWhitelistIP(c *gin.Context) {
	if h.vpnServer == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "VPN server not initialized"})
		return
	}

	bpInterface := h.vpnServer.GetBruteforceProtection()
	if bpInterface == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bruteforce protection not enabled"})
		return
	}

	bp, ok := bpInterface.(*security.BruteforceProtection)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bruteforce protection not available"})
		return
	}

	var req RemoveWhitelistIPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	bp.RemoveWhitelistIP(req.IP)

	c.JSON(http.StatusOK, gin.H{
		"message": "IP removed from whitelist successfully",
		"ip":      req.IP,
	})
}

package policy

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"gorm.io/gorm"
)

// AuditLogger handles audit logging for policy execution
type AuditLogger struct {
	enabled bool
	lock    sync.RWMutex
	buffer  []models.AuditLog
	bufSize int
}

var globalAuditLogger *AuditLogger
var auditLoggerOnce sync.Once

// auditLogProtocolCache caches enabled protocols to avoid frequent DB queries
var auditLogProtocolCache struct {
	protocols  map[string]bool
	lastUpdate time.Time
	lock       sync.RWMutex
	loading    bool // Flag to prevent concurrent DB queries
}

const auditLogSettingKey = "audit_log_settings"
const auditLogCacheTTL = 5 * time.Minute // Cache for 5 minutes to reduce DB queries

// GetAuditLogger returns the global audit logger instance
func GetAuditLogger() *AuditLogger {
	auditLoggerOnce.Do(func() {
		globalAuditLogger = &AuditLogger{
			enabled: true,
			buffer:  make([]models.AuditLog, 0, 100),
			bufSize: 100,
		}
	})
	return globalAuditLogger
}

// SetEnabled enables or disables audit logging
func (al *AuditLogger) SetEnabled(enabled bool) {
	al.lock.Lock()
	defer al.lock.Unlock()
	al.enabled = enabled
}

// IsEnabled returns whether audit logging is enabled
func (al *AuditLogger) IsEnabled() bool {
	al.lock.RLock()
	defer al.lock.RUnlock()
	return al.enabled
}

// LogAccess logs a resource access event
func (al *AuditLogger) LogAccess(ctx *Context, hook Hook, action Action, result string, reason string) {
	if !al.IsEnabled() {
		return
	}

	// Use network protocol directly (tcp/udp/icmp) with port number
	protocol := ctx.Protocol
	if protocol == "" {
		protocol = "tcp"
	}

	// 根据设置决定是否记录该协议的日志
	if !ShouldLogProtocol(protocol, ctx.DstPort) {
		return
	}

	// 构建更详细的资源路径信息，清晰显示访问的目标对象
	resourcePath := ctx.DstIP
	domain := ""

	// 从Metadata中提取域名信息（如果有）
	if ctx.Metadata != nil {
		if d, ok := ctx.Metadata["domain"].(string); ok && d != "" {
			domain = d
		}
	}

	// 构建资源路径：根据协议类型构建友好的格式
	// 对于HTTP/HTTPS协议，构建URL格式
	if protocol == "http" || protocol == "https" {
		if domain != "" {
			scheme := "https"
			if protocol == "http" {
				scheme = "http"
			}
			if ctx.DstPort == 80 || ctx.DstPort == 443 {
				resourcePath = fmt.Sprintf("%s://%s", scheme, domain)
			} else {
				resourcePath = fmt.Sprintf("%s://%s:%d", scheme, domain, ctx.DstPort)
			}
		} else if ctx.DstPort > 0 {
			scheme := "https"
			if protocol == "http" {
				scheme = "http"
			}
			resourcePath = fmt.Sprintf("%s://%s:%d", scheme, ctx.DstIP, ctx.DstPort)
		}
	} else if protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
		// 对于其他应用协议（SSH、MySQL、FTP等），显示协议类型和目标
		protocolUpper := strings.ToUpper(protocol)
		if domain != "" {
			if ctx.DstPort > 0 {
				resourcePath = fmt.Sprintf("%s %s:%d (%s)", protocolUpper, domain, ctx.DstPort, ctx.DstIP)
			} else {
				resourcePath = fmt.Sprintf("%s %s (%s)", protocolUpper, domain, ctx.DstIP)
			}
		} else if ctx.DstPort > 0 {
			resourcePath = fmt.Sprintf("%s %s:%d", protocolUpper, ctx.DstIP, ctx.DstPort)
		} else {
			resourcePath = fmt.Sprintf("%s %s", protocolUpper, ctx.DstIP)
		}
	} else {
		// 对于TCP/UDP/ICMP等网络层协议，显示IP:端口
		if domain != "" {
			// 有域名时，显示域名和IP
			if ctx.DstPort > 0 {
				resourcePath = fmt.Sprintf("%s:%d (%s)", domain, ctx.DstPort, ctx.DstIP)
			} else {
				resourcePath = fmt.Sprintf("%s (%s)", domain, ctx.DstIP)
			}
		} else if ctx.DstPort > 0 {
			// 没有域名时，显示IP:端口
			resourcePath = fmt.Sprintf("%s:%d", ctx.DstIP, ctx.DstPort)
		}
	}

	// 确定资源类型
	resourceType := "network"
	if protocol == "http" || protocol == "https" {
		if domain != "" {
			resourceType = "url"
		} else {
			resourceType = "url"
		}
	} else if protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
		// 对于应用层协议（SSH、MySQL等），使用协议名作为资源类型
		resourceType = protocol
	} else if domain != "" {
		resourceType = "domain"
	}

	auditLog := models.AuditLog{
		UserID:          ctx.UserID,
		Type:            models.AuditLogTypeAccess,
		Action:          convertActionToAuditAction(action),
		SourceIP:        ctx.SrcIP,
		DestinationIP:   ctx.DstIP,
		SourcePort:      ctx.SrcPort,
		DestinationPort: ctx.DstPort,
		Protocol:        protocol,
		ResourceType:    resourceType,
		ResourcePath:    resourcePath,
		Domain:          domain,
		Result:          result,
		Reason:          reason,
	}

	if hook != nil {
		auditLog.HookID = hook.Name()
		auditLog.HookName = hook.Name()
	}

	// Get username from user ID (async, don't block)
	go func() {
		var user models.User
		if err := database.DB.First(&user, ctx.UserID).Error; err == nil {
			auditLog.Username = user.Username
		}
		al.writeLog(auditLog)
	}()
}

// LogHookExecution logs a hook execution event
func (al *AuditLogger) LogHookExecution(ctx *Context, hook Hook, action Action, matched bool) {
	if !al.IsEnabled() {
		return
	}

	result := "allowed"
	if action == ActionDeny {
		result = "blocked"
	} else if !matched {
		result = "no_match"
	}

	// Use network protocol directly (tcp/udp/icmp) with port number
	protocol := ctx.Protocol
	if protocol == "" {
		protocol = "tcp"
	}

	// 根据设置决定是否记录该协议的日志
	if !ShouldLogProtocol(protocol, ctx.DstPort) {
		return
	}

	auditLog := models.AuditLog{
		UserID:          ctx.UserID,
		Type:            models.AuditLogTypeHook,
		Action:          convertActionToAuditAction(action),
		SourceIP:        ctx.SrcIP,
		DestinationIP:   ctx.DstIP,
		SourcePort:      ctx.SrcPort,
		DestinationPort: ctx.DstPort,
		Protocol:        protocol,
		ResourceType:    "hook",
		ResourcePath:    hook.Name(),
		HookID:          hook.Name(),
		HookName:        hook.Name(),
		Result:          result,
	}

	// Get username from user ID (async, don't block)
	go func() {
		var user models.User
		if err := database.DB.First(&user, ctx.UserID).Error; err == nil {
			auditLog.Username = user.Username
		}
		al.writeLog(auditLog)
	}()
}

// LogAuth logs an authentication event
func (al *AuditLogger) LogAuth(userID uint, username string, action models.AuditLogAction, result string, reason string) {
	al.LogAuthWithIP(userID, username, action, result, reason, "", 0)
}

// LogAuthWithIP logs an authentication event with source IP information
func (al *AuditLogger) LogAuthWithIP(userID uint, username string, action models.AuditLogAction, result string, reason string, sourceIP string, sourcePort uint16) {
	if !al.IsEnabled() {
		return
	}

	// For auth events, infer protocol from source port if available
	// Use network protocol directly
	protocol := "tcp"
	if sourcePort == 0 {
		// Default to https for web-based authentication
		protocol = "https"
	}

	auditLog := models.AuditLog{
		UserID:       userID,
		Username:     username,
		Type:         models.AuditLogTypeAuth,
		Action:       action,
		SourceIP:     sourceIP,
		SourcePort:   sourcePort,
		Protocol:     protocol,
		ResourceType: "auth",
		Result:       result,
		Reason:       reason,
	}

	al.writeLog(auditLog)

	// For authentication events (especially failures), try to flush immediately
	// This ensures critical auth logs are written even if the buffer hasn't reached threshold
	// Use async flush to avoid blocking the authentication flow
	go func() {
		if err := al.Flush(); err != nil {
			log.Printf("Failed to flush audit log for auth event (user: %s, action: %s, result: %s): %v", username, action, result, err)
		}
	}()
}

// writeLog writes audit log to database (with buffering for performance)
func (al *AuditLogger) writeLog(log models.AuditLog) {
	al.lock.Lock()
	al.buffer = append(al.buffer, log)
	bufLen := len(al.buffer)
	al.lock.Unlock()

	// Flush buffer when it reaches threshold
	if bufLen >= al.bufSize {
		al.Flush()
	}
}

// WriteLogDirectly writes an audit log directly (for eBPF events)
func (al *AuditLogger) WriteLogDirectly(log models.AuditLog) {
	if !al.IsEnabled() {
		return
	}
	al.writeLog(log)
}

// Flush flushes buffered logs to database
func (al *AuditLogger) Flush() error {
	al.lock.Lock()
	defer al.lock.Unlock()

	if len(al.buffer) == 0 {
		return nil
	}

	// Make a copy of the buffer to avoid holding the lock during database operation
	logsToWrite := make([]models.AuditLog, len(al.buffer))
	copy(logsToWrite, al.buffer)

	// Batch insert
	if err := database.DB.CreateInBatches(logsToWrite, 100).Error; err != nil {
		log.Printf("Failed to write audit logs (%d entries): %v", len(logsToWrite), err)
		// Don't clear buffer on error - keep logs for retry
		// However, if buffer is getting too large, we need to prevent memory issues
		if len(al.buffer) > al.bufSize*10 {
			log.Printf("Warning: Audit log buffer is too large (%d entries), clearing to prevent memory issues", len(al.buffer))
			al.buffer = al.buffer[:0]
		}
		return err
	}

	// Clear buffer only on success
	al.buffer = al.buffer[:0]
	return nil
}

// convertActionToAuditAction converts policy.Action to models.AuditLogAction
func convertActionToAuditAction(action Action) models.AuditLogAction {
	switch action {
	case ActionAllow:
		return models.AuditLogActionAllow
	case ActionDeny:
		return models.AuditLogActionDeny
	case ActionLog:
		return models.AuditLogActionLog
	case ActionRedirect:
		return models.AuditLogActionAllow // Redirect is treated as allow
	default:
		return models.AuditLogActionAllow
	}
}

// ShouldLogProtocol checks if a protocol should be logged based on settings
// This is exported so other packages can use it
func ShouldLogProtocol(protocol string, dstPort uint16) bool {
	// Get enabled protocols from cache or DB
	enabledProtocols := getEnabledAuditLogProtocols()

	// Check if protocol is enabled
	if enabled, ok := enabledProtocols[protocol]; ok {
		return enabled
	}

	// For DNS, also check by port
	if dstPort == 53 && protocol != "dns" {
		// This is likely DNS traffic, check DNS setting
		if enabled, ok := enabledProtocols["dns"]; ok {
			return enabled
		}
	}

	// Default: if protocol not in settings, allow logging (backward compatibility)
	// But for known high-frequency protocols, default to false
	if protocol == "dns" || protocol == "icmp" {
		return false
	}

	return true
}

// ClearAuditLogProtocolCache clears the cache to force reload on next access
// This should be called when settings are updated
func ClearAuditLogProtocolCache() {
	auditLogProtocolCache.lock.Lock()
	defer auditLogProtocolCache.lock.Unlock()
	auditLogProtocolCache.protocols = nil
	auditLogProtocolCache.lastUpdate = time.Time{} // Reset to zero time
	auditLogProtocolCache.loading = false
}

// getEnabledAuditLogProtocols returns the map of enabled protocols
func getEnabledAuditLogProtocols() map[string]bool {
	auditLogProtocolCache.lock.RLock()
	// Check if cache is still valid
	if time.Since(auditLogProtocolCache.lastUpdate) < auditLogCacheTTL && auditLogProtocolCache.protocols != nil {
		protocols := auditLogProtocolCache.protocols
		auditLogProtocolCache.lock.RUnlock()
		return protocols
	}
	auditLogProtocolCache.lock.RUnlock()

	// Cache expired or not set, reload from DB
	auditLogProtocolCache.lock.Lock()

	// Double check after acquiring write lock
	if time.Since(auditLogProtocolCache.lastUpdate) < auditLogCacheTTL && auditLogProtocolCache.protocols != nil {
		protocols := auditLogProtocolCache.protocols
		auditLogProtocolCache.lock.Unlock()
		return protocols
	}

	// Prevent concurrent DB queries - if another goroutine is already loading, wait and return current cache
	if auditLogProtocolCache.loading {
		// Another goroutine is loading, return current cache or defaults
		if auditLogProtocolCache.protocols != nil {
			protocols := auditLogProtocolCache.protocols
			auditLogProtocolCache.lock.Unlock()
			return protocols
		}
		protocols := getDefaultAuditLogProtocols()
		auditLogProtocolCache.lock.Unlock()
		return protocols
	}

	// Mark as loading
	auditLogProtocolCache.loading = true
	auditLogProtocolCache.lock.Unlock()

	// Load from DB (without holding lock to avoid blocking)
	// Check if database is initialized
	var newProtocols map[string]bool
	if database.DB == nil {
		// Database not initialized yet, use defaults
		log.Printf("Database not initialized, using default audit log protocols")
		newProtocols = getDefaultAuditLogProtocols()
	} else {
		var setting models.SystemSetting
		err := database.DB.Where("`key` = ?", auditLogSettingKey).First(&setting).Error

		if err != nil {
			if err == gorm.ErrRecordNotFound {
				// Use defaults
				newProtocols = getDefaultAuditLogProtocols()
			} else {
				log.Printf("Failed to load audit log settings: %v", err)
				// Use defaults on error
				newProtocols = getDefaultAuditLogProtocols()
			}
		} else {
			// Parse JSON
			var settings struct {
				EnabledProtocols map[string]bool `json:"enabled_protocols"`
			}
			if err := json.Unmarshal([]byte(setting.Value), &settings); err != nil {
				log.Printf("Failed to parse audit log settings: %v", err)
				newProtocols = getDefaultAuditLogProtocols()
			} else {
				newProtocols = settings.EnabledProtocols
			}
		}
	}

	// Update cache with write lock
	auditLogProtocolCache.lock.Lock()
	auditLogProtocolCache.protocols = newProtocols
	auditLogProtocolCache.lastUpdate = time.Now()
	auditLogProtocolCache.loading = false
	auditLogProtocolCache.lock.Unlock()

	return newProtocols
}

// getDefaultAuditLogProtocols returns default enabled protocols
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

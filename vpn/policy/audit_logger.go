package policy

import (
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
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

// inferApplicationProtocol infers application layer protocol from network protocol and port
// For TCP/UDP: infers application protocol from destination port (e.g., 80 -> http, 443 -> https)
// For ICMP and other protocols: returns network protocol as-is (e.g., "icmp")
func inferApplicationProtocol(netProtocol string, dstPort uint16) string {
	// If not TCP or UDP (e.g., ICMP), return network protocol as-is
	// ICMP doesn't have ports, so we can't infer application protocol from port
	if netProtocol != "tcp" && netProtocol != "udp" {
		return netProtocol
	}

	// Common port mappings for application protocols
	switch dstPort {
	case 20, 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		if netProtocol == "udp" {
			return "dns"
		}
		return netProtocol // TCP DNS is less common
	case 67, 68:
		return "dhcp"
	case 69:
		return "tftp"
	case 80:
		return "http"
	case 443:
		return "https"
	case 8080:
		return "http-alt"
	case 8443:
		return "https-alt"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 27017:
		return "mongodb"
	case 3389:
		return "rdp"
	case 5900:
		return "vnc"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 389:
		return "ldap"
	case 636:
		return "ldaps"
	case 143:
		return "imap"
	case 993:
		return "imaps"
	case 110:
		return "pop3"
	case 995:
		return "pop3s"
	case 9092:
		return "kafka"
	case 9200:
		return "elasticsearch"
	case 9300:
		return "elasticsearch-cluster"
	case 2181:
		return "zookeeper"
	case 9042:
		return "cassandra"
	case 7000, 7001:
		return "cassandra-cluster"
	case 27018:
		return "mongodb-shard"
	case 5984:
		return "couchdb"
	case 11211:
		return "memcached"
	case 5672:
		return "amqp"
	case 15672:
		return "rabbitmq-management"
	case 5671:
		return "amqps"
	case 1883:
		return "mqtt"
	case 8883:
		return "mqtts"
	case 2379, 2380:
		return "etcd"
	case 10250:
		return "kubelet"
	case 6443:
		return "kubernetes-api"
	default:
		// Return network protocol if no application protocol can be inferred
		return netProtocol
	}
}

// LogAccess logs a resource access event
func (al *AuditLogger) LogAccess(ctx *Context, hook Hook, action Action, result string, reason string) {
	if !al.IsEnabled() {
		return
	}

	// ctx.Protocol may already be inferred in protocol.go, but ensure it's set
	// If ctx.Protocol is empty or still network layer, infer from port
	protocol := ctx.Protocol
	if protocol == "" {
		// If empty, default to tcp for inference
		if ctx.DstPort > 0 {
			protocol = inferApplicationProtocol("tcp", ctx.DstPort)
		} else {
			protocol = "tcp"
		}
	} else if protocol == "tcp" || protocol == "udp" {
		// Still network layer, infer application protocol from destination port
		protocol = inferApplicationProtocol(protocol, ctx.DstPort)
	}
	// If protocol is already an application protocol (http, https, ssh, etc.), use it as-is

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

	// Ensure protocol is inferred if still network layer or empty
	protocol := ctx.Protocol
	if protocol == "" {
		if ctx.DstPort > 0 {
			protocol = inferApplicationProtocol("tcp", ctx.DstPort)
		} else {
			protocol = "tcp"
		}
	} else if protocol == "tcp" || protocol == "udp" {
		protocol = inferApplicationProtocol(protocol, ctx.DstPort)
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
	// Most auth events are over HTTPS (443) or HTTP (80) for web-based auth
	protocol := ""
	if sourcePort > 0 {
		protocol = inferApplicationProtocol("tcp", sourcePort)
	} else {
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

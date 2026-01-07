//go:build ebpf
// +build ebpf

package ebpf

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"gorm.io/gorm"
)


// PolicyEvent represents a policy match event from eBPF (both ALLOW and DENY)
type PolicyEvent struct {
	PolicyID  uint32
	Action    uint32 // POLICY_ACTION_ALLOW, DENY, etc.
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Timestamp uint32
}

// auditLogBuffer is a simple buffer for audit logs
type auditLogBuffer struct {
	buffer  []models.AuditLog
	lock    sync.Mutex
	bufSize int
}

var globalAuditBuffer = &auditLogBuffer{
	buffer:  make([]models.AuditLog, 0, 100),
	bufSize: 100,
}

// auditLogProtocolCache for eBPF package
var ebpfAuditLogProtocolCache struct {
	protocols  map[string]bool
	lastUpdate time.Time
	lock       sync.RWMutex
	loading    bool // Flag to prevent concurrent DB queries
}

const ebpfAuditLogSettingKey = "audit_log_settings"
const ebpfAuditLogCacheTTL = 5 * time.Minute // Cache for 5 minutes to reduce DB queries

// flushAuditBuffer flushes buffered audit logs to database
func (b *auditLogBuffer) flush() error {
	b.lock.Lock()
	defer b.lock.Unlock()

	if len(b.buffer) == 0 {
		return nil
	}

	// Batch insert
	if err := database.DB.CreateInBatches(b.buffer, 100).Error; err != nil {
		log.Printf("Failed to write audit logs: %v", err)
		return err
	}

	// Clear buffer
	b.buffer = b.buffer[:0]
	return nil
}

// addAuditLog adds an audit log to the buffer
func (b *auditLogBuffer) addLog(log models.AuditLog) {
	b.lock.Lock()
	b.buffer = append(b.buffer, log)
	bufLen := len(b.buffer)
	b.lock.Unlock()

	// Flush buffer when it reaches threshold
	if bufLen >= b.bufSize {
		b.flush()
	}
}

// StartAuditLogger starts a goroutine to monitor eBPF policy events and log them
func StartAuditLogger(xdpProgram *XDPProgram) {
	if xdpProgram == nil || xdpProgram.policyEvents == nil {
		return
	}

	go func() {
		ticker := time.NewTicker(1 * time.Second) // Check every second
		defer ticker.Stop()

		// Start periodic flush
		flushTicker := time.NewTicker(10 * time.Second)
		defer flushTicker.Stop()

		go func() {
			for range flushTicker.C {
				globalAuditBuffer.flush()
			}
		}()

		for range ticker.C {
			// Read policy events from eBPF queue (BPF_MAP_TYPE_QUEUE uses Pop operation)
			for {
				var event PolicyEvent
				// For BPF_MAP_TYPE_QUEUE, we use LookupAndDelete to get and remove the first element
				// The key parameter is ignored for queue maps
				if err := xdpProgram.policyEvents.LookupAndDelete(nil, &event); err != nil {
					// No more events or error (queue is empty)
					break
				}

				// Convert event to audit log
				if err := logPolicyEvent(&event); err != nil {
					log.Printf("Failed to log eBPF policy event: %v", err)
				}
			}
		}
	}()
	log.Println("eBPF audit logger started (logging all policy events including ALLOW)")
}

// logPolicyEvent logs a policy event from eBPF as an audit log (both ALLOW and DENY)
func logPolicyEvent(event *PolicyEvent) error {
	// Convert IPs (using uint32ToIP from loader_ebpf.go)
	srcIP := uint32ToIP(event.SrcIP)
	dstIP := uint32ToIP(event.DstIP)

	// Determine network layer protocol string
	netProtocolStr := "unknown"
	switch event.Protocol {
	case 6: // IPPROTO_TCP
		netProtocolStr = "tcp"
	case 17: // IPPROTO_UDP
		netProtocolStr = "udp"
	case 1: // IPPROTO_ICMP
		netProtocolStr = "icmp"
	}

	// Use network protocol directly (tcp/udp/icmp) with port number
	protocolStr := netProtocolStr

	// 根据设置决定是否记录该协议的日志
	if !shouldLogProtocolForEBPF(protocolStr, event.DstPort) {
		return nil
	}

	// Determine action and result based on event action
	// POLICY_ACTION_ALLOW = 0, POLICY_ACTION_DENY = 1, POLICY_ACTION_REDIRECT = 2
	var auditAction models.AuditLogAction
	var result string
	var reason string

	switch event.Action {
	case 0: // POLICY_ACTION_ALLOW
		auditAction = models.AuditLogActionAllow
		result = "allowed"
		reason = "Access allowed by eBPF policy"
	case 1: // POLICY_ACTION_DENY
		auditAction = models.AuditLogActionDeny
		result = "blocked"
		reason = "Packet dropped by eBPF policy"
	case 2: // POLICY_ACTION_REDIRECT
		auditAction = models.AuditLogActionAllow // Redirect is treated as allow
		result = "redirected"
		reason = "Traffic redirected by eBPF policy"
	default:
		auditAction = models.AuditLogActionAllow
		result = "allowed"
		reason = "Policy matched by eBPF"
	}

	// Try to find user ID from VPN IP mapping
	// This is approximate - we need to check vpn_clients map
	// For now, we'll log with user_id = 0 and try to find it later
	userID := uint(0)

	// Create audit log entry
	auditLog := models.AuditLog{
		UserID:          userID,
		Type:            models.AuditLogTypeAccess,
		Action:          auditAction,
		SourceIP:        srcIP.String(),
		DestinationIP:   dstIP.String(),
		SourcePort:      event.SrcPort,
		DestinationPort: event.DstPort,
		Protocol:        protocolStr,
		ResourceType:    "network",
		ResourcePath:    dstIP.String(),
		HookID:          fmt.Sprintf("ebpf-policy-%d", event.PolicyID),
		HookName:        fmt.Sprintf("eBPF Policy %d", event.PolicyID),
		Result:          result,
		Reason:          reason,
	}

	// Try to find username from VPN IP (async)
	go func() {
		// Try to find user by VPN IP
		// This requires checking vpn_clients map or querying database
		// For now, we'll query database for users with matching VPN IP
		var users []models.User
		if err := database.DB.Where("vpn_ip = ?", srcIP.String()).Find(&users).Error; err == nil && len(users) > 0 {
			auditLog.UserID = users[0].ID
			auditLog.Username = users[0].Username
		}

		globalAuditBuffer.addLog(auditLog)
	}()

	return nil
}

// shouldLogProtocolForEBPF checks if a protocol should be logged based on settings (eBPF version)
func shouldLogProtocolForEBPF(protocol string, dstPort uint16) bool {
	// Get enabled protocols from cache or DB
	enabledProtocols := getEnabledAuditLogProtocolsForEBPF()

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

// ClearEBPFAuditLogProtocolCache clears the cache to force reload on next access
// This should be called when settings are updated
func ClearEBPFAuditLogProtocolCache() {
	ebpfAuditLogProtocolCache.lock.Lock()
	defer ebpfAuditLogProtocolCache.lock.Unlock()
	ebpfAuditLogProtocolCache.protocols = nil
	ebpfAuditLogProtocolCache.lastUpdate = time.Time{} // Reset to zero time
	ebpfAuditLogProtocolCache.loading = false
}

// getEnabledAuditLogProtocolsForEBPF returns the map of enabled protocols (eBPF version)
func getEnabledAuditLogProtocolsForEBPF() map[string]bool {
	ebpfAuditLogProtocolCache.lock.RLock()
	// Check if cache is still valid
	if time.Since(ebpfAuditLogProtocolCache.lastUpdate) < ebpfAuditLogCacheTTL && ebpfAuditLogProtocolCache.protocols != nil {
		protocols := ebpfAuditLogProtocolCache.protocols
		ebpfAuditLogProtocolCache.lock.RUnlock()
		return protocols
	}
	ebpfAuditLogProtocolCache.lock.RUnlock()

	// Cache expired or not set, reload from DB
	ebpfAuditLogProtocolCache.lock.Lock()

	// Double check after acquiring write lock
	if time.Since(ebpfAuditLogProtocolCache.lastUpdate) < ebpfAuditLogCacheTTL && ebpfAuditLogProtocolCache.protocols != nil {
		protocols := ebpfAuditLogProtocolCache.protocols
		ebpfAuditLogProtocolCache.lock.Unlock()
		return protocols
	}

	// Prevent concurrent DB queries - if another goroutine is already loading, wait and return current cache
	if ebpfAuditLogProtocolCache.loading {
		// Another goroutine is loading, return current cache or defaults
		if ebpfAuditLogProtocolCache.protocols != nil {
			protocols := ebpfAuditLogProtocolCache.protocols
			ebpfAuditLogProtocolCache.lock.Unlock()
			return protocols
		}
		protocols := getDefaultAuditLogProtocolsForEBPF()
		ebpfAuditLogProtocolCache.lock.Unlock()
		return protocols
	}

	// Mark as loading
	ebpfAuditLogProtocolCache.loading = true
	ebpfAuditLogProtocolCache.lock.Unlock()

	// Load from DB (without holding lock to avoid blocking)
	// Check if database is initialized
	var newProtocols map[string]bool
	if database.DB == nil {
		// Database not initialized yet, use defaults
		log.Printf("Database not initialized, using default audit log protocols")
		newProtocols = getDefaultAuditLogProtocolsForEBPF()
	} else {
		var setting models.SystemSetting
		err := database.DB.Where("`key` = ?", ebpfAuditLogSettingKey).First(&setting).Error

		if err != nil {
			if err == gorm.ErrRecordNotFound {
				// Use defaults
				newProtocols = getDefaultAuditLogProtocolsForEBPF()
			} else {
				log.Printf("Failed to load audit log settings: %v", err)
				// Use defaults on error
				newProtocols = getDefaultAuditLogProtocolsForEBPF()
			}
		} else {
			// Parse JSON
			var settings struct {
				EnabledProtocols map[string]bool `json:"enabled_protocols"`
			}
			if err := json.Unmarshal([]byte(setting.Value), &settings); err != nil {
				log.Printf("Failed to parse audit log settings: %v", err)
				newProtocols = getDefaultAuditLogProtocolsForEBPF()
			} else {
				newProtocols = settings.EnabledProtocols
			}
		}
	}

	// Update cache with write lock
	ebpfAuditLogProtocolCache.lock.Lock()
	ebpfAuditLogProtocolCache.protocols = newProtocols
	ebpfAuditLogProtocolCache.lastUpdate = time.Now()
	ebpfAuditLogProtocolCache.loading = false
	ebpfAuditLogProtocolCache.lock.Unlock()

	return newProtocols
}

// getDefaultAuditLogProtocolsForEBPF returns default enabled protocols (eBPF version)
func getDefaultAuditLogProtocolsForEBPF() map[string]bool {
	return map[string]bool{
		"tcp":   true,
		"udp":   true,
		"http":  true,
		"https": true,
		"ssh":   false,
		"ftp":   false,
		"smtp":  false,
		"mysql": false,
		"dns":   false, // DNS queries are too frequent
		"icmp":  false, // ICMP (ping) is too frequent
	}
}

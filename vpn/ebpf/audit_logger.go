//go:build ebpf
// +build ebpf

package ebpf

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
)

// inferApplicationProtocol infers application layer protocol from network protocol and port
func inferApplicationProtocol(netProtocol string, dstPort uint16) string {
	// If not TCP or UDP, return network protocol as-is
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

	// Infer application layer protocol from destination port
	protocolStr := inferApplicationProtocol(netProtocolStr, event.DstPort)

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

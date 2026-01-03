package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

type AuditLogType string

const (
	AuditLogTypeAccess    AuditLogType = "access"    // 访问资源
	AuditLogTypePolicy    AuditLogType = "policy"    // 策略执行
	AuditLogTypeAuth      AuditLogType = "auth"      // 认证相关
	AuditLogTypeConfig    AuditLogType = "config"    // 配置变更
	AuditLogTypeHook      AuditLogType = "hook"      // Hook执行
)

type AuditLogAction string

const (
	AuditLogActionAllow   AuditLogAction = "allow"   // 允许
	AuditLogActionDeny    AuditLogAction = "deny"    // 拒绝
	AuditLogActionLog     AuditLogAction = "log"     // 记录
	AuditLogActionConnect AuditLogAction = "connect"  // 连接
	AuditLogActionDisconnect AuditLogAction = "disconnect" // 断开
	AuditLogActionLogin    AuditLogAction = "login"   // 登录
	AuditLogActionLogout   AuditLogAction = "logout"  // 登出
)

type AuditLog struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	UserID   uint   `gorm:"index" json:"user_id"`
	Username string `gorm:"size:255" json:"username"` // 冗余字段，便于查询

	Type        AuditLogType   `gorm:"not null;size:50;index" json:"type"`
	Action      AuditLogAction `gorm:"not null;size:50;index" json:"action"`
	SourceIP    string         `gorm:"size:45;index" json:"source_ip"`      // IPv4/IPv6
	DestinationIP string       `gorm:"size:45;index" json:"destination_ip"` // IPv4/IPv6
	SourcePort    uint16       `json:"source_port"`
	DestinationPort uint16      `json:"destination_port"`
	Protocol      string       `gorm:"size:20" json:"protocol"` // tcp, udp, icmp, etc.

	ResourceType string `gorm:"size:100" json:"resource_type"` // 资源类型：url, ip, port, etc.
	ResourcePath string `gorm:"type:text" json:"resource_path"` // 资源路径或标识
	Domain       string `gorm:"size:255;index" json:"domain,omitempty"` // 域名（用于域名动态拆分隧道）

	HookID      string `gorm:"size:255;index" json:"hook_id,omitempty"`      // 关联的Hook ID
	HookName    string `gorm:"size:255" json:"hook_name,omitempty"`          // Hook名称
	PolicyID    uint   `gorm:"index" json:"policy_id,omitempty"`            // 关联的策略ID
	PolicyName  string `gorm:"size:255" json:"policy_name,omitempty"`        // 策略名称

	Result      string `gorm:"size:50" json:"result"`        // 结果：success, failed, blocked
	Reason      string `gorm:"type:text" json:"reason,omitempty"` // 原因说明
	BytesSent   uint64 `json:"bytes_sent,omitempty"`        // 发送字节数
	BytesReceived uint64 `json:"bytes_received,omitempty"`  // 接收字节数

	Metadata AuditLogMetadata `gorm:"type:json" json:"metadata,omitempty"` // 额外元数据
}

type AuditLogMetadata map[string]interface{}

func (m *AuditLogMetadata) Scan(value interface{}) error {
	if value == nil {
		*m = make(AuditLogMetadata)
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}

	return json.Unmarshal(bytes, m)
}

func (m AuditLogMetadata) Value() (driver.Value, error) {
	if len(m) == 0 {
		return "{}", nil
	}
	return json.Marshal(m)
}

func (AuditLog) TableName() string {
	return "audit_logs"
}


package models

import (
	"time"

	"gorm.io/gorm"
)

// Domain 存储域名配置，用于域名动态拆分隧道
type Domain struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Domain      string `gorm:"uniqueIndex;not null;size:255" json:"domain"` // 域名，支持通配符如 *.example.com
	PolicyID    *uint  `gorm:"index" json:"policy_id"`                      // 关联的策略ID（可选）
	AutoResolve bool   `gorm:"default:true" json:"auto_resolve"`            // 是否自动解析

	// IP配置
	ManualIPs   string `gorm:"type:text" json:"-"`              // 手动配置的IP地址列表（JSON格式），用于内网域名等场景
	Resolved   bool      `gorm:"default:false" json:"resolved"`   // 是否已解析
	ResolvedAt *time.Time `json:"resolved_at"`                     // 最后解析时间
	IPs        string    `gorm:"type:text" json:"-"`              // 自动解析的IP地址列表（JSON格式）

	// 统计信息
	AccessCount uint64     `gorm:"default:0" json:"access_count"` // 访问次数
	LastUsed    *time.Time `json:"last_used"`                     // 最后使用时间

	// Relations
	Policy *Policy `gorm:"foreignKey:PolicyID" json:"policy,omitempty"`
}


package models

import (
	"time"

	"gorm.io/gorm"
)

// LDAPConfig LDAP配置模型（单例模式，只存储一条记录）
type LDAPConfig struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Enabled       bool   `gorm:"default:false" json:"enabled"`
	Host          string `gorm:"size:255" json:"host"`
	Port          int    `gorm:"default:389" json:"port"`
	UseSSL        bool   `gorm:"default:false" json:"use_ssl"`
	BindDN        string `gorm:"type:text" json:"bind_dn"`
	BindPassword  string `gorm:"type:text" json:"bind_password"` // 加密存储
	BaseDN        string `gorm:"type:text" json:"base_dn"`
	UserFilter    string `gorm:"type:text" json:"user_filter"` // 例如: (uid=%s) 或 (sAMAccountName=%s)
	AdminGroup    string `gorm:"type:text" json:"admin_group"`
	SkipTLSVerify bool   `gorm:"default:false" json:"skip_tls_verify"`
}


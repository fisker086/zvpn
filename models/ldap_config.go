package models

import (
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

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

	AttributeMapping string `gorm:"type:text" json:"attribute_mapping"` // JSON格式的属性映射
}

type LDAPAttributeMapping struct {
	UsernameAttribute string `json:"username"`  // 用户名属性，例如: "uid", "sAMAccountName", "cn"
	EmailAttribute    string `json:"email"`     // 邮箱属性，例如: "mail", "email"
	FullNameAttribute string `json:"full_name"` // 全名属性，例如: "displayName", "cn", "name"
	MemberOfAttribute string `json:"member_of"` // 组成员属性，例如: "memberOf", "groupMembership"
}

func (c *LDAPConfig) GetAttributeMapping() LDAPAttributeMapping {
	mapping := LDAPAttributeMapping{
		UsernameAttribute: "", // 从UserFilter推断
		EmailAttribute:    "mail",
		FullNameAttribute: "displayName",
		MemberOfAttribute: "memberOf",
	}

	if c.AttributeMapping != "" {
		if err := json.Unmarshal([]byte(c.AttributeMapping), &mapping); err == nil {
			if mapping.EmailAttribute == "" {
				mapping.EmailAttribute = "mail"
			}
			if mapping.FullNameAttribute == "" {
				mapping.FullNameAttribute = "displayName"
			}
			if mapping.MemberOfAttribute == "" {
				mapping.MemberOfAttribute = "memberOf"
			}
		}
	}

	return mapping
}

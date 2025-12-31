package models

import (
	"time"
)

// UserGroup 用户组模型
type UserGroup struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Name        string `gorm:"uniqueIndex;not null;size:255" json:"name"`
	Description string `json:"description"`

	// AllowLan 允许本地网络访问（类似 anylink 的 allow_lan 配置）
	// 如果启用，本地网络流量不走 VPN 隧道，即使是在全局模式下
	// 这可以确保 VPN 断开后不影响客户端本地网络访问
	AllowLan bool `gorm:"default:false" json:"allow_lan"`

	// Relations
	Users    []User   `gorm:"many2many:user_group_users;" json:"users,omitempty"`
	Policies []Policy `gorm:"many2many:user_group_policies;" json:"policies,omitempty"`
}

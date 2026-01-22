package models

import (
	"time"

	"gorm.io/gorm"
)

type Policy struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Name        string `gorm:"uniqueIndex;not null;size:255" json:"name"`
	Description string `json:"description"`

	AllowedNetworks []AllowedNetwork `gorm:"foreignKey:PolicyID" json:"allowed_networks"`
	Routes          []Route          `gorm:"foreignKey:PolicyID" json:"routes"`
	ExcludeRoutes   []ExcludeRoute   `gorm:"foreignKey:PolicyID" json:"exclude_routes"` // 排除路由（用于全局模式）

	MaxBandwidth int64 `json:"max_bandwidth"` // 0 means unlimited

	DNSServers string `gorm:"type:text" json:"dns_servers"` // JSON array of DNS server IPs, e.g. ["8.8.8.8","8.8.4.4"]

	SplitDNS   string `gorm:"type:text" json:"split_dns"`   // JSON array of domains for split DNS, e.g. ["example.com","*.example.com"]

	TimeRestrictions []TimeRestriction `gorm:"foreignKey:PolicyID" json:"time_restrictions"`

	Groups []UserGroup `gorm:"many2many:user_group_policies;" json:"groups,omitempty"`
}

type AllowedNetwork struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	PolicyID uint   `gorm:"not null" json:"policy_id"`
	Network  string `gorm:"not null" json:"network"` // CIDR format
}

type Route struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	PolicyID uint   `gorm:"not null" json:"policy_id"`
	Network  string `gorm:"not null" json:"network"` // CIDR format
	Gateway  string `json:"gateway"`                 // Optional gateway
	Metric   int    `gorm:"default:100" json:"metric"`
}

type ExcludeRoute struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	PolicyID uint   `gorm:"not null" json:"policy_id"`
	Network  string `gorm:"not null" json:"network"` // CIDR format
}

type TimeRestriction struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	PolicyID  uint   `gorm:"not null" json:"policy_id"`
	DayOfWeek int    `gorm:"not null" json:"day_of_week"` // 0-6, Sunday=0
	StartTime string `gorm:"not null" json:"start_time"`  // HH:MM format
	EndTime   string `gorm:"not null" json:"end_time"`    // HH:MM format
}

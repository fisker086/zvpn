package models

import (
	"time"

	"gorm.io/gorm"
)

type Session struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	UserID    uint      `gorm:"not null;index" json:"user_id"`
	User      User      `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Token     string    `gorm:"uniqueIndex;not null;size:255" json:"token"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	ExpiresAt time.Time `gorm:"not null;index" json:"expires_at"`
	Active    bool      `gorm:"default:true" json:"active"`
}

func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

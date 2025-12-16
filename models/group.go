package models

import (
	"time"

	"gorm.io/gorm"
)

// UserGroup 用户组模型
type UserGroup struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name        string `gorm:"uniqueIndex;not null;size:255" json:"name"`
	Description string `json:"description"`

	// Relations
	Users    []User   `gorm:"many2many:user_group_users;" json:"users,omitempty"`
	Policies []Policy `gorm:"many2many:user_group_policies;" json:"policies,omitempty"`
}

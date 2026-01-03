package models

import (
	"time"
)

type UserGroup struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Name        string `gorm:"uniqueIndex;not null;size:255" json:"name"`
	Description string `json:"description"`

	AllowLan bool `gorm:"default:false" json:"allow_lan"`

	Users    []User   `gorm:"many2many:user_group_users;" json:"users,omitempty"`
	Policies []Policy `gorm:"many2many:user_group_policies;" json:"policies,omitempty"`
}

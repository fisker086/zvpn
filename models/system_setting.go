package models

import "time"

type SystemSetting struct {
	Key       string    `gorm:"primaryKey;size:100;column:key" json:"key"`
	Value     string    `gorm:"type:text" json:"value"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (SystemSetting) TableName() string {
	return "system_settings"
}

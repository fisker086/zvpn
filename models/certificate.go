package models

import (
	"time"

	"gorm.io/gorm"
)

type Certificate struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	SNI        string `gorm:"uniqueIndex;not null;size:255" json:"sni"`        // SNI 域名（唯一索引）
	CertData   []byte `gorm:"type:longtext;not null" json:"-"`                 // 证书内容（PEM格式，不返回给前端）
	KeyData    []byte `gorm:"type:longtext;not null" json:"-"`                 // 私钥内容（PEM格式，不返回给前端）
	CommonName string `gorm:"size:255" json:"common_name"`                     // 证书 CN
	DNSNames   string `gorm:"type:text" json:"dns_names"`                     // DNS 名称列表（JSON格式）
	Issuer     string `gorm:"size:255" json:"issuer"`                          // 颁发者
	NotBefore  time.Time `json:"not_before"`                                   // 有效期开始
	NotAfter   time.Time `json:"not_after"`                                    // 有效期结束
	IsActive   bool     `gorm:"default:true" json:"is_active"`                  // 是否启用
	Description string `gorm:"size:500" json:"description"`                    // 描述信息
}

func (Certificate) TableName() string {
	return "certificates"
}



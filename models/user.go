package models

import (
	"log"
	"time"

	"github.com/fisker/zvpn/auth"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Username     string `gorm:"uniqueIndex;not null;size:255" json:"username"`
	PasswordHash string `gorm:"not null" json:"-"`
	Email        string `gorm:"uniqueIndex;size:255" json:"email"`
	IsAdmin      bool   `gorm:"default:false" json:"is_admin"`
	IsActive     bool   `gorm:"default:true" json:"is_active"`

	// VPN related
	VPNIP     string     `json:"vpn_ip"`    // Assigned VPN IP
	ClientIP  string     `json:"client_ip"` // Client's real IP
	Connected bool       `gorm:"default:false" json:"connected"`
	LastSeen  *time.Time `json:"last_seen"`

	// OTP related
	OTPSecret  string `gorm:"size:255" json:"-"`        // OTP密钥（不返回给API）
	OTPEnabled bool   `gorm:"default:false" json:"otp_enabled"` // OTP是否启用

	// Relations - 用户必须属于至少一个用户组
	Groups []UserGroup `gorm:"many2many:user_group_users;" json:"groups,omitempty"`

	// 内部字段：策略通过用户组获取，仅用于VPN服务器内部逻辑，不返回给API
	PolicyID uint   `gorm:"-" json:"-"` // 内部使用，不返回给API
	Policy   Policy `gorm:"-" json:"-"` // 内部使用，不返回给API
}

// GetPolicy 从用户组获取合并后的策略（合并所有组的所有策略的路由）
func (u *User) GetPolicy() *Policy {
	log.Printf("User.GetPolicy: 开始获取用户 %v 的策略", u.Username)
	log.Printf("User.GetPolicy: 用户所在组数量: %d", len(u.Groups))

	if len(u.Groups) == 0 {
		log.Printf("User.GetPolicy: 用户没有任何组，返回nil")
		return nil
	}

	// 创建一个新的合并策略
	mergedPolicy := &Policy{
		Routes: []Route{},
	}

	// 合并所有用户组的所有策略的路由
	routeMap := make(map[string]bool) // 用于去重
	// 存储所有策略ID，用于后续设置合并策略的ID
	var policyIDs []uint

	for groupIndex, group := range u.Groups {
		log.Printf("User.GetPolicy: 处理组 %d (ID: %d)", groupIndex+1, group.ID)
		log.Printf("User.GetPolicy: 组 %d 的策略数量: %d", groupIndex+1, len(group.Policies))

		for policyIndex, policy := range group.Policies {
			log.Printf("User.GetPolicy: 处理组 %d 的策略 %d (ID: %d)", groupIndex+1, policyIndex+1, policy.ID)
			log.Printf("User.GetPolicy: 策略 %d 的路由数量: %d", policyIndex+1, len(policy.Routes))

			// 收集所有策略ID
			policyIDs = append(policyIDs, policy.ID)
			for routeIndex, route := range policy.Routes {
				log.Printf("User.GetPolicy: 策略 %d 的路由 %d: %s", policyIndex+1, routeIndex+1, route.Network)
				// 去重路由
				if !routeMap[route.Network] {
					log.Printf("User.GetPolicy: 添加新路由: %s", route.Network)
					mergedPolicy.Routes = append(mergedPolicy.Routes, route)
					routeMap[route.Network] = true
				} else {
					log.Printf("User.GetPolicy: 跳过重复路由: %s", route.Network)
				}
			}
		}
	}

	log.Printf("User.GetPolicy: 合并后策略路由数量: %d", len(mergedPolicy.Routes))

	// 如果没有路由，返回nil
	if len(mergedPolicy.Routes) == 0 {
		log.Printf("User.GetPolicy: 合并后没有路由，返回nil")
		return nil
	}

	// 如果有策略ID，使用第一个策略的ID作为合并策略的ID
	if len(policyIDs) > 0 {
		mergedPolicy.ID = policyIDs[0]
		log.Printf("User.GetPolicy: 设置合并策略ID为 %d (第一个策略ID)", mergedPolicy.ID)
	}

	log.Printf("User.GetPolicy: 返回合并后的策略，ID: %d，路由数量: %d", mergedPolicy.ID, len(mergedPolicy.Routes))
	return mergedPolicy
}

// GetPolicyID 获取策略ID（从用户组）
func (u *User) GetPolicyID() uint {
	policy := u.GetPolicy()
	if policy != nil {
		return policy.ID
	}
	return 0
}

func (u *User) SetPassword(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hash)
	return nil
}

func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}

// CheckPasswordWithOTP 检查密码和OTP（如果启用了OTP）
// password参数可能是纯密码，也可能是"密码+OTP代码"的格式
// OpenConnect协议：如果启用了OTP，密码格式为"密码+OTP代码"（OTP代码是6位数字，追加在密码后面）
func (u *User) CheckPasswordWithOTP(password string) bool {
	// 如果启用了OTP，需要从password中提取密码和OTP代码
	if u.OTPEnabled && u.OTPSecret != "" {
		// OpenConnect协议：密码格式为"密码+OTP代码"
		// OTP代码通常是6位数字，从末尾提取
		if len(password) < 7 {
			// 密码太短，无法包含OTP（至少需要1位密码+6位OTP）
			// 先尝试只验证密码，如果失败则返回false
			return false
		}

		// 提取最后6位作为OTP代码
		otpCode := password[len(password)-6:]
		actualPassword := password[:len(password)-6]

		// 验证OTP代码格式（应该是6位数字）
		if len(otpCode) != 6 {
			return false
		}
		for _, c := range otpCode {
			if c < '0' || c > '9' {
				return false // OTP代码必须全是数字
			}
		}

		// 验证密码
		if !u.CheckPassword(actualPassword) {
			return false
		}

		// 验证OTP代码
		otpAuth := auth.NewOTPAuthenticator("ZVPN")
		return otpAuth.ValidateOTP(u.OTPSecret, otpCode)
	}

	// 未启用OTP，只验证密码
	return u.CheckPassword(password)
}

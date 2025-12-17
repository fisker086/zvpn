package models

import (
	"encoding/json"
	"log"
	"time"

	"github.com/fisker/zvpn/auth"
	"golang.org/x/crypto/bcrypt"
)

// 用户来源常量
const (
	UserSourceSystem = "system" // 系统账户
	UserSourceLDAP   = "ldap"   // LDAP用户
)

type User struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Username     string `gorm:"uniqueIndex;not null;size:255" json:"username"`
	PasswordHash string `gorm:"size:255" json:"-"` // LDAP用户可以为空（认证由LDAP服务器完成），系统用户必须设置
	Email        string `gorm:"uniqueIndex;size:255" json:"email"`
	IsAdmin      bool   `gorm:"default:false" json:"is_admin"`
	IsActive     bool   `gorm:"default:true" json:"is_active"`

	// 用户来源：system（系统账户）或 ldap（LDAP用户）
	Source string `gorm:"default:'system';size:20;index" json:"source"` // system 或 ldap

	// LDAP related fields
	LDAPDN         string `gorm:"size:512" json:"ldap_dn"`   // LDAP Distinguished Name
	FullName       string `gorm:"size:255" json:"full_name"` // 全名/中文名 (displayName/cn)
	LDAPAttributes string `gorm:"type:text" json:"-"`        // LDAP原始属性JSON（不返回给API，用于扩展）

	// VPN related
	VPNIP     string     `gorm:"size:50" json:"-"`    // Assigned VPN IP (不返回给前端API，在线用户接口单独返回)
	ClientIP  string     `gorm:"size:50" json:"-"`    // Client's real IP (不返回给前端API)
	Connected bool       `gorm:"default:false" json:"connected"`
	LastSeen  *time.Time `json:"last_seen"`

	// OTP related
	OTPSecret  string `gorm:"size:255" json:"-"`                // OTP密钥（不返回给API）
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

// SetPassword 设置密码（仅系统账户需要）
func (u *User) SetPassword(password string) error {
	// LDAP用户不需要设置密码（认证由LDAP服务器完成）
	if u.Source == UserSourceLDAP {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hash)
	return nil
}

// CheckPassword 检查密码（仅系统账户需要）
func (u *User) CheckPassword(password string) bool {
	// LDAP用户不需要检查密码（认证由LDAP服务器完成）
	if u.Source == UserSourceLDAP {
		return false
	}
	// 系统账户必须设置密码
	if u.PasswordHash == "" {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}

// SetLDAPAttributes 设置LDAP原始属性（从map序列化为JSON字符串）
func (u *User) SetLDAPAttributes(attributes map[string][]string) error {
	if len(attributes) == 0 {
		u.LDAPAttributes = ""
		return nil
	}
	attrsJSON, err := json.Marshal(attributes)
	if err != nil {
		return err
	}
	u.LDAPAttributes = string(attrsJSON)
	return nil
}

// GetLDAPAttributes 获取LDAP原始属性（从JSON字符串反序列化为map）
// 返回格式：map[string]interface{}，其中值可以是string（单值属性）或[]string（多值属性）
func (u *User) GetLDAPAttributes() (map[string]interface{}, error) {
	if u.LDAPAttributes == "" {
		return nil, nil
	}
	var attributes map[string]interface{}
	err := json.Unmarshal([]byte(u.LDAPAttributes), &attributes)
	if err != nil {
		return nil, err
	}
	return attributes, nil
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

// CheckOTPOnly 仅验证OTP代码（不验证密码）
// 用于LDAP用户启用OTP的情况，因为LDAP用户的密码存储在LDAP服务器中，本地数据库没有密码
// password参数应该是"密码+OTP代码"的格式，但这里只提取并验证OTP代码部分
func (u *User) CheckOTPOnly(password string) bool {
	if !u.OTPEnabled || u.OTPSecret == "" {
		return false // 未启用OTP
	}

	// OpenConnect协议：密码格式为"密码+OTP代码"
	// OTP代码通常是6位数字，从末尾提取
	if len(password) < 6 {
		return false // 密码太短，无法包含OTP
	}

	// 提取最后6位作为OTP代码
	otpCode := password[len(password)-6:]

	// 验证OTP代码格式（应该是6位数字）
	if len(otpCode) != 6 {
		return false
	}
	for _, c := range otpCode {
		if c < '0' || c > '9' {
			return false // OTP代码必须全是数字
		}
	}

	// 验证OTP代码
	otpAuth := auth.NewOTPAuthenticator("ZVPN")
	return otpAuth.ValidateOTP(u.OTPSecret, otpCode)
}

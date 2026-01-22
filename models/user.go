package models

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/fisker/zvpn/auth"
	"golang.org/x/crypto/bcrypt"
)

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

	Source string `gorm:"default:'system';size:20;index" json:"source"` // system 或 ldap

	LDAPDN         string `gorm:"size:512" json:"ldap_dn"`   // LDAP Distinguished Name
	FullName       string `gorm:"size:255" json:"full_name"` // 全名/中文名 (displayName/cn)
	LDAPAttributes string `gorm:"type:text" json:"-"`        // LDAP原始属性JSON（不返回给API，用于扩展）

	VPNIP      string     `gorm:"size:50" json:"-"` // Assigned VPN IP (不返回给前端API，在线用户接口单独返回)
	ClientIP   string     `gorm:"size:50" json:"-"` // Client's real IP (不返回给前端API)
	Connected  bool       `gorm:"default:false" json:"connected"`
	LastSeen   *time.Time `json:"last_seen"`
	TunnelMode string     `gorm:"default:'split';size:20" json:"tunnel_mode"` // 隧道模式: split(分隧道) 或 full(全局)

	OTPSecret  string `gorm:"size:255" json:"-"`                // OTP密钥（不返回给API）
	OTPEnabled bool   `gorm:"default:false" json:"otp_enabled"` // OTP是否启用

	Groups []UserGroup `gorm:"many2many:user_group_users;" json:"groups,omitempty"`

	PolicyID uint   `gorm:"-" json:"-"` // 内部使用，不返回给API
	Policy   Policy `gorm:"-" json:"-"` // 内部使用，不返回给API
}

func (u *User) GetPolicy() *Policy {
	log.Printf("User.GetPolicy: 开始获取用户 %v 的策略", u.Username)
	log.Printf("User.GetPolicy: 用户所在组数量: %d", len(u.Groups))

	if len(u.Groups) == 0 {
		log.Printf("User.GetPolicy: 用户没有任何组，返回nil")
		return nil
	}

	mergedPolicy := &Policy{
		Routes:        []Route{},
		ExcludeRoutes: []ExcludeRoute{},
	}

	routeMap := make(map[string]bool)        // 用于去重路由
	excludeRouteMap := make(map[string]bool) // 用于去重排除路由
	dnsMap := make(map[string]bool)          // 用于去重 DNS 服务器
	splitDNSMap := make(map[string]bool)     // 用于去重 Split-DNS 域名
	var policyIDs []uint
	var mergedDNSServers []string
	var mergedSplitDNS []string

	for groupIndex, group := range u.Groups {
		log.Printf("User.GetPolicy: 处理组 %d (ID: %d)", groupIndex+1, group.ID)
		log.Printf("User.GetPolicy: 组 %d 的策略数量: %d", groupIndex+1, len(group.Policies))

		for policyIndex, policy := range group.Policies {
			log.Printf("User.GetPolicy: 处理组 %d 的策略 %d (ID: %d)", groupIndex+1, policyIndex+1, policy.ID)
			log.Printf("User.GetPolicy: 策略 %d 的路由数量: %d，排除路由数量: %d", policyIndex+1, len(policy.Routes), len(policy.ExcludeRoutes))

			policyIDs = append(policyIDs, policy.ID)

			// 合并 DNS 服务器
			if policy.DNSServers != "" {
				var dnsServers []string
				if err := json.Unmarshal([]byte(policy.DNSServers), &dnsServers); err == nil {
					// JSON 格式解析成功
					for _, dns := range dnsServers {
						dns = strings.TrimSpace(dns)
						if dns != "" && !dnsMap[dns] {
							log.Printf("User.GetPolicy: 添加 DNS 服务器: %s", dns)
							mergedDNSServers = append(mergedDNSServers, dns)
							dnsMap[dns] = true
						}
					}
				} else {
					// 尝试逗号分隔格式
					for _, dns := range strings.Split(policy.DNSServers, ",") {
						dns = strings.TrimSpace(dns)
						if dns != "" && !dnsMap[dns] {
							log.Printf("User.GetPolicy: 添加 DNS 服务器: %s", dns)
							mergedDNSServers = append(mergedDNSServers, dns)
							dnsMap[dns] = true
						}
					}
				}
			}

			// 合并 Split-DNS 域名
			log.Printf("User.GetPolicy: 策略 %d 的 SplitDNS 字段值: '%s'", policyIndex+1, policy.SplitDNS)
			if policy.SplitDNS != "" {
				var splitDNSDomains []string
				if err := json.Unmarshal([]byte(policy.SplitDNS), &splitDNSDomains); err == nil {
					// JSON 格式解析成功
					log.Printf("User.GetPolicy: 策略 %d 解析出 %d 个 Split-DNS 域名 (JSON格式)", policyIndex+1, len(splitDNSDomains))
					for _, domain := range splitDNSDomains {
						domain = strings.TrimSpace(domain)
						if domain != "" && !splitDNSMap[domain] {
							log.Printf("User.GetPolicy: 添加 Split-DNS 域名: %s", domain)
							mergedSplitDNS = append(mergedSplitDNS, domain)
							splitDNSMap[domain] = true
						}
					}
				} else {
					// 尝试逗号分隔格式
					log.Printf("User.GetPolicy: 策略 %d SplitDNS JSON 解析失败，尝试逗号分隔格式: %v", policyIndex+1, err)
					for _, domain := range strings.Split(policy.SplitDNS, ",") {
						domain = strings.TrimSpace(domain)
						if domain != "" && !splitDNSMap[domain] {
							log.Printf("User.GetPolicy: 添加 Split-DNS 域名: %s", domain)
							mergedSplitDNS = append(mergedSplitDNS, domain)
							splitDNSMap[domain] = true
						}
					}
				}
			} else {
				log.Printf("User.GetPolicy: 策略 %d 的 SplitDNS 字段为空", policyIndex+1)
			}

			for routeIndex, route := range policy.Routes {
				log.Printf("User.GetPolicy: 策略 %d 的路由 %d: %s", policyIndex+1, routeIndex+1, route.Network)
				if !routeMap[route.Network] {
					log.Printf("User.GetPolicy: 添加新路由: %s", route.Network)
					mergedPolicy.Routes = append(mergedPolicy.Routes, route)
					routeMap[route.Network] = true
				} else {
					log.Printf("User.GetPolicy: 跳过重复路由: %s", route.Network)
				}
			}

			for excludeRouteIndex, excludeRoute := range policy.ExcludeRoutes {
				log.Printf("User.GetPolicy: 策略 %d 的排除路由 %d: %s", policyIndex+1, excludeRouteIndex+1, excludeRoute.Network)
				if !excludeRouteMap[excludeRoute.Network] {
					log.Printf("User.GetPolicy: 添加新排除路由: %s", excludeRoute.Network)
					mergedPolicy.ExcludeRoutes = append(mergedPolicy.ExcludeRoutes, excludeRoute)
					excludeRouteMap[excludeRoute.Network] = true
				} else {
					log.Printf("User.GetPolicy: 跳过重复排除路由: %s", excludeRoute.Network)
				}
			}
		}
	}

	// 设置合并后的 DNS 服务器
	if len(mergedDNSServers) > 0 {
		dnsJSON, err := json.Marshal(mergedDNSServers)
		if err == nil {
			mergedPolicy.DNSServers = string(dnsJSON)
			log.Printf("User.GetPolicy: 合并后 DNS 服务器数量: %d", len(mergedDNSServers))
		}
	}

	// 设置合并后的 Split-DNS 域名
	if len(mergedSplitDNS) > 0 {
		splitDNSJSON, err := json.Marshal(mergedSplitDNS)
		if err == nil {
			mergedPolicy.SplitDNS = string(splitDNSJSON)
			log.Printf("User.GetPolicy: 合并后 Split-DNS 域名数量: %d", len(mergedSplitDNS))
		}
	}

	log.Printf("User.GetPolicy: 合并后策略路由数量: %d，排除路由数量: %d", len(mergedPolicy.Routes), len(mergedPolicy.ExcludeRoutes))

	if len(mergedPolicy.Routes) == 0 {
		log.Printf("User.GetPolicy: 合并后没有路由，返回nil")
		return nil
	}

	if len(policyIDs) > 0 {
		mergedPolicy.ID = policyIDs[0]
		log.Printf("User.GetPolicy: 设置合并策略ID为 %d (第一个策略ID)", mergedPolicy.ID)
	}

	log.Printf("User.GetPolicy: 返回合并后的策略，ID: %d，路由数量: %d", mergedPolicy.ID, len(mergedPolicy.Routes))
	return mergedPolicy
}

func (u *User) GetPolicyID() uint {
	policy := u.GetPolicy()
	if policy != nil {
		return policy.ID
	}
	return 0
}

func (u *User) SetPassword(password string) error {
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

func (u *User) CheckPassword(password string) bool {
	if u.Source == UserSourceLDAP {
		return false
	}
	if u.PasswordHash == "" {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}

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

func (u *User) CheckPasswordWithOTP(password string) bool {
	if u.OTPEnabled && u.OTPSecret != "" {
		if len(password) < 7 {
			return false
		}

		otpCode := password[len(password)-6:]
		actualPassword := password[:len(password)-6]

		if len(otpCode) != 6 {
			return false
		}
		for _, c := range otpCode {
			if c < '0' || c > '9' {
				return false // OTP代码必须全是数字
			}
		}

		if !u.CheckPassword(actualPassword) {
			return false
		}

		otpAuth := auth.NewOTPAuthenticator("ZVPN")
		return otpAuth.ValidateOTP(u.OTPSecret, otpCode)
	}

	return u.CheckPassword(password)
}

func (u *User) CheckOTPOnly(password string) bool {
	if !u.OTPEnabled || u.OTPSecret == "" {
		return false // 未启用OTP
	}

	if len(password) < 6 {
		return false // 密码太短，无法包含OTP
	}

	otpCode := password[len(password)-6:]

	if len(otpCode) != 6 {
		return false
	}
	for _, c := range otpCode {
		if c < '0' || c > '9' {
			return false // OTP代码必须全是数字
		}
	}

	otpAuth := auth.NewOTPAuthenticator("ZVPN")
	return otpAuth.ValidateOTP(u.OTPSecret, otpCode)
}


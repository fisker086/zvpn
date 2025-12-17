package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fisker/zvpn/auth"
	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/vpn/ebpf"
	"github.com/fisker/zvpn/vpn/policy"
	"github.com/fisker/zvpn/vpn/security"
	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	config               *config.Config
	ldapAuthenticator    *auth.LDAPAuthenticator
	bruteforceProtection *security.BruteforceProtection
}

func NewAuthHandler(cfg *config.Config, vpnServer interface{}) *AuthHandler {
	var ldapAuth *auth.LDAPAuthenticator
	if cfg.LDAP.Enabled {
		ldapConfig := &auth.LDAPConfig{
			Enabled:      cfg.LDAP.Enabled,
			Host:         cfg.LDAP.Host,
			Port:         cfg.LDAP.Port,
			BindDN:       cfg.LDAP.BindDN,
			BindPassword: cfg.LDAP.BindPassword,
			BaseDN:       cfg.LDAP.BaseDN,
			UserFilter:   cfg.LDAP.UserFilter,
			AdminGroup:   cfg.LDAP.AdminGroup,
		}
		ldapAuth = auth.NewLDAPAuthenticator(ldapConfig)
		log.Println("LDAP authentication enabled")
	}

	// 从 VPNServer 获取密码爆破防护实例（如果已初始化）
	var bruteforceProtection *security.BruteforceProtection
	if vpnServer != nil {
		// 使用类型断言获取 VPNServer
		if vs, ok := vpnServer.(interface{ GetBruteforceProtection() interface{} }); ok {
			if bpInterface := vs.GetBruteforceProtection(); bpInterface != nil {
				if bp, ok := bpInterface.(*security.BruteforceProtection); ok {
					bruteforceProtection = bp
					log.Printf("AuthHandler: Using shared bruteforce protection instance from VPNServer")
				}
			}
		}
	}

	// 如果 VPNServer 中没有，则创建新实例（向后兼容）
	if bruteforceProtection == nil && cfg.VPN.EnableBruteforceProtection {
		maxAttempts := cfg.VPN.MaxLoginAttempts
		if maxAttempts <= 0 {
			maxAttempts = 5 // 默认值
		}
		lockoutDuration := time.Duration(cfg.VPN.LoginLockoutDuration) * time.Second
		if lockoutDuration <= 0 {
			lockoutDuration = 15 * time.Minute // 默认15分钟
		}
		windowDuration := time.Duration(cfg.VPN.LoginAttemptWindow) * time.Second
		if windowDuration <= 0 {
			windowDuration = 5 * time.Minute // 默认5分钟
		}
		bruteforceProtection = security.NewBruteforceProtection(maxAttempts, lockoutDuration, windowDuration)
		// 如果 eBPF 程序可用，设置它
		if vpnServer != nil {
			if vs, ok := vpnServer.(interface{ GetEBPFProgram() *ebpf.XDPProgram }); ok {
				if ebpfProg := vs.GetEBPFProgram(); ebpfProg != nil {
					bruteforceProtection.SetEBPFProgram(ebpfProg)
				}
			}
		}
		log.Printf("AuthHandler: Bruteforce protection enabled: max attempts=%d, lockout=%v, window=%v",
			maxAttempts, lockoutDuration, windowDuration)
	}

	return &AuthHandler{
		config:               cfg,
		ldapAuthenticator:    ldapAuth,
		bruteforceProtection: bruteforceProtection,
	}
}

type LoginRequest struct {
	Username      string `json:"username" binding:"required"`
	Password      string `json:"password"`      // 第一步：密码（必需），第二步：可选
	OTPCode       string `json:"otp_code"`      // 第二步：OTP代码（多步骤认证时使用）
	PasswordToken string `json:"password_token"` // 第二步：密码验证token（多步骤认证时使用）
}

type LoginResponse struct {
	Token         string      `json:"token,omitempty"`          // JWT token（最终登录成功时返回）
	PasswordToken string      `json:"password_token,omitempty"` // 密码验证token（第一步成功时返回，要求输入OTP）
	RequiresOTP   bool        `json:"requires_otp"`            // 是否需要OTP验证
	User          models.User `json:"user,omitempty"`          // 用户信息（最终登录成功时返回）
	Message       string      `json:"message,omitempty"`        // 提示信息
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	clientIP := c.ClientIP()

	// 后台登录不需要OTP验证，直接验证密码即可
	// 注意：OTP双因素认证仅用于OpenConnect客户端登录，后台登录不使用OTP
	if req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password is required"})
		return
	}

	// 检查密码爆破防护
	if h.bruteforceProtection != nil {
		blocked, blockedUntil := h.bruteforceProtection.IsBlocked(clientIP)
		if blocked {
			remainingTime := time.Until(blockedUntil)
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":         fmt.Sprintf("IP address is temporarily blocked due to too many failed login attempts. Please try again after %v", remainingTime.Round(time.Second)),
				"blocked_until": blockedUntil,
			})
			return
		}
	}

	var user models.User
	var isLDAPAuth bool

	// 从数据库读取LDAP配置
	var ldapConfig models.LDAPConfig
	if err := database.DB.First(&ldapConfig).Error; err != nil {
		// 如果不存在，使用默认配置（禁用）
		ldapConfig = models.LDAPConfig{Enabled: false}
	}

	// 如果LDAP启用，创建LDAP认证器（使用属性映射配置）
	var ldapAuth *auth.LDAPAuthenticator
	if ldapConfig.Enabled {
		// 获取属性映射配置
		mapping := ldapConfig.GetAttributeMapping()
		authConfig := &auth.LDAPConfig{
			Enabled:       ldapConfig.Enabled,
			Host:          ldapConfig.Host,
			Port:          ldapConfig.Port,
			UseSSL:        ldapConfig.UseSSL,
			BindDN:        ldapConfig.BindDN,
			BindPassword:  ldapConfig.BindPassword,
			BaseDN:        ldapConfig.BaseDN,
			UserFilter:    ldapConfig.UserFilter,
			AdminGroup:    ldapConfig.AdminGroup,
			SkipTLSVerify: ldapConfig.SkipTLSVerify,
			AttributeMapping: auth.AttributeMapping{
				UsernameAttribute: mapping.UsernameAttribute,
				EmailAttribute:    mapping.EmailAttribute,
				FullNameAttribute: mapping.FullNameAttribute,
				MemberOfAttribute: mapping.MemberOfAttribute,
			},
		}
		ldapAuth = auth.NewLDAPAuthenticator(authConfig)
		log.Printf("LDAP authenticator created: Host=%s, Port=%d, UseSSL=%v, SkipTLSVerify=%v",
			ldapConfig.Host, ldapConfig.Port, ldapConfig.UseSSL, ldapConfig.SkipTLSVerify)
	}

	// 尝试 LDAP 认证（如果启用）
	// 兼容性说明：
	// 1. LDAP用户：Source字段为'ldap'，登录时使用LDAP服务器认证，数据库不存储密码
	// 2. 系统账户：Source字段为'system'，登录时使用数据库认证（bcrypt哈希）
	// 3. 系统根据Source字段自动识别账户类型，无需密码格式判断
	// 4. LDAP用户登录使用uid（英文账户名），系统账户可以使用任意用户名
	if ldapAuth != nil && ldapConfig.Enabled {
		// 先检查用户是否存在于数据库中
		var existingUser models.User
		userExistsInDB := database.DB.Where("username = ?", req.Username).First(&existingUser).Error == nil

		// 如果用户存在，检查是LDAP用户还是系统账户
		if userExistsInDB {
			// 根据Source字段判断用户类型
			if existingUser.Source == models.UserSourceLDAP {
				// LDAP用户，使用LDAP认证
			} else {
				// 系统账户，跳过LDAP认证，直接使用数据库认证
				log.Printf("User %s is a system account (source: %s), using database authentication", req.Username, existingUser.Source)
				// 不设置 isLDAPAuth，让后续代码使用数据库认证
			}

			// 如果是LDAP用户，尝试LDAP认证
			if existingUser.Source == models.UserSourceLDAP {
				// 是LDAP用户，尝试LDAP认证
				ldapUser, err := ldapAuth.Authenticate(req.Username, req.Password)
				if err == nil {
					// LDAP 认证成功，同步用户到本地数据库
					if err := database.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
						// 用户不存在，创建新用户
						user = models.User{
							Username: req.Username,
							Email:    ldapUser.Email,
							IsAdmin:  ldapUser.IsAdmin,
							IsActive: true,
							Source:   models.UserSourceLDAP, // 标记为LDAP用户
							LDAPDN:   ldapUser.DN,
							FullName: ldapUser.FullName,
							// PasswordHash 留空，LDAP用户不需要存储密码
						}
						// 序列化LDAP原始属性为JSON（用于扩展）
						if len(ldapUser.Attributes) > 0 {
							if attrsJSON, err := json.Marshal(ldapUser.Attributes); err == nil {
								user.LDAPAttributes = string(attrsJSON)
							}
						}
						if err := database.DB.Create(&user).Error; err != nil {
							log.Printf("Failed to create LDAP user %s: %v", req.Username, err)
							c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
							return
						}

						// 为新创建的 LDAP 用户分配默认用户组
						// 管理员用户分配到 admin 组，普通用户分配到 default 组（如果不存在则创建）
						var defaultGroup models.UserGroup
						groupName := "default"
						if ldapUser.IsAdmin {
							groupName = "admin"
						}

						// 查找或创建默认用户组
						if err := database.DB.Where("name = ?", groupName).First(&defaultGroup).Error; err != nil {
							// 组不存在，尝试创建（仅对 default 组）
							if groupName == "default" {
								// 查找默认策略
								var defaultPolicy models.Policy
								if err := database.DB.Where("name = ?", "default").First(&defaultPolicy).Error; err == nil {
									defaultGroup = models.UserGroup{
										Name:        "default",
										Description: "默认用户组",
									}
									if err := database.DB.Create(&defaultGroup).Error; err != nil {
										log.Printf("Warning: Failed to create default user group: %v", err)
									} else {
										// 关联默认策略
										if err := database.DB.Model(&defaultGroup).Association("Policies").Append(&defaultPolicy); err != nil {
											log.Printf("Warning: Failed to assign default policy to default group: %v", err)
										}
										log.Printf("✓ Created default user group")
									}
								}
							}
						}

						// 分配用户组
						if defaultGroup.ID > 0 {
							if err := database.DB.Model(&user).Association("Groups").Append(&defaultGroup); err != nil {
								log.Printf("Warning: Failed to assign group '%s' to LDAP user %s: %v", groupName, req.Username, err)
							} else {
								log.Printf("✓ LDAP user %s assigned to group '%s'", req.Username, groupName)
							}
						} else {
							log.Printf("Warning: User group '%s' not found, LDAP user %s has no groups (may affect VPN access)", groupName, req.Username)
						}

						log.Printf("✓ LDAP user created: %s (email: %s, fullname: %s, admin: %v)",
							req.Username, ldapUser.Email, ldapUser.FullName, ldapUser.IsAdmin)
					} else {
						// 用户已存在，检查是否被禁用
						if !user.IsActive {
							// 记录失败的登录尝试
							auditLogger := policy.GetAuditLogger()
							clientIP := c.ClientIP()
							auditLogger.LogAuthWithIP(user.ID, user.Username, models.AuditLogActionLogin, "failed", "Account disabled", clientIP, 0)
							c.JSON(http.StatusForbidden, gin.H{"error": "User account is disabled"})
							return
						}

						// 同步最新信息
						updated := false
						if user.Email != ldapUser.Email && ldapUser.Email != "" {
							user.Email = ldapUser.Email
							updated = true
						}
						if user.IsAdmin != ldapUser.IsAdmin {
							user.IsAdmin = ldapUser.IsAdmin
							updated = true
						}
						// 更新LDAP属性
						if user.LDAPDN != ldapUser.DN && ldapUser.DN != "" {
							user.LDAPDN = ldapUser.DN
							updated = true
						}
						if user.FullName != ldapUser.FullName && ldapUser.FullName != "" {
							user.FullName = ldapUser.FullName
							updated = true
						}
						// 更新LDAP原始属性JSON（用于扩展）
						if len(ldapUser.Attributes) > 0 {
							if attrsJSON, err := json.Marshal(ldapUser.Attributes); err == nil {
								if user.LDAPAttributes != string(attrsJSON) {
									user.LDAPAttributes = string(attrsJSON)
									updated = true
								}
							}
						}
						if updated {
							if err := database.DB.Save(&user).Error; err != nil {
								log.Printf("Failed to update LDAP user %s: %v", req.Username, err)
							} else {
								log.Printf("✓ LDAP user synced: %s (email: %s, fullname: %s, admin: %v)",
									req.Username, ldapUser.Email, ldapUser.FullName, ldapUser.IsAdmin)
							}
						}
					}
					isLDAPAuth = true
					log.Printf("✓ User %s authenticated via LDAP (password correct)", req.Username)
					// LDAP认证成功，继续后续流程生成JWT token（后台登录不需要OTP）
				} else {
					// LDAP 认证失败，用户是LDAP用户，不应该fallback到本地认证
					// 因为LDAP用户的密码存储在LDAP服务器中，本地数据库没有密码
					auditLogger := policy.GetAuditLogger()
					auditLogger.LogAuthWithIP(existingUser.ID, req.Username, models.AuditLogActionLogin, "failed",
						fmt.Sprintf("LDAP authentication failed: %v. Source IP: %s", err, clientIP), clientIP, 0)

					// 记录密码爆破尝试
					if h.bruteforceProtection != nil {
						blocked, _, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
						if blocked {
							c.JSON(http.StatusTooManyRequests, gin.H{
								"error":         fmt.Sprintf("Too many failed login attempts. IP address blocked until %v", blockedUntil.Format(time.RFC3339)),
								"blocked_until": blockedUntil,
							})
							return
						}
					}
					log.Printf("✗ LDAP authentication failed for LDAP user %s: %v", req.Username, err)
					c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
					return
				}
			}
		} else {
			// 用户不存在于数据库中，尝试LDAP认证
			ldapUser, err := ldapAuth.Authenticate(req.Username, req.Password)
			if err == nil {
				// LDAP 认证成功，创建新用户
				user = models.User{
					Username: req.Username,
					Email:    ldapUser.Email,
					IsAdmin:  ldapUser.IsAdmin,
					IsActive: true,
					Source:   models.UserSourceLDAP, // 标记为LDAP用户
					LDAPDN:   ldapUser.DN,
					FullName: ldapUser.FullName,
					// PasswordHash 留空，LDAP用户不需要存储密码
				}
				// 序列化LDAP原始属性为JSON（用于扩展）
				if len(ldapUser.Attributes) > 0 {
					if attrsJSON, err := json.Marshal(ldapUser.Attributes); err == nil {
						user.LDAPAttributes = string(attrsJSON)
					}
				}
				if err := database.DB.Create(&user).Error; err != nil {
					log.Printf("Failed to create LDAP user %s: %v", req.Username, err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
					return
				}

				// 为新创建的 LDAP 用户分配默认用户组
				var defaultGroup models.UserGroup
				groupName := "default"
				if ldapUser.IsAdmin {
					groupName = "admin"
				}
				if err := database.DB.Where("name = ?", groupName).First(&defaultGroup).Error; err == nil {
					database.DB.Model(&user).Association("Groups").Append(&defaultGroup)
				}

				isLDAPAuth = true
				log.Printf("✓ LDAP user created and authenticated: %s (password correct)", req.Username)
				// LDAP认证成功，继续后续流程生成JWT token（后台登录不需要OTP）
			} else {
				// LDAP 认证失败，用户不存在于数据库中，不应该fallback到本地认证
				// 因为用户不存在，只有LDAP认证成功才能创建新用户
				auditLogger := policy.GetAuditLogger()
				auditLogger.LogAuthWithIP(0, req.Username, models.AuditLogActionLogin, "failed",
					fmt.Sprintf("LDAP authentication failed: %v. Source IP: %s", err, clientIP), clientIP, 0)

				// 记录密码爆破尝试
				if h.bruteforceProtection != nil {
					blocked, _, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
					if blocked {
						c.JSON(http.StatusTooManyRequests, gin.H{
							"error":         fmt.Sprintf("Too many failed login attempts. IP address blocked until %v", blockedUntil.Format(time.RFC3339)),
							"blocked_until": blockedUntil,
						})
						return
					}
				}
				log.Printf("✗ LDAP authentication failed for user %s (not in DB): %v", req.Username, err)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
				return
			}
		}
	}

	// 本地认证（如果 LDAP 未启用或 LDAP 认证失败）
	if !isLDAPAuth {
		if err := database.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
			// 记录失败的登录尝试
			auditLogger := policy.GetAuditLogger()
			auditLogger.LogAuthWithIP(0, req.Username, models.AuditLogActionLogin, "failed", "User not found", clientIP, 0)

			// 记录密码爆破尝试
			if h.bruteforceProtection != nil {
				blocked, remaining, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
				if blocked {
					c.JSON(http.StatusTooManyRequests, gin.H{
						"error":         fmt.Sprintf("Too many failed login attempts. IP address blocked until %v", blockedUntil.Format(time.RFC3339)),
						"blocked_until": blockedUntil,
					})
					return
				}
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":              "Invalid credentials",
					"remaining_attempts": remaining,
				})
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// 检查：如果用户是LDAP用户，但LDAP已关闭，不允许登录
		// 因为LDAP用户的密码存储在LDAP服务器中，本地数据库没有密码
		if user.Source == models.UserSourceLDAP && !ldapConfig.Enabled {
			log.Printf("User %s is an LDAP user but LDAP is disabled", req.Username)
			auditLogger := policy.GetAuditLogger()
			if auditLogger != nil {
				auditLogger.LogAuthWithIP(user.ID, req.Username, models.AuditLogActionLogin, "failed",
					fmt.Sprintf("LDAP user cannot login when LDAP is disabled. Source IP: %s", clientIP), clientIP, 0)
			}
			c.JSON(http.StatusForbidden, gin.H{"error": "LDAP authentication is disabled. Please contact administrator."})
			return
		}

		if !user.IsActive {
			// 记录失败的登录尝试
			auditLogger := policy.GetAuditLogger()
			auditLogger.LogAuth(user.ID, user.Username, models.AuditLogActionLogin, "failed", "Account disabled")
			c.JSON(http.StatusForbidden, gin.H{"error": "User account is disabled"})
			return
		}

		if !user.CheckPassword(req.Password) {
			// 记录失败的登录尝试
			auditLogger := policy.GetAuditLogger()
			auditLogger.LogAuthWithIP(user.ID, user.Username, models.AuditLogActionLogin, "failed", "Invalid password", clientIP, 0)

			// 记录密码爆破尝试
			if h.bruteforceProtection != nil {
				blocked, remaining, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
				if blocked {
					c.JSON(http.StatusTooManyRequests, gin.H{
						"error":         fmt.Sprintf("Too many failed login attempts. IP address blocked until %v", blockedUntil.Format(time.RFC3339)),
						"blocked_until": blockedUntil,
					})
					return
				}
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":              "Invalid credentials",
					"remaining_attempts": remaining,
				})
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// 密码验证成功，继续后续流程生成JWT token（后台登录不需要OTP）
	}

	// 生成 JWT token（密码验证成功或LDAP认证成功）
	token, err := auth.GenerateToken(user.ID, user.Username, user.IsAdmin, h.config.JWT.Secret, h.config.JWT.Expiration)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// 创建会话
	session := &models.Session{
		UserID:    user.ID,
		Token:     token,
		IPAddress: c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
		ExpiresAt: time.Now().Add(time.Duration(h.config.JWT.Expiration) * time.Hour),
		Active:    true,
	}
	database.DB.Create(session)

	// 清除密码哈希
	user.PasswordHash = ""

	// 记录审计日志
	auditLogger := policy.GetAuditLogger()
	auditLogger.LogAuthWithIP(user.ID, user.Username, models.AuditLogActionLogin, "success", "", clientIP, 0)

	// 登录成功，清除该IP的失败记录
	if h.bruteforceProtection != nil {
		h.bruteforceProtection.RecordSuccess(clientIP)
	}

	c.JSON(http.StatusOK, LoginResponse{
		Token: token,
		User:  user,
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	var username string
	if exists {
		var user models.User
		if err := database.DB.First(&user, userID).Error; err == nil {
			username = user.Username
		}
	}

	// Get token from header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		parts := c.GetHeader("Authorization")
		if len(parts) > 7 && parts[:7] == "Bearer " {
			token := parts[7:]
			database.DB.Model(&models.Session{}).Where("token = ?", token).Update("active", false)
		}
	}

	// 记录审计日志
	if exists {
		auditLogger := policy.GetAuditLogger()
		clientIP := c.ClientIP()
		auditLogger.LogAuthWithIP(userID.(uint), username, models.AuditLogActionLogout, "success", "", clientIP, 0)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func (h *AuthHandler) Profile(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var user models.User
	if err := database.DB.Preload("Groups").First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	user.PasswordHash = ""
	c.JSON(http.StatusOK, user)
}

// generatePasswordToken 生成密码验证token（用于多步骤认证）
func (h *AuthHandler) generatePasswordToken(username string) string {
	timestamp := time.Now().Unix()
	message := fmt.Sprintf("%s:%d", username, timestamp)

	// 使用JWT密钥生成密码验证token（与JWT使用相同的密钥）
	secret := h.config.JWT.Secret
	if secret == "" {
		// 如果未配置，使用默认密钥（仅用于开发环境）
		secret = "zvpn-default-secret-key-change-in-production"
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	return base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", message, signature)))
}

// verifyPasswordToken 验证密码验证token
func (h *AuthHandler) verifyPasswordToken(token string, username string) bool {
	// 解码token
	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return false
	}

	parts := strings.Split(string(data), ":")
	if len(parts) != 3 {
		return false
	}

	tokenUsername := parts[0]
	timestampStr := parts[1]
	signature := parts[2]

	// 验证用户名
	if tokenUsername != username {
		return false
	}

	// 验证时间戳（token有效期5分钟）
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false
	}
	if time.Now().Unix()-timestamp > 300 { // 5分钟过期
		return false
	}

	// 验证签名
	message := fmt.Sprintf("%s:%d", username, timestamp)
	secret := h.config.JWT.Secret
	if secret == "" {
		secret = "zvpn-default-secret-key-change-in-production"
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	expectedSignature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

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
	Password      string `json:"password"`       // 第一步：密码（必需），第二步：可选
	OTPCode       string `json:"otp_code"`       // 第二步：OTP代码（多步骤认证时使用）
	PasswordToken string `json:"password_token"` // 第二步：密码验证token（多步骤认证时使用）
}

type LoginResponse struct {
	Token         string      `json:"token,omitempty"`          // JWT token（最终登录成功时返回）
	PasswordToken string      `json:"password_token,omitempty"` // 密码验证token（第一步成功时返回，要求输入OTP）
	RequiresOTP   bool        `json:"requires_otp"`             // 是否需要OTP验证
	User          models.User `json:"user,omitempty"`           // 用户信息（最终登录成功时返回）
	Message       string      `json:"message,omitempty"`        // 提示信息
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Backend Login: Invalid request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	clientIP := c.ClientIP()
	log.Printf("Backend Login: Attempting login for user '%s' from IP %s", req.Username, clientIP)

	// 后台登录不需要OTP验证，直接验证密码即可
	// 注意：OTP双因素认证仅用于OpenConnect客户端登录，后台登录不使用OTP
	if req.Password == "" {
		log.Printf("Backend Login: Password is empty for user '%s'", req.Username)
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

	// 认证逻辑：先查数据库，根据Source字段决定认证方式
	// 1. 先检查用户是否存在于数据库中
	var existingUser models.User
	userExistsInDB := database.DB.Where("username = ?", req.Username).First(&existingUser).Error == nil

	if userExistsInDB {
		// 用户存在于数据库中，根据Source字段决定认证方式
		log.Printf("Backend Login: User '%s' found in database (Source: %s)", req.Username, existingUser.Source)

		if existingUser.Source == models.UserSourceLDAP {
			// LDAP用户，使用LDAP认证
			if ldapAuth == nil || !ldapConfig.Enabled {
				log.Printf("Backend Login: User '%s' is LDAP user but LDAP is disabled", req.Username)
				auditLogger := policy.GetAuditLogger()
				if auditLogger != nil {
					auditLogger.LogAuthWithIP(existingUser.ID, req.Username, models.AuditLogActionLogin, "failed",
						fmt.Sprintf("LDAP user cannot login when LDAP is disabled. Source IP: %s", clientIP), clientIP, 0)
				}
				c.JSON(http.StatusForbidden, gin.H{"error": "LDAP authentication is disabled. Please contact administrator."})
				return
			}

			log.Printf("Backend Login: Authenticating LDAP user '%s' via LDAP server", req.Username)
			ldapUser, err := ldapAuth.Authenticate(req.Username, req.Password)
			if err == nil {
				// LDAP认证成功
				if err := database.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "User data error"})
					return
				}

				// 检查账户是否被禁用
				if !user.IsActive {
					auditLogger := policy.GetAuditLogger()
					auditLogger.LogAuthWithIP(user.ID, user.Username, models.AuditLogActionLogin, "failed", "Account disabled", clientIP, 0)
					c.JSON(http.StatusForbidden, gin.H{"error": "您的账户已被禁用，无法登录。请联系管理员激活账户。"})
					return
				}

				// 同步LDAP用户信息（如果需要）
				updated := false
				if user.Email != ldapUser.Email && ldapUser.Email != "" {
					user.Email = ldapUser.Email
					updated = true
				}
				if user.IsAdmin != ldapUser.IsAdmin {
					user.IsAdmin = ldapUser.IsAdmin
					updated = true
				}
				if user.LDAPDN != ldapUser.DN && ldapUser.DN != "" {
					user.LDAPDN = ldapUser.DN
					updated = true
				}
				if user.FullName != ldapUser.FullName && ldapUser.FullName != "" {
					user.FullName = ldapUser.FullName
					updated = true
				}
				if len(ldapUser.Attributes) > 0 {
					if attrsJSON, err := json.Marshal(ldapUser.Attributes); err == nil {
						if user.LDAPAttributes != string(attrsJSON) {
							user.LDAPAttributes = string(attrsJSON)
							updated = true
						}
					}
				}
				if updated {
					updateFields := []string{"email", "is_admin", "ldap_dn", "full_name", "ldap_attributes", "updated_at"}
					if err := database.DB.Model(&user).Select(updateFields).Updates(user).Error; err != nil {
						log.Printf("Failed to update LDAP user %s: %v", req.Username, err)
					}
				}

				log.Printf("Backend Login: ✓ LDAP user '%s' authenticated successfully", req.Username)
				// LDAP认证成功，继续后续流程生成JWT token
			} else {
				// LDAP认证失败
				auditLogger := policy.GetAuditLogger()
				auditLogger.LogAuthWithIP(existingUser.ID, req.Username, models.AuditLogActionLogin, "failed",
					fmt.Sprintf("LDAP authentication failed: %v. Source IP: %s", err, clientIP), clientIP, 0)

				if h.bruteforceProtection != nil {
					blocked, remaining, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
					if blocked {
						remainingTime := time.Until(blockedUntil)
						c.JSON(http.StatusTooManyRequests, gin.H{
							"error":         fmt.Sprintf("IP address is temporarily blocked due to too many failed login attempts. Please try again after %v", remainingTime.Round(time.Second)),
							"blocked_until": blockedUntil,
						})
						return
					}
					c.JSON(http.StatusUnauthorized, gin.H{
						"error":              "LDAP authentication failed. Please check your username and password.",
						"remaining_attempts": remaining,
					})
					return
				}
				log.Printf("Backend Login: ✗ LDAP authentication failed for LDAP user '%s': %v", req.Username, err)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "LDAP authentication failed. Please check your username and password."})
				return
			}
		} else {
			// 系统账户，使用数据库认证
			log.Printf("Backend Login: Authenticating system user '%s' via database", req.Username)
			if err := database.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
				log.Printf("Backend Login: User '%s' not found in database: %v", req.Username, err)
				auditLogger := policy.GetAuditLogger()
				auditLogger.LogAuthWithIP(0, req.Username, models.AuditLogActionLogin, "failed", "User not found", clientIP, 0)

				if h.bruteforceProtection != nil {
					blocked, remaining, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
					if blocked {
						remainingTime := time.Until(blockedUntil)
						c.JSON(http.StatusTooManyRequests, gin.H{
							"error":         fmt.Sprintf("IP address is temporarily blocked due to too many failed login attempts. Please try again after %v", remainingTime.Round(time.Second)),
							"blocked_until": blockedUntil,
						})
						return
					}
					c.JSON(http.StatusUnauthorized, gin.H{
						"error":              "User not found",
						"remaining_attempts": remaining,
					})
					return
				}
				c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
				return
			}

			// 检查账户是否被禁用
			if !user.IsActive {
				log.Printf("Backend Login: User '%s' account is disabled", req.Username)
				auditLogger := policy.GetAuditLogger()
				auditLogger.LogAuth(user.ID, user.Username, models.AuditLogActionLogin, "failed", "Account disabled")
				c.JSON(http.StatusForbidden, gin.H{"error": "您的账户已被禁用，无法登录。请联系管理员激活账户。"})
				return
			}

			// 验证密码
			log.Printf("Backend Login: Checking password for system user '%s' (PasswordHash length: %d)", req.Username, len(user.PasswordHash))
			if !user.CheckPassword(req.Password) {
				log.Printf("Backend Login: Password check failed for system user '%s'", req.Username)
				auditLogger := policy.GetAuditLogger()
				auditLogger.LogAuthWithIP(user.ID, user.Username, models.AuditLogActionLogin, "failed", "Invalid password", clientIP, 0)

				if h.bruteforceProtection != nil {
					blocked, remaining, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
					if blocked {
						remainingTime := time.Until(blockedUntil)
						c.JSON(http.StatusTooManyRequests, gin.H{
							"error":         fmt.Sprintf("IP address is temporarily blocked due to too many failed login attempts. Please try again after %v", remainingTime.Round(time.Second)),
							"blocked_until": blockedUntil,
						})
						return
					}
					c.JSON(http.StatusUnauthorized, gin.H{
						"error":              "Password incorrect",
						"remaining_attempts": remaining,
					})
					return
				}
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Password incorrect"})
				return
			}

			log.Printf("Backend Login: ✓ System user '%s' authenticated successfully", req.Username)
			// 数据库认证成功，继续后续流程生成JWT token
		}
	} else {
		// 用户不存在于数据库中
		// 如果LDAP启用，尝试LDAP认证（可能是新的LDAP用户）
		if ldapAuth != nil && ldapConfig.Enabled {
			log.Printf("Backend Login: User '%s' not in database, trying LDAP authentication", req.Username)
			ldapUser, err := ldapAuth.Authenticate(req.Username, req.Password)
			if err == nil {
				// LDAP认证成功，创建新用户
				user = models.User{
					Username: req.Username,
					Email:    ldapUser.Email,
					IsAdmin:  ldapUser.IsAdmin,
					IsActive: true,
					Source:   models.UserSourceLDAP,
					LDAPDN:   ldapUser.DN,
					FullName: ldapUser.FullName,
				}
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

				// 分配默认用户组
				var defaultGroup models.UserGroup
				groupName := "default"
				if ldapUser.IsAdmin {
					groupName = "admin"
				}
				if err := database.DB.Where("name = ?", groupName).First(&defaultGroup).Error; err == nil {
					database.DB.Model(&user).Association("Groups").Append(&defaultGroup)
				}

				log.Printf("Backend Login: ✓ LDAP user '%s' created and authenticated", req.Username)
				// LDAP认证成功，继续后续流程生成JWT token
			} else {
				// LDAP认证失败，用户不存在
				auditLogger := policy.GetAuditLogger()
				auditLogger.LogAuthWithIP(0, req.Username, models.AuditLogActionLogin, "failed",
					fmt.Sprintf("User not found and LDAP authentication failed: %v. Source IP: %s", err, clientIP), clientIP, 0)

				if h.bruteforceProtection != nil {
					blocked, remaining, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
					if blocked {
						remainingTime := time.Until(blockedUntil)
						c.JSON(http.StatusTooManyRequests, gin.H{
							"error":         fmt.Sprintf("IP address is temporarily blocked due to too many failed login attempts. Please try again after %v", remainingTime.Round(time.Second)),
							"blocked_until": blockedUntil,
						})
						return
					}
					c.JSON(http.StatusUnauthorized, gin.H{
						"error":              "User not found or invalid credentials",
						"remaining_attempts": remaining,
					})
					return
				}
				log.Printf("Backend Login: ✗ User '%s' not found and LDAP authentication failed: %v", req.Username, err)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found or invalid credentials"})
				return
			}
		} else {
			// LDAP未启用，用户不存在
			log.Printf("Backend Login: User '%s' not found in database and LDAP is disabled", req.Username)
			auditLogger := policy.GetAuditLogger()
			auditLogger.LogAuthWithIP(0, req.Username, models.AuditLogActionLogin, "failed", "User not found", clientIP, 0)

			if h.bruteforceProtection != nil {
				blocked, remaining, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
				if blocked {
					remainingTime := time.Until(blockedUntil)
					c.JSON(http.StatusTooManyRequests, gin.H{
						"error":         fmt.Sprintf("IP address is temporarily blocked due to too many failed login attempts. Please try again after %v", remainingTime.Round(time.Second)),
						"blocked_until": blockedUntil,
					})
					return
				}
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":              "User not found",
					"remaining_attempts": remaining,
				})
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}
	}

	// 生成 JWT token（认证成功）
	log.Printf("Backend Login: Generating JWT token for user '%s' (ID: %d)", req.Username, user.ID)
	token, err := auth.GenerateToken(user.ID, user.Username, user.IsAdmin, h.config.JWT.Secret, h.config.JWT.Expiration)
	if err != nil {
		log.Printf("Backend Login: Failed to generate token for user '%s': %v", req.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}
	log.Printf("Backend Login: JWT token generated successfully for user '%s'", req.Username)

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

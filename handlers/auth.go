package handlers

import (
	"fmt"
	"log"
	"net/http"
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
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Token string      `json:"token"`
	User  models.User `json:"user"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	clientIP := c.ClientIP()

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

	// 如果LDAP启用，创建LDAP认证器
	var ldapAuth *auth.LDAPAuthenticator
	if ldapConfig.Enabled {
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
		}
		ldapAuth = auth.NewLDAPAuthenticator(authConfig)
		log.Printf("LDAP authenticator created: Host=%s, Port=%d, UseSSL=%v, SkipTLSVerify=%v",
			ldapConfig.Host, ldapConfig.Port, ldapConfig.UseSSL, ldapConfig.SkipTLSVerify)
	}

	// 尝试 LDAP 认证（如果启用）
	if ldapAuth != nil && ldapConfig.Enabled {
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
				}
				// LDAP 用户设置随机密码（不使用本地密码认证）
				if err := user.SetPassword("ldap-user-no-local-password-" + req.Username); err != nil {
					log.Printf("Failed to set password for LDAP user %s: %v", req.Username, err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
					return
				}
				if err := database.DB.Create(&user).Error; err != nil {
					log.Printf("Failed to create LDAP user %s: %v", req.Username, err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
					return
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
			log.Printf("✓ User %s authenticated via LDAP", req.Username)
		} else {
			// LDAP 认证失败，记录失败尝试并 fallback 到本地认证
			auditLogger := policy.GetAuditLogger()
			auditLogger.LogAuthWithIP(0, req.Username, models.AuditLogActionLogin, "failed", fmt.Sprintf("LDAP authentication failed: %v", err), clientIP, 0)

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
			log.Printf("✗ LDAP authentication failed for %s: %v, trying local auth", req.Username, err)
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
	}

	// 生成 JWT token
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

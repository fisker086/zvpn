package openconnect

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"image"
	"image/png"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fisker/zvpn/auth"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/vpn"
	"github.com/fisker/zvpn/vpn/policy"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

func validateSecureHeaders(c *gin.Context) bool {
	xAggregateAuth := c.Request.Header.Get("X-Aggregate-Auth")
	xTranscendVersion := c.Request.Header.Get("X-Transcend-Version")

	if xAggregateAuth != "1" || xTranscendVersion != "1" {
		log.Printf("OpenConnect: Security header validation failed - X-Aggregate-Auth: %s, X-Transcend-Version: %s (from %s)",
			xAggregateAuth, xTranscendVersion, c.ClientIP())
		c.AbortWithStatus(http.StatusForbidden)
		return false
	}

	return true
}

func (h *Handler) GetConfig(c *gin.Context) {
	// 记录请求的所有重要 header（用于调试）
	log.Printf("OpenConnect: GET/POST / - Request headers from %s:", c.ClientIP())
	log.Printf("  Connection: %s", c.GetHeader("Connection"))
	log.Printf("  User-Agent: %s", c.GetHeader("User-Agent"))
	log.Printf("  X-Aggregate-Auth: %s", c.GetHeader("X-Aggregate-Auth"))
	log.Printf("  X-Transcend-Version: %s", c.GetHeader("X-Transcend-Version"))
	log.Printf("  Accept: %s", c.GetHeader("Accept"))
	log.Printf("  Content-Type: %s", c.GetHeader("Content-Type"))

	// 安全验证：验证 X-Aggregate-Auth 和 X-Transcend-Version 头部
	// 先验证安全头部，这样可以准确识别 VPN 客户端
	if !validateSecureHeaders(c) {
		return
	}

	// 注意：connectHandler 已经处理了 Connection header，强制设置为 keep-alive
	// 这里不再需要检查，因为 connectHandler 已经确保 VPN 客户端使用 keep-alive
	// 如果客户端发送了 Connection: close，connectHandler 会强制协商为 keep-alive

	// 读取请求体
	bodyBytes, err := c.GetRawData()
	if err != nil {
		log.Printf("OpenConnect: Failed to read request body: %v", err)
		h.sendAuthForm(c)
		return
	}

	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	var authReq AuthRequest
	requestType := "init" // 默认类型

	if len(bodyBytes) > 0 {
		// 记录请求体内容（用于调试，完整内容）
		log.Printf("OpenConnect: [REQUEST] Client sent XML (length: %d bytes):\n%s", len(bodyBytes), string(bodyBytes))

		// 尝试解析 XML
		if bytes.HasPrefix(bytes.TrimSpace(bodyBytes), []byte("<?xml")) {
			if err := xml.Unmarshal(bodyBytes, &authReq); err == nil {
				requestType = authReq.Type
				log.Printf("OpenConnect: Parsed XML request - type: %s, username: %s", requestType, authReq.Auth.Username)
			} else {
				log.Printf("OpenConnect: Failed to parse XML request: %v", err)
			}
		} else {
			// 如果不是 XML，尝试解析表单格式（客户端可能使用表单提交用户名密码）
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			if err := c.Request.ParseForm(); err == nil {
				// 检查是否包含用户名和密码（表单格式的认证请求）
				username := c.Request.PostForm.Get("username")
				password := c.Request.PostForm.Get("password")
				otpCode := c.Request.PostForm.Get("otp-code")
				passwordToken := c.Request.PostForm.Get("password-token")
				if username != "" && (password != "" || (otpCode != "" && passwordToken != "")) {
					// 这是表单格式的认证请求，应该调用 Authenticate
					log.Printf("OpenConnect: Detected form-based authentication request (username: %s)", username)
					h.Authenticate(c)
					return
				}
			}
		}
	}

	log.Printf("OpenConnect: Processing request type: %s", requestType)

	switch requestType {
	case "init":
		log.Printf("OpenConnect: Sending auth form (init request)")
		h.sendAuthForm(c)
		return

	case "logout":
		log.Printf("OpenConnect: Handling logout request")
		h.handleLogout(c)
		return

	case "auth-reply":
		log.Printf("OpenConnect: Processing auth-reply request")
		h.Authenticate(c)
		return

	default:
		log.Printf("OpenConnect: Unknown request type '%s', sending auth form", requestType)
		h.sendAuthForm(c)
		return
	}
}

// AuthResponse OpenConnect 认证响应
type AuthResponse struct {
	XMLName xml.Name `xml:"config-auth"`
	Client  string   `xml:"client,attr"`
	Type    string   `xml:"type,attr"`
	Auth    struct {
		ID      string `xml:"id,attr"`
		Message string `xml:"message,omitempty"`
		Error   string `xml:"error,omitempty"`
	} `xml:"auth"`
}

// AuthRequest OpenConnect 认证请求结构（客户端发送）
type AuthRequest struct {
	XMLName xml.Name `xml:"config-auth"`
	Type    string   `xml:"type,attr"` // auth-reply, auth-request等
	Opaque  struct {
		TunnelGroup string `xml:"tunnel-group"` // Cisco Secure Client 的 default_group 参数
		GroupSelect string `xml:"group-select"` // 客户端选择的组（Cisco Secure Client 和 OpenConnect 都支持）
	} `xml:"opaque"`
	Auth struct {
		Username      string `xml:"username"`
		Password      string `xml:"password"`       // 第一步：密码
		PasswordToken string `xml:"password-token"` // 第二步：密码验证token
		OTPCode       string `xml:"otp-code"`       // OTP代码（多步骤认证时使用）
	} `xml:"auth"`
}

// Authenticate 处理认证请求
func (h *Handler) Authenticate(c *gin.Context) {
	if !validateSecureHeaders(c) {
		return // validateSecureHeaders 已经设置了 403 响应
	}

	clientIP := c.ClientIP()

	// 检查密码爆破防护
	if h.bruteforceProtection != nil {
		blocked, blockedUntil := h.bruteforceProtection.IsBlocked(clientIP)
		if blocked {
			remainingTime := time.Until(blockedUntil)
			h.sendAuthError(c, fmt.Sprintf("IP address is temporarily blocked due to too many failed login attempts. Please try again after %v", remainingTime.Round(time.Second)))
			return
		}
	}

	var username, password string

	bodyBytes, err := c.GetRawData()
	if err != nil {
		log.Printf("OpenConnect: Failed to read request body: %v", err)
		h.sendAuthError(c, "Failed to read request")
		return
	}

	// 恢复请求体，供后续解析使用
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// 1. 首先尝试解析 XML（即使 Content-Type 不是 xml，OpenConnect 也可能发送 XML）
	var authReq AuthRequest
	var xmlParsed bool
	if len(bodyBytes) > 0 && bytes.HasPrefix(bytes.TrimSpace(bodyBytes), []byte("<?xml")) {
		if err := xml.Unmarshal(bodyBytes, &authReq); err == nil {
			xmlParsed = true
			username = authReq.Auth.Username
			password = authReq.Auth.Password
			passwordTokenFromXML := authReq.Auth.PasswordToken

			// 检查是否是初始化请求（type="init" 或 type="auth-reply"但没有凭证）
			if (authReq.Type == "init" || authReq.Type == "auth-reply") && username == "" && password == "" && passwordTokenFromXML == "" {
				h.sendAuthForm(c)
				return
			}
		}
	}

	// 2. 如果 XML 解析失败或没有解析到，尝试表单解析
	if username == "" || password == "" {
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		if err := c.Request.ParseForm(); err == nil {
			username = c.Request.PostForm.Get("username")
			password = c.Request.PostForm.Get("password")
		}

		// 如果表单为空，尝试从 URL 查询参数获取
		if username == "" || password == "" {
			username = c.Query("username")
			password = c.Query("password")
		}
	}

	// 3. 最后尝试 Basic Auth（如果前面都没解析到）
	if username == "" || password == "" {
		u, p, ok := c.Request.BasicAuth()
		if ok {
			username = u
			password = p
		}
	}

	// 检查是否有凭证（password或password-token）
	var hasPasswordToken bool
	if xmlParsed {
		hasPasswordToken = authReq.Auth.PasswordToken != ""
		if username == "" && authReq.Auth.Username != "" {
			username = authReq.Auth.Username
		}
		if password == "" && authReq.Auth.Password != "" {
			password = authReq.Auth.Password
		}
	}
	// 如果XML中没有，检查表单
	if !hasPasswordToken {
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		if err := c.Request.ParseForm(); err == nil {
			hasPasswordToken = c.Request.PostForm.Get("password-token") != ""
			if username == "" {
				formUsername := c.Request.PostForm.Get("username")
				if formUsername != "" {
					username = formUsername
				}
			}
			// 如果表单中有password但之前没提取到，现在提取
			if password == "" {
				formPassword := c.Request.PostForm.Get("password")
				if formPassword != "" {
					password = formPassword
					log.Printf("OpenConnect: Extracted password from form (length: %d)", len(password))
				}
			}
			// 如果表单中有password但之前没提取到，现在提取
			if password == "" {
				formPassword := c.Request.PostForm.Get("password")
				if formPassword != "" {
					password = formPassword
					log.Printf("OpenConnect: Extracted password from form (length: %d)", len(password))
				}
			}
		}
	}

	// 如果既没有password也没有password-token，则认证失败
	if username == "" || (password == "" && !hasPasswordToken) {
		log.Printf("OpenConnect: Authentication failed - no credentials provided (username: %s, has password: %v, has token: %v)",
			username, password != "", hasPasswordToken)
		h.sendAuthError(c, "Username and password required")
		return
	}

	// 验证用户
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
		log.Printf("OpenConnect: LDAP authenticator created: Host=%s, Port=%d, UseSSL=%v, SkipTLSVerify=%v",
			ldapConfig.Host, ldapConfig.Port, ldapConfig.UseSSL, ldapConfig.SkipTLSVerify)
	}

	// 尝试 LDAP 认证（如果启用）
	if ldapAuth != nil && ldapConfig.Enabled {
		var existingUser models.User
		userExistsInDB := database.DB.Where("username = ?", username).First(&existingUser).Error == nil

		if userExistsInDB {
			if existingUser.Source == models.UserSourceLDAP {
				// LDAP用户，使用LDAP认证
				// 检查是否是OTP多步骤认证的第二步（有OTP代码和密码token）
				var otpCodeFromRequest string
				var passwordTokenFromRequest string
				if len(bodyBytes) > 0 && bytes.HasPrefix(bytes.TrimSpace(bodyBytes), []byte("<?xml")) {
					var authReq AuthRequest
					if err := xml.Unmarshal(bodyBytes, &authReq); err == nil {
						otpCodeFromRequest = authReq.Auth.OTPCode
						passwordTokenFromRequest = authReq.Auth.PasswordToken
					}
				}
				if otpCodeFromRequest == "" || passwordTokenFromRequest == "" {
					// 从表单获取OTP代码和密码token
					c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
					if err := c.Request.ParseForm(); err == nil {
						otpCodeFromRequest = c.Request.PostForm.Get("otp-code")
						passwordTokenFromRequest = c.Request.PostForm.Get("password-token")
					}
				}

				// 如果用户启用了OTP，且提供了OTP代码和密码token，说明是第二步认证
				if existingUser.OTPEnabled && existingUser.OTPSecret != "" && otpCodeFromRequest != "" && passwordTokenFromRequest != "" {
					// 第二步：验证密码token和OTP代码
					if !h.verifyPasswordToken(passwordTokenFromRequest, username) {
						log.Printf("OpenConnect: Invalid password token for LDAP user %s (OTP step 2)", username)
						h.sendAuthError(c, "Session expired. Please login again.")
						return
					}

					// 验证OTP代码
					otpAuth := auth.NewOTPAuthenticator("ZVPN")
					if !otpAuth.ValidateOTP(existingUser.OTPSecret, otpCodeFromRequest) {
						log.Printf("OpenConnect: Invalid OTP code for LDAP user %s", username)
						auditLogger := policy.GetAuditLogger()
						if auditLogger != nil {
							auditLogger.LogAuthWithIP(existingUser.ID, username, models.AuditLogActionLogin, "failed",
								fmt.Sprintf("LDAP password correct but OTP verification failed. Source IP: %s", clientIP), clientIP, 0)
						}
						if h.bruteforceProtection != nil {
							blocked, _, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
							if blocked {
								h.sendAuthError(c, fmt.Sprintf("Too many failed login attempts. IP address blocked until %v", blockedUntil.Format(time.RFC3339)))
								return
							}
						}
						h.sendOTPRequest(c, username, "Invalid OTP code. Please try again.")
						return
					}

					// OTP验证成功，重新加载用户（包含用户组和策略）
					database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").Preload("Groups.Policies.ExcludeRoutes").
						Where("username = ?", username).First(&user)
					// 计算用户的策略（从用户组获取）
					if policy := user.GetPolicy(); policy != nil {
						user.PolicyID = policy.ID
						user.Policy = *policy
					}

					isLDAPAuth = true
					log.Printf("OpenConnect: ✓ LDAP user %s authenticated (password correct, OTP correct)", username)
					// OTP验证成功，继续后续的认证成功流程
				} else {
					// 如果用户启用了OTP但没有提供OTP代码，说明是第一步，只验证密码
					ldapUser, err := ldapAuth.Authenticate(username, password)
					if err == nil {
						// LDAP 认证成功，同步用户到本地数据库
						if err := database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").Preload("Groups.Policies.ExcludeRoutes").
							Where("username = ?", username).First(&user).Error; err != nil {
							// 用户不存在，创建新用户
							user = models.User{
								Username: username,
								Email:    ldapUser.Email,
								IsAdmin:  ldapUser.IsAdmin,
								IsActive: true,
								Source:   models.UserSourceLDAP, // 标记为LDAP用户
								LDAPDN:   ldapUser.DN,
								FullName: ldapUser.FullName,
							}
							if len(ldapUser.Attributes) > 0 {
								if attrsJSON, err := json.Marshal(ldapUser.Attributes); err == nil {
									user.LDAPAttributes = string(attrsJSON)
								}
							}
							if err := database.DB.Create(&user).Error; err != nil {
								log.Printf("OpenConnect: Failed to create LDAP user %s: %v", username, err)
								h.sendAuthError(c, "Failed to create user")
								return
							}

							// 为新创建的 LDAP 用户分配默认用户组
							// 管理员用户分配到 admin 组，普通用户分配到 default 组（如果不存在则创建）
							var defaultGroup models.UserGroup
							// 统一使用 "admin" 作为默认用户组（首次部署时已创建）
							groupName := "admin"
							if err := database.DB.Where("name = ?", groupName).First(&defaultGroup).Error; err != nil {
								log.Printf("OpenConnect: Warning: Default user group 'admin' not found, LDAP user %s will have no groups (may affect VPN access)", username)
							}

							// 分配用户组
							if defaultGroup.ID > 0 {
								if err := database.DB.Model(&user).Association("Groups").Append(&defaultGroup); err != nil {
									log.Printf("OpenConnect: Warning: Failed to assign group '%s' to LDAP user %s: %v", groupName, username, err)
								} else {
									log.Printf("OpenConnect: ✓ LDAP user %s assigned to group '%s'", username, groupName)
								}
							} else {
								log.Printf("OpenConnect: Warning: User group '%s' not found, LDAP user %s has no groups (may affect VPN access)", groupName, username)
							}

							log.Printf("OpenConnect: ✓ LDAP user created: %s (email: %s, fullname: %s, admin: %v)",
								username, ldapUser.Email, ldapUser.FullName, ldapUser.IsAdmin)

							// 重新加载用户（包含用户组和策略）
							database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").Preload("Groups.Policies.ExcludeRoutes").
								Where("username = ?", username).First(&user)
							// 计算用户的策略（从用户组获取）
							if policy := user.GetPolicy(); policy != nil {
								user.PolicyID = policy.ID
								user.Policy = *policy
							}
						} else {
							// 用户已存在，检查是否被禁用
							if !user.IsActive {
								log.Printf("OpenConnect: User %s is disabled, rejecting LDAP authentication", username)
								h.sendAuthError(c, "您的账户已被禁用，无法连接VPN。请联系管理员激活账户。")
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
									log.Printf("OpenConnect: Failed to update LDAP user %s: %v", username, err)
								} else {
									log.Printf("OpenConnect: ✓ LDAP user synced: %s (email: %s, fullname: %s, admin: %v)",
										username, ldapUser.Email, ldapUser.FullName, ldapUser.IsAdmin)
								}
								// 重新加载用户（包含用户组和策略）
								database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").Preload("Groups.Policies.ExcludeRoutes").
									Where("username = ?", username).First(&user)
								// 计算用户的策略（从用户组获取）
								if policy := user.GetPolicy(); policy != nil {
									user.PolicyID = policy.ID
									user.Policy = *policy
								}
							}
						}

						isLDAPAuth = true
						log.Printf("OpenConnect: ✓ User %s authenticated via LDAP (password correct)", username)

						// LDAP密码认证成功后，如果用户启用了OTP，发送OTP请求页面（多步骤认证的第一步）
						if user.OTPEnabled && user.OTPSecret != "" {
							log.Printf("OpenConnect: LDAP password correct for user %s, requesting OTP code", username)
							h.sendOTPRequest(c, username, "")
							return
						}
						// LDAP认证成功（密码正确，如果启用了OTP则OTP也正确）
					} else {
						auditLogger := policy.GetAuditLogger()
						if auditLogger != nil {
							auditLogger.LogAuthWithIP(existingUser.ID, username, models.AuditLogActionLogin, "failed",
								fmt.Sprintf("LDAP authentication failed: %v. Source IP: %s", err, clientIP), clientIP, 0)
						}
						if h.bruteforceProtection != nil {
							blocked, _, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
							if blocked {
								h.sendAuthError(c, fmt.Sprintf("Too many failed login attempts. IP address blocked until %v", blockedUntil.Format(time.RFC3339)))
								return
							}
						}
						log.Printf("OpenConnect: ✗ LDAP authentication failed for LDAP user %s: %v", username, err)
						h.sendAuthError(c, "Invalid credentials")
						return
					}
				}
			} else {
				// 系统账户，跳过LDAP认证，直接使用数据库认证
				log.Printf("OpenConnect: User %s is a system account (source: %s), skipping LDAP authentication", username, existingUser.Source)
				// 不设置 isLDAPAuth，让后续代码使用数据库认证
			}
		} else {
			// 用户不存在于数据库中，尝试LDAP认证
			// 注意：如果LDAP认证失败，不应该fallback到本地认证，因为用户不存在于数据库中
			// 只有LDAP认证成功才能创建新用户
			var ldapPassword = password
			ldapUser, err := ldapAuth.Authenticate(username, ldapPassword)
			if err == nil {
				user = models.User{
					Username: username,
					Email:    ldapUser.Email,
					IsAdmin:  ldapUser.IsAdmin,
					IsActive: true,
					Source:   models.UserSourceLDAP, // 标记为LDAP用户
					LDAPDN:   ldapUser.DN,
					FullName: ldapUser.FullName,
					// PasswordHash 留空，LDAP用户不需要存储密码（认证由LDAP服务器完成）
				}
				if len(ldapUser.Attributes) > 0 {
					if attrsJSON, err := json.Marshal(ldapUser.Attributes); err == nil {
						user.LDAPAttributes = string(attrsJSON)
					}
				}
				if err := database.DB.Create(&user).Error; err != nil {
					log.Printf("OpenConnect: Failed to create LDAP user %s: %v", username, err)
					h.sendAuthError(c, "Failed to create user")
					return
				}

				// 为新创建的 LDAP 用户分配默认用户组（统一使用 "admin" 组）
				var defaultGroup models.UserGroup
				groupName := "admin"
				if err := database.DB.Where("name = ?", groupName).First(&defaultGroup).Error; err == nil {
					database.DB.Model(&user).Association("Groups").Append(&defaultGroup)
				} else {
					log.Printf("OpenConnect: Warning: Default user group 'admin' not found, LDAP user %s will have no groups (may affect VPN access)", username)
				}

				// 重新加载用户（包含用户组和策略）
				database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").
					Where("username = ?", username).First(&user)
				// 计算用户的策略（从用户组获取）
				if policy := user.GetPolicy(); policy != nil {
					user.PolicyID = policy.ID
					user.Policy = *policy
				}

				isLDAPAuth = true
				log.Printf("OpenConnect: ✓ LDAP user created and authenticated: %s", username)
			} else {
				// LDAP 认证失败，用户不存在于数据库中，直接返回错误
				// 不fallback到本地认证，因为用户不存在于数据库中，本地认证肯定会失败
				auditLogger := policy.GetAuditLogger()
				if auditLogger != nil {
					auditLogger.LogAuthWithIP(0, username, models.AuditLogActionLogin, "failed",
						fmt.Sprintf("LDAP authentication failed (user not in DB): %v. Source IP: %s", err, clientIP), clientIP, 0)
				}
				if h.bruteforceProtection != nil {
					blocked, _, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
					if blocked {
						h.sendAuthError(c, fmt.Sprintf("Too many failed login attempts. IP address blocked until %v", blockedUntil.Format(time.RFC3339)))
						return
					}
				}
				log.Printf("OpenConnect: ✗ LDAP authentication failed for %s (user not in DB): %v", username, err)
				h.sendAuthError(c, "Invalid credentials")
				return
			}
		}
	}

	// 本地认证（如果 LDAP 未启用或认证失败）
	if !isLDAPAuth {
		if err := database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").Preload("Groups.Policies.ExcludeRoutes").
			Where("username = ?", username).First(&user).Error; err != nil {
			log.Printf("OpenConnect: User not found: %s", username)
			// 记录认证失败审计日志
			auditLogger := policy.GetAuditLogger()
			if auditLogger != nil {
				auditLogger.LogAuthWithIP(0, username, models.AuditLogActionLogin, "failed",
					fmt.Sprintf("User not found. Source IP: %s", clientIP), clientIP, 0)
			}

			// 记录密码爆破尝试
			if h.bruteforceProtection != nil {
				blocked, remaining, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
				if blocked {
					h.sendAuthError(c, fmt.Sprintf("Too many failed login attempts. IP address blocked until %v", blockedUntil.Format(time.RFC3339)))
					return
				}
				// 可以在这里添加剩余尝试次数的提示（如果需要）
				_ = remaining
			}
			h.sendAuthError(c, "Invalid credentials")
			return
		}

		// 检查：如果用户是LDAP用户，但LDAP已关闭，不允许登录
		// 因为LDAP用户的密码存储在LDAP服务器中，本地数据库没有密码
		if user.Source == models.UserSourceLDAP && !ldapConfig.Enabled {
			log.Printf("OpenConnect: User %s is an LDAP user but LDAP is disabled", username)
			auditLogger := policy.GetAuditLogger()
			if auditLogger != nil {
				auditLogger.LogAuthWithIP(user.ID, username, models.AuditLogActionLogin, "failed",
					fmt.Sprintf("LDAP user cannot login when LDAP is disabled. Source IP: %s", clientIP), clientIP, 0)
			}
			h.sendAuthError(c, "LDAP authentication is disabled. Please contact administrator.")
			return
		}

		if !user.IsActive {
			log.Printf("OpenConnect: User %s is not active", username)
			// 记录认证失败审计日志
			auditLogger := policy.GetAuditLogger()
			if auditLogger != nil {
				clientIP := c.ClientIP()
				auditLogger.LogAuthWithIP(user.ID, username, models.AuditLogActionLogin, "failed",
					fmt.Sprintf("Account disabled. Source IP: %s", clientIP), clientIP, 0)
			}
			h.sendAuthError(c, "您的账户已被禁用，无法连接VPN。请联系管理员激活账户。")
			return
		}

		// 检查是否启用了OTP（根据用户配置动态决定）
		// 只有OTPEnabled为true且OTPSecret不为空时，才需要双因素认证
		if user.OTPEnabled && user.OTPSecret != "" {
			// 多步骤认证：先验证密码，再验证OTP
			// 检查请求中是否包含OTP代码和密码token（多步骤认证的第二步）
			var otpCode string
			var passwordToken string
			if len(bodyBytes) > 0 && bytes.HasPrefix(bytes.TrimSpace(bodyBytes), []byte("<?xml")) {
				var authReq AuthRequest
				if err := xml.Unmarshal(bodyBytes, &authReq); err == nil {
					otpCode = authReq.Auth.OTPCode
					passwordToken = authReq.Auth.PasswordToken
					// 如果XML中有用户名，使用XML中的用户名
					if authReq.Auth.Username != "" {
						username = authReq.Auth.Username
					}
					log.Printf("OpenConnect: XML parsed for OTP step - username: %s, has OTP: %v, has token: %v",
						username, otpCode != "", passwordToken != "")
				}
			}
			if otpCode == "" || passwordToken == "" {
				// 从表单获取OTP代码和密码token
				c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				if err := c.Request.ParseForm(); err == nil {
					otpCode = c.Request.PostForm.Get("otp-code")
					passwordToken = c.Request.PostForm.Get("password-token")
					// 如果表单中有用户名，使用表单中的用户名
					if formUsername := c.Request.PostForm.Get("username"); formUsername != "" {
						username = formUsername
					}
					log.Printf("OpenConnect: Form parsed for OTP step - username: %s, has OTP: %v, has token: %v",
						username, otpCode != "", passwordToken != "")
				}
			}

			// 检查是否是OTP设置流程（首次登录）
			var isOTPSetup bool
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			if err := c.Request.ParseForm(); err == nil {
				if c.Request.PostForm.Get("otp-setup") == "true" {
					isOTPSetup = true
				}
			}

			// 如果提供了OTP代码和密码token，进行第二步验证
			if otpCode != "" && passwordToken != "" {
				// 验证密码token（证明第一步密码验证已通过）
				if !h.verifyPasswordToken(passwordToken, username) {
					log.Printf("OpenConnect: Invalid password token for user %s (OTP step 2)", username)
					h.sendAuthError(c, "Session expired. Please login again.")
					return
				}

				// 如果是OTP设置流程，验证OTP代码后启用OTP
				if isOTPSetup {
					// 重新加载用户（确保获取最新的OTPSecret）
					if err := database.DB.Where("username = ?", username).First(&user).Error; err != nil {
						log.Printf("OpenConnect: Failed to reload user %s for OTP setup", username)
						h.sendAuthError(c, "User not found")
						return
					}

					// 验证OTP代码
					if user.OTPSecret == "" {
						log.Printf("OpenConnect: User %s has no OTP secret during setup", username)
						h.sendOTPSetupRequest(c, username)
						return
					}

					otpAuth := auth.NewOTPAuthenticator("ZVPN")
					if !otpAuth.ValidateOTP(user.OTPSecret, otpCode) {
						log.Printf("OpenConnect: Invalid OTP code for user %s during setup", username)
						h.sendOTPSetupRequest(c, username)
						return
					}

					// OTP验证成功，启用OTP
					user.OTPEnabled = true
					if err := database.DB.Save(&user).Error; err != nil {
						log.Printf("OpenConnect: Failed to enable OTP for user %s: %v", username, err)
						h.sendAuthError(c, "Failed to enable OTP")
						return
					}

					// 重新加载用户（包含用户组和策略）
					database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").Preload("Groups.Policies.ExcludeRoutes").
						Where("username = ?", username).First(&user)
					log.Printf("OpenConnect: User %s OTP setup completed and enabled", username)
				} else {
					// 正常的OTP验证流程
					otpAuth := auth.NewOTPAuthenticator("ZVPN")
					if !otpAuth.ValidateOTP(user.OTPSecret, otpCode) {
						log.Printf("OpenConnect: Invalid OTP code for user %s", username)
						// 记录OTP验证失败审计日志
						auditLogger := policy.GetAuditLogger()
						if auditLogger != nil {
							auditLogger.LogAuthWithIP(user.ID, username, models.AuditLogActionLogin, "failed",
								fmt.Sprintf("Invalid OTP code. Source IP: %s", clientIP), clientIP, 0)
						}

						// 记录密码爆破尝试（OTP 验证失败也算一次失败）
						if h.bruteforceProtection != nil {
							blocked, remaining, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
							if blocked {
								h.sendAuthError(c, fmt.Sprintf("Too many failed login attempts. IP address blocked until %v", blockedUntil.Format(time.RFC3339)))
								return
							}
							_ = remaining
						}
						h.sendOTPRequest(c, username, "Invalid OTP code. Please try again.")
						return
					}

					log.Printf("OpenConnect: User %s authenticated successfully with password and OTP", username)
				}
			} else {
				// 第一步：只验证密码
				if !user.CheckPassword(password) {
					log.Printf("OpenConnect: Invalid password for user %s (OTP enabled, step 1)", username)
					// 记录认证失败审计日志
					auditLogger := policy.GetAuditLogger()
					if auditLogger != nil {
						auditLogger.LogAuthWithIP(user.ID, username, models.AuditLogActionLogin, "failed",
							fmt.Sprintf("Invalid password (OTP enabled). Source IP: %s", clientIP), clientIP, 0)
					}

					// 记录密码爆破尝试
					if h.bruteforceProtection != nil {
						blocked, remaining, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
						if blocked {
							h.sendAuthError(c, fmt.Sprintf("Too many failed login attempts. IP address blocked until %v", blockedUntil.Format(time.RFC3339)))
							return
						}
						_ = remaining
					}
					h.sendAuthError(c, "Invalid credentials")
					return
				}

				// 密码正确，要求输入OTP代码
				log.Printf("OpenConnect: Password correct for user %s, requesting OTP code", username)
				h.sendOTPRequest(c, username, "")
				return
			}
		} else if user.OTPEnabled && user.OTPSecret == "" {
			// 用户启用了OTP但还没有配置OTP密钥（首次登录场景）
			// 先验证密码
			if !user.CheckPassword(password) {
				log.Printf("OpenConnect: Invalid password for user %s (OTP enabled but not configured)", username)
				// 记录密码爆破尝试
				if h.bruteforceProtection != nil {
					blocked, remaining, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
					if blocked {
						h.sendAuthError(c, fmt.Sprintf("Too many failed login attempts. IP address blocked until %v", blockedUntil.Format(time.RFC3339)))
						return
					}
					_ = remaining
				}
				h.sendAuthError(c, "Invalid credentials")
				return
			}

			// 密码正确，要求用户配置OTP（显示二维码）
			log.Printf("OpenConnect: Password correct for user %s, requesting OTP setup (first login)", username)
			h.sendOTPSetupRequest(c, username)
			return
		} else {
			// 未启用OTP（OTPEnabled为false），直接验证密码
			if !user.CheckPassword(password) {
				log.Printf("OpenConnect: Invalid password for user %s", username)
				// 记录认证失败审计日志
				auditLogger := policy.GetAuditLogger()
				if auditLogger != nil {
					auditLogger.LogAuthWithIP(user.ID, username, models.AuditLogActionLogin, "failed",
						fmt.Sprintf("Invalid password. Source IP: %s", clientIP), clientIP, 0)
				}

				// 记录密码爆破尝试
				if h.bruteforceProtection != nil {
					blocked, remaining, blockedUntil := h.bruteforceProtection.RecordFailedAttempt(clientIP)
					if blocked {
						h.sendAuthError(c, fmt.Sprintf("Too many failed login attempts. IP address blocked until %v", blockedUntil.Format(time.RFC3339)))
						return
					}
					// 可以在这里添加剩余尝试次数的提示（如果需要）
					_ = remaining
				}
				h.sendAuthError(c, "Invalid credentials")
				return
			}
			log.Printf("OpenConnect: User %s authenticated successfully (OTP disabled)", username)
		}
	}

	// 多端并发登录控制：如果禁用且用户已连接，拒绝新的登录
	// 但是，如果用户标记为已连接但实际上没有活跃连接，自动重置状态
	if !h.config.VPN.AllowMultiClientLogin && user.Connected {
		// 检查是否真的有活跃连接
		if h.vpnServer != nil {
			_, hasActiveConnection := h.vpnServer.GetClient(user.ID)
			if !hasActiveConnection {
				// 用户标记为已连接，但实际上没有活跃连接，重置状态
				log.Printf("OpenConnect: User %s marked as connected but no active connection found, resetting status", username)
				user.Connected = false
				user.VPNIP = ""
				if err := database.DB.Model(&user).Select("connected", "vpn_ip", "updated_at").Updates(user).Error; err != nil {
					log.Printf("OpenConnect: Failed to reset user connection status: %v", err)
				} else {
					log.Printf("OpenConnect: User %s connection status reset successfully", username)
				}
			} else {
				// 确实有活跃连接，拒绝新登录
				log.Printf("OpenConnect: User %s already connected, multi-client login disabled", username)
				h.sendAuthError(c, "该账号已在线，已禁止多端同时登录")
				return
			}
		} else {
			// VPN服务器未初始化，无法检查，直接拒绝
			log.Printf("OpenConnect: User %s already connected, multi-client login disabled (VPN server not initialized)", username)
			h.sendAuthError(c, "该账号已在线，已禁止多端同时登录")
			return
		}
	}

	// 认证成功 - 分配 VPN IP（但不设置 Connected，等连接真正建立后再设置）
	sessionID := fmt.Sprintf("webvpn-%s-%d", username, user.ID)

	// 分配或重用 VPN IP（如果用户已经连接，重用现有 IP）
	if user.VPNIP == "" {
		_, ipNet, _ := net.ParseCIDR(h.config.VPN.Network)
		ipPool, err := vpn.NewIPPool(ipNet)
		if err != nil {
			h.sendAuthError(c, "IP allocation failed")
			return
		}

		// 跳过网关 IP（优先使用TUN设备IP，支持多服务器横向扩容）
		var gatewayIP net.IP
		if h.vpnServer != nil {
			gatewayIP = h.vpnServer.GetVPNGatewayIP()
		}
		if gatewayIP == nil {
			// Fallback to configured gateway IP
			gatewayIP = make(net.IP, len(ipNet.IP))
			copy(gatewayIP, ipNet.IP)
			gatewayIP[len(gatewayIP)-1] = 1
		}

		vpnIP, err := ipPool.Allocate()
		if err != nil {
			h.sendAuthError(c, "No available IPs")
			return
		}

		// 如果分配到网关 IP，再分配一次
		if vpnIP.Equal(gatewayIP) {
			vpnIP, err = ipPool.Allocate()
			if err != nil {
				h.sendAuthError(c, "No available IPs")
				return
			}
		}

		user.VPNIP = vpnIP.String()
		// 注意：不在这里设置 Connected，等连接真正建立后再设置
		// 重要：使用 Select 只更新 VPNIP 字段，避免覆盖其他字段（特别是 TunnelMode）
		// 如果使用 Save(&user)，可能会用内存中的旧值覆盖数据库中的新值
		if err := database.DB.Model(&user).Select("vpn_ip", "updated_at").Updates(map[string]interface{}{
			"vpn_ip": user.VPNIP,
		}).Error; err != nil {
			log.Printf("OpenConnect: Warning - Failed to save VPN IP for user %s: %v", user.Username, err)
		}

		log.Printf("OpenConnect: Allocated IP %s to user %s (gateway: %s)",
			user.VPNIP, user.Username, gatewayIP.String())
	}

	// 设置 cookie
	c.SetCookie("webvpn", sessionID, 3600, "/", "", true, true)

	log.Printf("OpenConnect: User %s authenticated successfully", username)

	// 登录成功，清除该IP的失败记录
	if h.bruteforceProtection != nil {
		h.bruteforceProtection.RecordSuccess(clientIP)
	}

	// 重新加载用户以确保获取最新的 TunnelMode 值（防止缓存问题）
	// 注意：在认证过程中，用户对象可能被多次修改，需要重新加载以确保获取数据库中的最新值
	var freshUser models.User
	if err := database.DB.Where("id = ?", user.ID).First(&freshUser).Error; err == nil {
		// 使用最新加载的用户对象，但保留已加载的策略信息
		user.TunnelMode = freshUser.TunnelMode
	} else {
		log.Printf("OpenConnect: Warning - Failed to reload user %s for TunnelMode: %v", user.Username, err)
	}

	// 计算并设置用户策略（从用户组获取）
	if policy := user.GetPolicy(); policy != nil {
		user.PolicyID = policy.ID
		user.Policy = *policy
	}

	// 计算网络掩码
	_, ipNet, _ := net.ParseCIDR(h.config.VPN.Network)
	// mask := net.IP(ipNet.Mask)

	// 计算网关 IP（从前面计算的 ipNet 使用）
	gatewayIP := make(net.IP, len(ipNet.IP))
	copy(gatewayIP, ipNet.IP)
	gatewayIP[len(gatewayIP)-1] = 1

	// 获取用户的隧道模式（默认 split）
	tunnelMode := getUserTunnelMode(&user)

	// 注意：全局模式下总是排除私有IP（类似 AnyLink），不依赖 AllowLan 配置
	// 分隧道模式下，AllowLan 配置保留用于未来扩展（当前分隧道模式本身就不路由本地网络）

	// 构建路由信息（根据用户策略和隧道模式）
	var splitIncludeRoutes []string
	var routeXML string
	var defaultRoute string
	var splitExcludeRoutes []string // 用于存储排除路由（本地网络）

	if tunnelMode == "full" {
		// 全局模式：所有流量都走 VPN
		defaultRoute = "true"
		routeXML = "" // 全局模式不需要 split-include

		// 根据配置决定是否排除本地网络（类似 AnyLink 的 allow_lan）
		// allow_lan 设置优先于全局路由模式，会覆盖全局路由设置对本地网络的影响
		// 当 allow_lan=true 时，排除本地网络流量，需要客户端同时开启"Allow Local Lan"选项
		if h.config.VPN.AllowLan {
			// 添加 AnyLink 风格的排除规则（0.0.0.0/255.255.255.255）
			// 这个规则会覆盖全局路由设置对本地网络的影响，告诉客户端排除本地网络
			// 需要客户端同时开启 "Allow Local Lan" 选项才能生效
			splitExcludeRoutes = append(splitExcludeRoutes, "0.0.0.0/255.255.255.255")
			log.Printf("OpenConnect: Full tunnel mode with allow_lan=true - Added AnyLink-style exclude rule (0.0.0.0/255.255.255.255), requires client to enable 'Allow Local Lan' option")
			log.Printf("OpenConnect: Local network traffic bypasses VPN, all other traffic goes through VPN tunnel")
		} else {
			log.Printf("OpenConnect: Full tunnel mode with allow_lan=false - All traffic goes through VPN (no local network exclusion)")
		}

		// 添加策略中配置的自定义排除路由（用于全局模式）
		// 这些路由是用户自定义的，用于排除特定的网段不走VPN
		if user.PolicyID != 0 && len(user.Policy.ExcludeRoutes) > 0 {
			excludeRouteMap := make(map[string]bool) // 用于去重
			for _, excludeRoute := range user.Policy.ExcludeRoutes {
				// 去重：避免重复添加相同的排除路由
				if excludeRouteMap[excludeRoute.Network] {
					continue
				}
				splitExcludeRoutes = append(splitExcludeRoutes, excludeRoute.Network)
				excludeRouteMap[excludeRoute.Network] = true
			}
			log.Printf("OpenConnect: Full tunnel mode - Added %d custom exclude routes from policy: %v", len(user.Policy.ExcludeRoutes), func() []string {
				var routes []string
				for _, r := range user.Policy.ExcludeRoutes {
					routes = append(routes, r.Network)
				}
				return routes
			}())
		}
	} else {
		// 分隧道模式：只路由特定网段
		defaultRoute = "false"

		// 使用 map 去重路由
		routeMap := make(map[string]bool)

		// 首先添加VPN网络本身的路由，确保基本连通性（服务器、网关等）
		// 这对于ping服务器等基础功能是必需的
		splitIncludeRoutes = append(splitIncludeRoutes, h.config.VPN.Network)
		routeMap[h.config.VPN.Network] = true

		// Split-tunnel mode: 添加策略路由（去重）
		// 注意：自动过滤掉私有网络路由，确保本地网络不在 split-include 中
		if user.PolicyID != 0 && len(user.Policy.Routes) > 0 {
			for _, route := range user.Policy.Routes {
				// 去重：避免重复添加相同的路由
				if routeMap[route.Network] {
					continue
				}

				// 过滤掉私有网络路由，确保本地网络不走VPN
				// 这样可以避免本地网络流量被错误地路由到VPN
				if isPrivateNetwork(route.Network) {
					log.Printf("OpenConnect: Skipping private network route %s in split-tunnel mode (local network should not go through VPN)", route.Network)
					continue
				}

				splitIncludeRoutes = append(splitIncludeRoutes, route.Network)
				routeMap[route.Network] = true
			}
		}

		// 构建 split-include XML（使用 strings.Builder 提高性能）
		// 格式要求：IP + 掩码分开写
		var routeXMLBuilder strings.Builder
		for _, route := range splitIncludeRoutes {
			// 解析 CIDR 格式（如 192.168.0.0/16）为 IP 和掩码
			_, ipNet, err := net.ParseCIDR(route)
			if err != nil {
				log.Printf("OpenConnect: Failed to parse route %s: %v", route, err)
				continue
			}
			network := ipNet.IP.String()
			netmask := net.IP(ipNet.Mask).String()
			routeXMLBuilder.WriteString("\n\t\t<cstp:split-include>")
			routeXMLBuilder.WriteString("\n\t\t\t<cstp:network>")
			routeXMLBuilder.WriteString(network)
			routeXMLBuilder.WriteString("</cstp:network>")
			routeXMLBuilder.WriteString("\n\t\t\t<cstp:netmask>")
			routeXMLBuilder.WriteString(netmask)
			routeXMLBuilder.WriteString("</cstp:netmask>")
			routeXMLBuilder.WriteString("\n\t\t</cstp:split-include>")
		}
		routeXML = routeXMLBuilder.String()
	}

	// 获取服务器地址（用于添加主机路由保护和配置）
	serverHost := extractHostname(c.Request.Host)

	// 检查serverHost是否是IP地址
	isIP := net.ParseIP(serverHost) != nil
	noSplitDNSXML := ""
	// no-split-dns 只在分隧道模式下设置，全局模式下所有流量都走 VPN，不需要 no-split-dns
	if tunnelMode == "split" && !isIP {
		// 只有当serverHost是域名且为分隧道模式时才配置no-split-dns
		// no-split-dns用于指定哪些域名不使用VPN DNS解析（分隧道模式下）
		noSplitDNSXML = "\n\t\t<!-- no-split-dns: 指定哪些域名不使用VPN DNS解析（分隧道模式） -->\n\t\t<cstp:no-split-dns>" + serverHost + "</cstp:no-split-dns>"
	}

	// 获取DNS服务器配置（从策略中获取，如果没有则使用默认DNS）
	userDNSServers := getDNSServers(&user.Policy)

	// 构建DNS服务器列表
	// 只添加用户配置的DNS（从策略中获取）
	// 注意：不通过CSTP下发公网DNS，让客户端使用系统默认DNS（不走VPN）
	// 这样可以避免OpenConnect客户端为公网DNS IP自动添加路由到VPN
	var dnsServers []string

	// 添加用户配置的DNS（从策略中获取）
	if len(userDNSServers) > 0 {
		dnsServers = append(dnsServers, userDNSServers...)
		log.Printf("OpenConnect: Added user-configured DNS servers: %v", userDNSServers)
	}

	// CRITICAL: 在全局模式下，如果只配置了VPN网关作为DNS服务器，需要添加公网DNS作为备用
	// 这样可以避免VPN断开后DNS解析失败导致"Network is unreachable"错误
	// 因为当VPN断开时，客户端无法访问VPN网关IP（如10.8.0.1），如果没有备用DNS，DNS解析会失败
	// 注意：全局模式下，VPN退出后不应该影响客户端本地网络访问，所以需要提供备用DNS
	if tunnelMode == "full" && len(dnsServers) > 0 {
		// 计算VPN网关IP（通常是.1）
		var gatewayIP string
		_, ipNet, err := net.ParseCIDR(h.config.VPN.Network)
		if err == nil {
			gateway := make(net.IP, len(ipNet.IP))
			copy(gateway, ipNet.IP)
			gateway[len(gateway)-1] = 1
			gatewayIP = gateway.String()
		}

		// 检查DNS服务器列表
		hasPublicDNS := false
		hasVPNGatewayDNS := false
		for _, dns := range dnsServers {
			if isPublicDNS(dns) {
				hasPublicDNS = true
			}
			if gatewayIP != "" && dns == gatewayIP {
				hasVPNGatewayDNS = true
			}
		}

		// 如果只有VPN网关DNS，没有公网DNS，添加配置中的上游DNS作为备用
		if hasVPNGatewayDNS && !hasPublicDNS {
			// 从配置中获取上游DNS服务器（去掉端口号，CSTP配置只需要IP）
			fallbackDNS := ""
			if h.config.VPN.UpstreamDNS != "" {
				// 解析逗号分隔的DNS服务器列表，取第一个
				dnsList := strings.Split(h.config.VPN.UpstreamDNS, ",")
				if len(dnsList) > 0 {
					firstDNS := strings.TrimSpace(dnsList[0])
					// 去掉端口号（如果有）
					if colonPos := strings.Index(firstDNS, ":"); colonPos != -1 {
						firstDNS = firstDNS[:colonPos]
					}
					// 验证是否是有效的IP地址
					if net.ParseIP(firstDNS) != nil {
						fallbackDNS = firstDNS
					}
				}
			}

			// 如果配置中没有DNS或解析失败，使用默认的Cloudflare DNS
			if fallbackDNS == "" {
				fallbackDNS = "1.1.1.1"
				log.Printf("OpenConnect: Full tunnel mode - Using default fallback DNS %s (no upstream DNS configured)", fallbackDNS)
			} else {
				log.Printf("OpenConnect: Full tunnel mode - Using configured upstream DNS %s as fallback", fallbackDNS)
			}

			dnsServers = append(dnsServers, fallbackDNS)
			log.Printf("OpenConnect: Full tunnel mode - Added public DNS %s as fallback to prevent DNS resolution failure after disconnect (VPN gateway DNS: %s)", fallbackDNS, gatewayIP)
		}
	}

	dnsXML := ""
	for _, dns := range dnsServers {
		if dns != "" {
			dnsXML += "\n\t\t\t<cstp:server>" + dns + "</cstp:server>"
		}
	}

	// 检测客户端类型，用于日志记录和可能的 XML 格式调整
	clientType := h.clientDetector.Detect(c)
	isAnyConnect := clientType == ClientTypeAnyConnect

	// 构建完整的 XML 响应
	// 注意：根据 AnyConnect 协议，认证成功后应返回 type="auth-reply"
	// 获取证书信息（包括 hash 和自签名检测）
	certInfo := h.getServerCertInfo()
	certHash := certInfo.SHA1Hash
	if certHash == "" {
		certHash = "0000000000000000000000000000000000000000" // 默认值（如果无法读取证书）
	}

	// 从 sessionID 中提取 session-id（格式：webvpn-username-userID）
	sessionIDOnly := sessionID
	if parts := strings.Split(sessionID, "-"); len(parts) >= 3 {
		// 使用时间戳作为 session-id
		sessionIDOnly = strconv.FormatInt(time.Now().Unix(), 10)
	}

	// 计算 profile.xml 的 SHA1 hash（仅当 AnyConnect 客户端时需要）
	// OpenConnect 客户端不需要 profile.xml，跳过下载以优化连接速度
	var profileHash string
	var profileManifestXML string
	if isAnyConnect {
		// AnyConnect 客户端需要 profile.xml，计算 hash 并包含 manifest
		profileHash = h.getProfileHash(c)
		profileManifestXML = `
		<vpn-profile-manifest>
			<vpn rev="1.0">
				<file type="profile" service-type="user">
					<uri>/profile.xml</uri>
					<hash type="sha1">` + profileHash + `</hash>
				</file>
			</vpn>
		</vpn-profile-manifest>`
	}

	// 确保 XML 格式符合 AnyConnect 标准
	// aggregate-auth-version="2" 是 AnyConnect 4.x+ 的标准版本
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
	<session-id>` + sessionIDOnly + `</session-id>
	<session-token>` + sessionID + `</session-token>
	<auth id="success">
		<banner>欢迎连接 ZVPN</banner>
		<message id="0" param1="" param2=""></message>
	</auth>
	<capabilities>
		<crypto-supported>ssl-dhe</crypto-supported>
		<crypto-supported>ssl-rsa</crypto-supported>
		<crypto-supported>ssl-ecdh</crypto-supported>
		<crypto-supported>ssl-ecdhe</crypto-supported>
	</capabilities>
	<config client="vpn" type="private">
		<vpn-base-config>
			<server-cert-hash>` + certHash + `</server-cert-hash>
			<!-- 如果 serverHost 是域名，添加服务器主机名；如果是 IP，则不添加 -->
			` + func() string {
		if !isIP && serverHost != "" {
			return "			<server-hostname>" + serverHost + "</server-hostname>\n"
		}
		return ""
	}() + `			<!-- 如果是自签名证书，添加证书固定信息（pin-sha256） -->
			<!-- 这允许 OpenConnect 客户端通过证书固定接受自签名证书 -->
			` + func() string {
		if certInfo.IsSelfSigned && certInfo.SHA256Hash != "" {
			return "			<server-cert-pin-sha256>" + certInfo.SHA256Hash + "</server-cert-pin-sha256>\n"
		}
		return ""
	}() + `		</vpn-base-config>
		<opaque is-for="vpn-client"></opaque>` + profileManifestXML + `
	</config>
	<cstp:config xmlns:cstp="http://www.cisco.com/cstp">
		<!-- IP 地址配置 -->
		<cstp:address-pool>
			<cstp:primary-address>` + user.VPNIP + `</cstp:primary-address>
			<cstp:primary-netmask>` + net.IP(ipNet.Mask).String() + `</cstp:primary-netmask>
		</cstp:address-pool>

		<!-- MTU -->
		<cstp:mtu>` + strconv.Itoa(h.config.VPN.MTU) + `</cstp:mtu>

		<!-- DNS 服务器 -->
		<cstp:dns>` + dnsXML + `
		</cstp:dns>

		<!-- 隧道模式配置 -->
		<!-- full: 全局模式，所有流量走 VPN；split: 分隧道模式，只路由特定网段 -->
		<cstp:default-route>` + defaultRoute + `</cstp:default-route>
		
		<!-- 包含的路由（分隧道模式下，只有这些网段走 VPN） -->
		<!-- 注意：全局模式下不需要 split-include -->` + routeXML + noSplitDNSXML + `
		
		<!-- 排除路由（split-exclude）：用于排除本地网络，让本地网络流量不走 VPN 隧道 -->
		<!-- OpenConnect 客户端没有 "Allow Local Lan" 开关，需要在服务端自动处理 -->
		<!-- 在全局模式下，排除常见的私有IP地址段，确保本地网络流量不走VPN -->
		` + func() string {
		if len(splitExcludeRoutes) > 0 {
			var excludeXMLBuilder strings.Builder
			for _, route := range splitExcludeRoutes {
				// 特殊处理 AnyLink 风格的排除规则（0.0.0.0/255.255.255.255）
				if route == "0.0.0.0/255.255.255.255" {
					excludeXMLBuilder.WriteString("\n\t\t<cstp:split-exclude>")
					excludeXMLBuilder.WriteString("\n\t\t\t<cstp:network>0.0.0.0</cstp:network>")
					excludeXMLBuilder.WriteString("\n\t\t\t<cstp:netmask>255.255.255.255</cstp:netmask>")
					excludeXMLBuilder.WriteString("\n\t\t</cstp:split-exclude>")
					continue
				}

				// 解析标准 CIDR 格式（如 192.168.0.0/16）
				_, ipNet, err := net.ParseCIDR(route)
				if err != nil {
					log.Printf("OpenConnect: Failed to parse exclude route %s: %v", route, err)
					continue
				}
				network := ipNet.IP.String()
				netmask := net.IP(ipNet.Mask).String()
				excludeXMLBuilder.WriteString("\n\t\t<cstp:split-exclude>")
				excludeXMLBuilder.WriteString("\n\t\t\t<cstp:network>")
				excludeXMLBuilder.WriteString(network)
				excludeXMLBuilder.WriteString("</cstp:network>")
				excludeXMLBuilder.WriteString("\n\t\t\t<cstp:netmask>")
				excludeXMLBuilder.WriteString(netmask)
				excludeXMLBuilder.WriteString("</cstp:netmask>")
				excludeXMLBuilder.WriteString("\n\t\t</cstp:split-exclude>")
			}
			return excludeXMLBuilder.String()
		}
		return ""
	}() + `

		<!-- 超时配置 -->
		<cstp:idle-timeout>7200</cstp:idle-timeout>
		<cstp:session-timeout>86400</cstp:session-timeout>

		<!-- DTLS 配置（启用以提升性能） -->` + getDTLSConfig(h.config, c.Request.Host) + `

		<!-- 心跳和保活 -->
		<!-- 从配置读取，与 HTTP header 中的 X-CSTP-Keepalive 和 X-CSTP-DPD 保持一致 -->
		<!-- Keepalive: 防止 NAT/防火墙/代理设备关闭连接，默认 20 秒（AnyConnect 标准） -->
		<!-- DPD: 死连接检测，默认 30 秒 -->
		<!-- 注意：read timeout 应该略大于 keepalive 值，以便在超时前发送 keepalive -->
		<!-- TCP keepalive 由 X-CSTP-TCP-Keepalive 控制，XML 中不设置 -->
		<cstp:keepalive>` + func() string {
		cstpKeepalive := h.config.VPN.CSTPKeepalive
		if cstpKeepalive == 0 {
			cstpKeepalive = 20 // 默认值：20秒（AnyConnect 标准）
		}
		return strconv.Itoa(cstpKeepalive)
	}() + `</cstp:keepalive>
		<cstp:dpd>` + func() string {
		cstpDPD := h.config.VPN.CSTPDPD
		if cstpDPD == 0 {
			cstpDPD = 30 // 默认值：30秒
		}
		return strconv.Itoa(cstpDPD)
	}() + `</cstp:dpd>

		<!-- 压缩 -->
		<cstp:compression>` + getCompressionType(h.config) + `</cstp:compression>
	</cstp:config>
</config-auth>`

	c.Writer.Header().Del("Server")
	c.Writer.Header().Del("X-Powered-By")
	c.Header("Content-Type", "text/xml; charset=utf-8")
	c.Header("Content-Length", strconv.Itoa(len(xml)))
	c.Header("Connection", h.getConnectionHeader(c))
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	log.Printf("OpenConnect: Authentication successful for user %s, sending auth-reply response (type=\"auth-reply\")", user.Username)
	c.Data(http.StatusOK, "text/xml; charset=utf-8", []byte(xml))
}

// handleLogout 处理退出登录请求
func (h *Handler) handleLogout(c *gin.Context) {
	// 清除会话 cookie
	c.SetCookie("webvpn", "", -1, "/", "", true, true)

	// 返回退出登录确认
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
	<logout>
		<message>Logout successful</message>
	</logout>
</config-auth>`

	c.Writer.Header().Del("Server")
	c.Writer.Header().Del("X-Powered-By")
	c.Header("Content-Type", "text/xml; charset=utf-8")
	c.Header("Content-Length", strconv.Itoa(len(xml)))
	c.Header("Connection", h.getConnectionHeader(c))
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	c.Data(http.StatusOK, "text/xml; charset=utf-8", []byte(xml))
}

func (h *Handler) getConnectionHeader(c *gin.Context) string {
	return "keep-alive"
}

// sendAuthForm 发送认证表单（用于初始化请求）
func (h *Handler) sendAuthForm(c *gin.Context) {
	// 检查客户端是否发送了 group-select 参数（Cisco Secure Client 的 default_group）
	// 如果客户端发送了 group-select，使用客户端选择的组；否则使用 "default"
	tunnelGroup := "default"
	groupAlias := "default"

	// 尝试从请求体中解析 group-select（如果客户端发送了）
	// 支持两种方式：
	// 1. XML 格式：<opaque><group-select>xxx</group-select></opaque>（Cisco Secure Client）
	// 2. 表单格式：group_list=xxx（OpenConnect 客户端使用 --authgroup 参数）
	bodyBytes, _ := c.GetRawData()
	if len(bodyBytes) > 0 {
		var authReq AuthRequest
		if bytes.HasPrefix(bytes.TrimSpace(bodyBytes), []byte("<?xml")) {
			// XML 格式：解析 group-select 或 tunnel-group
			if err := xml.Unmarshal(bodyBytes, &authReq); err == nil {
				// 客户端发送了 group-select 或 tunnel-group
				if authReq.Opaque.GroupSelect != "" {
					tunnelGroup = authReq.Opaque.GroupSelect
					groupAlias = authReq.Opaque.GroupSelect
					log.Printf("OpenConnect: Client requested group-select (XML): %s", tunnelGroup)
				} else if authReq.Opaque.TunnelGroup != "" {
					tunnelGroup = authReq.Opaque.TunnelGroup
					groupAlias = authReq.Opaque.TunnelGroup
					log.Printf("OpenConnect: Client requested tunnel-group (XML): %s", tunnelGroup)
				}
			}
		}
		// 恢复请求体，供后续使用
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// 使用客户端选择的组（如果有），否则使用 "default"
	// 生成唯一的 aggauth-handle 和 config-hash（基于时间戳）
	aggauthHandle := fmt.Sprintf("%d", time.Now().UnixNano()%1000000000)
	configHash := fmt.Sprintf("%d", time.Now().UnixNano()%10000000000)

	// 构建 auth 部分的内容（添加 title 和 message，符合 AnyConnect 标准）
	// form 必须包含 action 和 method 属性，AnyConnect 客户端才能正确提交
	authContent := "    <auth id=\"main\">\n"
	authContent += "        <title>Login</title>\n"
	authContent += "        <message>Please enter your username and password.</message>\n"
	authContent += "        <banner></banner>\n"
	authContent += "        <form method=\"post\" action=\"/\">\n"
	authContent += "            <input type=\"text\" name=\"username\" label=\"Username:\"></input>\n"
	authContent += "            <input type=\"password\" name=\"password\" label=\"Password:\"></input>\n"
	authContent += "            <select name=\"group_list\" label=\"GROUP:\">\n"
	authContent += "                <option selected=\"true\">" + groupAlias + "</option>\n"
	authContent += "            </select>\n"
	authContent += "        </form>\n"
	authContent += "    </auth>\n"

	// 使用公共函数构建 XML（传入动态生成的 handle 和 hash）
	xmlContent := h.buildAuthRequestXML(c, authContent, tunnelGroup, groupAlias, aggauthHandle, configHash)

	c.Writer.Header().Del("Server")
	c.Writer.Header().Del("X-Powered-By")

	// 使用公共函数发送响应（但需要额外设置 X-Frame-Options 和 X-Content-Type-Options）
	responseConnection := h.getConnectionHeader(c)

	c.Header("Content-Type", "text/xml; charset=utf-8")
	c.Header("Content-Length", strconv.Itoa(len(xmlContent)))
	c.Header("Connection", responseConnection)
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	log.Printf("OpenConnect: sendAuthForm - Sending XML response (length: %d bytes)", len(xmlContent))
	log.Printf("OpenConnect: sendAuthForm - Response headers: Connection=%s, Content-Type=%s, Content-Length=%s",
		c.Writer.Header().Get("Connection"),
		c.Writer.Header().Get("Content-Type"),
		c.Writer.Header().Get("Content-Length"))

	// 记录完整的 XML 内容（用于调试）
	log.Printf("OpenConnect: [RESPONSE] Server sending XML (type=\"auth-request\"):\n%s", xmlContent)

	c.Data(http.StatusOK, "text/xml; charset=utf-8", []byte(xmlContent))

	if flusher, ok := c.Writer.(http.Flusher); ok {
		flusher.Flush()
		log.Printf("OpenConnect: sendAuthForm - Response flushed, waiting for next request on keep-alive connection")
	} else {
		log.Printf("OpenConnect: sendAuthForm - Warning: ResponseWriter does not implement Flusher")
	}
}

// extractVersionFromUserAgent 从 User-Agent 中提取客户端版本号
// 支持多种格式：
// - AnyConnect Linux_Arm64 5.1.13.177 -> 5.1.13.177
// - AnyConnect Windows 5.1.13.177 -> 5.1.13.177
// - OpenConnect 9.01 -> 9.01
func extractVersionFromUserAgent(userAgent string) string {
	if userAgent == "" {
		return ""
	}

	// 匹配 AnyConnect 版本号格式：AnyConnect [OS] 版本号
	// 例如：AnyConnect Linux_Arm64 5.1.13.177
	re1 := regexp.MustCompile(`(?i)anyconnect[^0-9]*([0-9]+(?:\.[0-9]+){2,})`)
	if matches := re1.FindStringSubmatch(userAgent); len(matches) >= 2 {
		return matches[1]
	}

	// 匹配 OpenConnect 版本号格式：OpenConnect/版本号
	// 例如：OpenConnect/9.01
	re2 := regexp.MustCompile(`(?i)openconnect[/\s]+([0-9]+(?:\.[0-9]+)+)`)
	if matches := re2.FindStringSubmatch(userAgent); len(matches) >= 2 {
		return matches[1]
	}

	return ""
}

// extractDeviceIDFromUserAgent 从 User-Agent 中提取设备ID
// 例如：AnyConnect Linux_Arm64 5.1.13.177 -> linux-64
// 支持多种格式：
// - AnyConnect Linux_Arm64 -> linux-64
// - AnyConnect Windows_x64 -> win-64
// - AnyConnect MacOS -> mac
func extractDeviceIDFromUserAgent(userAgent string) string {
	if userAgent == "" {
		return ""
	}

	ua := strings.ToLower(userAgent)

	// 提取操作系统和架构信息
	var osName, arch string

	// 操作系统（按优先级匹配，避免误匹配）
	if strings.Contains(ua, "windows") || strings.Contains(ua, "win_") {
		osName = "win"
	} else if strings.Contains(ua, "macos") || strings.Contains(ua, "mac_") || (strings.Contains(ua, "mac") && !strings.Contains(ua, "arm")) {
		osName = "mac"
	} else if strings.Contains(ua, "linux") || strings.Contains(ua, "linux_") {
		osName = "linux"
	} else if strings.Contains(ua, "android") {
		osName = "android"
	} else if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ios") {
		osName = "ios"
	}

	// 架构（按优先级匹配，避免误匹配）
	// 优先匹配明确的架构标识
	if strings.Contains(ua, "arm64") || strings.Contains(ua, "aarch64") {
		arch = "arm64"
	} else if strings.Contains(ua, "arm") && !strings.Contains(ua, "arm64") {
		arch = "arm"
	} else if strings.Contains(ua, "x86_64") || strings.Contains(ua, "amd64") || strings.Contains(ua, "_x64") || strings.Contains(ua, "_64") {
		arch = "64"
	} else if strings.Contains(ua, "x86") || strings.Contains(ua, "_32") {
		arch = "32"
	}

	// 组合设备ID
	if osName != "" && arch != "" {
		return osName + "-" + arch
	} else if osName != "" {
		return osName
	}
	return ""
}

// buildAuthRequestXML 构建 auth-request 类型的 XML 响应的公共部分
// c: gin context（用于获取 serverURL）
// authContent: <auth> 标签内的内容
// tunnelGroup: 隧道组名（默认 "default"）
// groupAlias: 组别名（默认 "default"）
// aggauthHandle: 认证句柄（如果为空，使用默认值）
// configHash: 配置哈希（如果为空，使用默认值）
func (h *Handler) buildAuthRequestXML(c *gin.Context, authContent, tunnelGroup, groupAlias, aggauthHandle, configHash string) string {
	// 根据实际请求判断 scheme（支持反向代理场景）
	// 优先检查 X-Forwarded-Proto（反向代理场景），然后检查 TLS 连接
	scheme := "https"
	if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
		scheme = strings.ToLower(proto)
	} else if c.Request.TLS == nil {
		// 如果没有 TLS 连接且没有 X-Forwarded-Proto，则使用 http
		scheme = "http"
	}
	serverURL := scheme + "://" + c.Request.Host

	// 使用默认值（如果未提供）
	if aggauthHandle == "" {
		aggauthHandle = "168179266"
	}
	if configHash == "" {
		configHash = "1595829378234"
	}
	if tunnelGroup == "" {
		tunnelGroup = "default"
	}
	if groupAlias == "" {
		groupAlias = "default"
	}

	// 从 User-Agent 提取版本号和设备信息
	userAgent := c.Request.UserAgent()
	version := extractVersionFromUserAgent(userAgent)
	deviceID := extractDeviceIDFromUserAgent(userAgent)

	xml := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	xml += "<config-auth client=\"vpn\" type=\"auth-request\" aggregate-auth-version=\"2\">\n"

	// 添加 version 标签（如果提取到版本号）
	if version != "" {
		xml += "    <version who=\"vpn\">" + version + "</version>\n"
	}

	// 添加 device-id 标签（可选，如果提取到设备信息）
	if deviceID != "" {
		xml += "    <device-id>" + deviceID + "</device-id>\n"
	}

	// 添加 group-select（可选，表示支持组选择）
	xml += "    <group-select>true</group-select>\n"

	// opaque 标签用于传递服务器组信息
	xml += "    <opaque is-for=\"sg\">\n"
	xml += "        <tunnel-group>" + tunnelGroup + "</tunnel-group>\n"
	xml += "        <group-alias>" + groupAlias + "</group-alias>\n"
	xml += "        <aggauth-handle>" + aggauthHandle + "</aggauth-handle>\n"
	xml += "        <config-hash>" + configHash + "</config-hash>\n"
	xml += "        <auth-method>password</auth-method>\n"
	xml += "    </opaque>\n"
	xml += authContent
	xml += "    <config>\n"
	xml += "        <profile-url>" + serverURL + "/profile.xml</profile-url>\n"
	xml += "    </config>\n"
	xml += "</config-auth>"

	return xml
}

// sendAuthRequestResponse 发送 auth-request 类型的 XML 响应（设置公共响应头）
func (h *Handler) sendAuthRequestResponse(c *gin.Context, xmlContent string) {
	c.Writer.Header().Del("Server")
	c.Writer.Header().Del("X-Powered-By")

	responseConnection := h.getConnectionHeader(c)

	c.Header("Content-Type", "text/xml; charset=utf-8")
	c.Header("Content-Length", strconv.Itoa(len(xmlContent)))
	c.Header("Connection", responseConnection)
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	c.Data(http.StatusOK, "text/xml; charset=utf-8", []byte(xmlContent))
}

// sendAuthError 发送认证错误
// 在 auth-request 中包含错误信息，而不是使用 auth-fail
func (h *Handler) sendAuthError(c *gin.Context, message string) {
	// 构建 auth 部分的内容
	authContent := "    <auth id=\"main\">\n"
	authContent += "        <title>Authentication Failed</title>\n"
	authContent += "        <message>" + message + "</message>\n"
	authContent += "        <banner></banner>\n"
	authContent += "        <form method=\"post\" action=\"/\">\n"
	authContent += "            <input type=\"text\" name=\"username\" label=\"Username:\" />\n"
	authContent += "            <input type=\"password\" name=\"password\" label=\"Password:\" />\n"
	authContent += "        </form>\n"
	authContent += "    </auth>\n"

	// 使用公共函数构建 XML
	xml := h.buildAuthRequestXML(c, authContent, "default", "default", "", "")

	// 使用公共函数发送响应
	h.sendAuthRequestResponse(c, xml)
}

// getServerCertInfo 获取服务器证书信息（包括 hash 和是否为自签名证书）
type ServerCertInfo struct {
	SHA1Hash     string // SHA1 hash（用于 AnyConnect）
	SHA256Hash   string // SHA256 hash（用于 pin-sha256，OpenConnect 客户端）
	IsSelfSigned bool   // 是否为自签名证书
}

// getServerCertInfo 获取服务器证书信息
func (h *Handler) getServerCertInfo() *ServerCertInfo {
	info := &ServerCertInfo{
		SHA1Hash:     "0000000000000000000000000000000000000000",
		SHA256Hash:   "",
		IsSelfSigned: false,
	}

	hash := h.getServerCertHash()
	if hash != "" {
		info.SHA1Hash = hash
	}

	// 获取 SHA256 hash
	sha256Hash := h.getServerCertSHA256Hash()
	if sha256Hash != "" {
		info.SHA256Hash = sha256Hash
	}

	// 检测是否为自签名证书
	info.IsSelfSigned = h.isSelfSignedCertificate()

	return info
}

// getServerCertHash 计算服务器证书的 SHA1 hash（用于 vpn-base-config）
func (h *Handler) getServerCertHash() string {
	// 尝试加载证书文件
	certFile := h.config.VPN.CertFile
	if certFile == "" {
		certFile = "./certs/server.crt"
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		log.Printf("OpenConnect: Failed to read certificate file %s: %v, using empty hash", certFile, err)
		return ""
	}

	// 解析 PEM 格式的证书
	block, _ := pem.Decode(certPEM)
	if block == nil {
		log.Printf("OpenConnect: Failed to decode certificate PEM")
		return ""
	}

	// 解析 X.509 证书
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("OpenConnect: Failed to parse certificate: %v", err)
		return ""
	}

	// 记录证书信息（用于诊断）
	issuer := cert.Issuer.String()
	log.Printf("OpenConnect: Server certificate info - CN: %s, DNS Names: %v, IP Addresses: %v",
		cert.Subject.CommonName, cert.DNSNames, cert.IPAddresses)
	log.Printf("OpenConnect: Certificate Issuer: %s", issuer)

	// 检查是否是开发证书（mkcert 或其他自签名证书）
	isDevCert := strings.Contains(issuer, "mkcert") ||
		strings.Contains(issuer, "development") ||
		strings.Contains(issuer, "self-signed") ||
		cert.Issuer.String() == cert.Subject.String()

	if isDevCert {
		log.Printf("OpenConnect: WARNING - This appears to be a development/self-signed certificate")
		log.Printf("OpenConnect: AnyConnect clients may show certificate verification warnings")
		log.Printf("OpenConnect: For production use, please use a certificate from a trusted CA (e.g., Let's Encrypt)")
	}

	// 计算 SHA1 hash（AnyConnect 使用 SHA1）
	hash := sha1.Sum(cert.Raw)
	hashStr := strings.ToUpper(hex.EncodeToString(hash[:]))

	// 计算 SHA256 hash（用于 pin-sha256，OpenConnect 客户端支持）
	sha256Hash := sha256.Sum256(cert.Raw)
	sha256HashStr := base64.StdEncoding.EncodeToString(sha256Hash[:])

	log.Printf("OpenConnect: Server certificate SHA1 hash: %s", hashStr)
	if isDevCert {
		log.Printf("OpenConnect: For OpenConnect clients with self-signed cert, use: --servercert=pin-sha256:%s", sha256HashStr)
		log.Printf("OpenConnect: Or install the CA certificate (mkcert -install) on the client machine")
	}
	return hashStr
}

// getServerCertSHA256Hash 计算服务器证书的 SHA256 hash（用于 pin-sha256）
func (h *Handler) getServerCertSHA256Hash() string {
	certFile := h.config.VPN.CertFile
	if certFile == "" {
		certFile = "./certs/server.crt"
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return ""
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return ""
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}

	// 计算 SHA256 hash（用于 pin-sha256）
	sha256Hash := sha256.Sum256(cert.Raw)
	return base64.StdEncoding.EncodeToString(sha256Hash[:])
}

// isSelfSignedCertificate 检测是否为自签名证书
func (h *Handler) isSelfSignedCertificate() bool {
	certFile := h.config.VPN.CertFile
	if certFile == "" {
		certFile = "./certs/server.crt"
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return false
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	// 检查是否为自签名证书
	// 1. 颁发者和主体相同
	// 2. 包含 mkcert、development、self-signed 等关键词
	issuer := cert.Issuer.String()
	subject := cert.Subject.String()

	isSelfSigned := issuer == subject ||
		strings.Contains(issuer, "mkcert") ||
		strings.Contains(issuer, "development") ||
		strings.Contains(issuer, "self-signed") ||
		strings.Contains(strings.ToLower(issuer), "ca")

	return isSelfSigned
}

// generatePasswordToken 生成密码验证token（用于多步骤认证）
func (h *Handler) generatePasswordToken(username string) string {
	timestamp := time.Now().Unix()
	message := fmt.Sprintf("%s:%d", username, timestamp)

	// 使用 JWT secret 作为密钥（与 JWT token 使用相同的密钥）
	secret := h.config.JWT.Secret

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	return base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", message, signature)))
}

// verifyPasswordToken 验证密码验证token
func (h *Handler) verifyPasswordToken(token string, username string) bool {
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

	secret := h.config.JWT.Secret

	message := fmt.Sprintf("%s:%s", tokenUsername, timestampStr)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	expectedSignature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

// sendOTPRequest 发送OTP代码输入请求（多步骤认证的第二步）
func (h *Handler) sendOTPRequest(c *gin.Context, username string, errorMessage string) {
	// 生成密码验证token
	passwordToken := h.generatePasswordToken(username)

	message := "Password verified. Please enter your OTP code from your authenticator app."
	if errorMessage != "" {
		message = errorMessage
	}

	// 构建 auth 部分的内容
	authContent := "    <auth id=\"otp\">\n"
	authContent += "        <title>OTP Authentication</title>\n"
	authContent += "        <message>" + message + "</message>\n"
	authContent += "        <form method=\"post\" action=\"/\">\n"
	authContent += "            <input type=\"hidden\" name=\"username\" value=\"" + username + "\" />\n"
	authContent += "            <input type=\"hidden\" name=\"password-token\" value=\"" + passwordToken + "\" />\n"
	authContent += "            <input type=\"text\" name=\"otp-code\" label=\"OTP Code (6 digits):\" />\n"
	authContent += "        </form>\n"
	authContent += "    </auth>\n"

	// 使用公共函数构建 XML
	xml := h.buildAuthRequestXML(c, authContent, "default", "default", "", "")

	// 使用公共函数发送响应
	h.sendAuthRequestResponse(c, xml)
}

// sendOTPSetupRequest 发送OTP配置请求（首次登录时）
func (h *Handler) sendOTPSetupRequest(c *gin.Context, username string) {
	// 生成密码验证token
	passwordToken := h.generatePasswordToken(username)

	// 为用户生成OTP密钥和二维码
	var user models.User
	if err := database.DB.Where("username = ?", username).First(&user).Error; err != nil {
		log.Printf("OpenConnect: Failed to find user %s for OTP setup", username)
		h.sendAuthError(c, "User not found")
		return
	}

	// 如果用户已经有OTPSecret，使用现有的；否则生成新的
	var secret string
	var key interface {
		Secret() string
		Image(width, height int) (image.Image, error)
	}
	var err error

	if user.OTPSecret != "" {
		// 使用现有的密钥，生成新的key对象用于显示二维码
		// 注意：生成的key的secret会不同，但验证时会使用用户现有的secret
		key, err = totp.Generate(totp.GenerateOpts{
			Issuer:      "ZVPN",
			AccountName: user.Username,
		})
		if err != nil {
			log.Printf("OpenConnect: Failed to generate OTP key for user %s: %v", username, err)
			h.sendAuthError(c, "Failed to generate OTP key")
			return
		}
		secret = user.OTPSecret
	} else {
		key, err = totp.Generate(totp.GenerateOpts{
			Issuer:      "ZVPN",
			AccountName: user.Username,
		})
		if err != nil {
			log.Printf("OpenConnect: Failed to generate OTP key for user %s: %v", username, err)
			h.sendAuthError(c, "Failed to generate OTP key")
			return
		}
		secret = key.Secret()
	}

	img, err := key.Image(200, 200)
	if err != nil {
		log.Printf("OpenConnect: Failed to generate QR code for user %s: %v", username, err)
		h.sendAuthError(c, "Failed to generate QR code")
		return
	}

	var buf strings.Builder
	buf.WriteString("data:image/png;base64,")
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	if err := png.Encode(encoder, img); err != nil {
		log.Printf("OpenConnect: Failed to encode QR code for user %s: %v", username, err)
		h.sendAuthError(c, "Failed to encode QR code")
		return
	}
	encoder.Close()
	qrCode := buf.String()

	user.OTPSecret = secret
	if err := database.DB.Save(&user).Error; err != nil {
		log.Printf("OpenConnect: Failed to save OTP secret for user %s: %v", username, err)
		h.sendAuthError(c, "Failed to save OTP secret")
		return
	}

	message := "Please scan the QR code with your authenticator app (e.g., Google Authenticator), then enter the OTP code to complete setup."

	// 构建 auth 部分的内容
	authContent := "    <auth id=\"otp-setup\">\n"
	authContent += "        <title>OTP Setup Required</title>\n"
	authContent += "        <message>" + message + "</message>\n"
	authContent += "        <banner>Scan this QR code with your authenticator app:</banner>\n"
	authContent += "        <img src=\"" + qrCode + "\" alt=\"OTP QR Code\" style=\"max-width: 200px; display: block; margin: 10px auto;\" />\n"
	authContent += "        <form method=\"post\" action=\"/\">\n"
	authContent += "            <input type=\"hidden\" name=\"username\" value=\"" + username + "\" />\n"
	authContent += "            <input type=\"hidden\" name=\"password-token\" value=\"" + passwordToken + "\" />\n"
	authContent += "            <input type=\"hidden\" name=\"otp-setup\" value=\"true\" />\n"
	authContent += "            <input type=\"text\" name=\"otp-code\" label=\"OTP Code (6 digits):\" />\n"
	authContent += "        </form>\n"
	authContent += "    </auth>\n"

	// 使用公共函数构建 XML
	xml := h.buildAuthRequestXML(c, authContent, "default", "default", "", "")

	// 使用公共函数发送响应
	h.sendAuthRequestResponse(c, xml)
}

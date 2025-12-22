package openconnect

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"image"
	"image/png"
	"io"
	"log"
	"net"
	"net/http"
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

// GetConfig 返回 OpenConnect 初始配置（响应 POST /）
func (h *Handler) GetConfig(c *gin.Context) {
	// OpenConnect 协议：返回支持的认证方法
	// 添加 profile-url 让客户端下载配置文件
	serverURL := "https://" + c.Request.Host

	xml := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
    <version who="sg">0.1(1)0</version>
    <auth id="main">
        <title>ZVPN Login</title>
        <message>Please enter your username and password.</message>
        <form method="post" action="/auth">
            <input type="text" name="username" label="Username:" />
            <input type="password" name="password" label="Password:" />
        </form>
    </auth>
    <config>
        <profile-url>` + serverURL + `/profile.xml</profile-url>
    </config>
</config-auth>`
	c.Data(http.StatusOK, "text/xml; charset=utf-8", []byte(xml))
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
	Auth    struct {
		Username      string `xml:"username"`
		Password      string `xml:"password"`       // 第一步：密码
		PasswordToken string `xml:"password-token"` // 第二步：密码验证token
		OTPCode       string `xml:"otp-code"`       // OTP代码（多步骤认证时使用）
	} `xml:"auth"`
}

// Authenticate 处理认证请求
func (h *Handler) Authenticate(c *gin.Context) {
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

	contentType := c.Request.Header.Get("Content-Type")
	log.Printf("OpenConnect: Auth request - Content-Type: %s, Method: %s", contentType, c.Request.Method)

	// 读取原始请求体（只能读一次，需要保存）
	bodyBytes, err := c.GetRawData()
	if err != nil {
		log.Printf("OpenConnect: Failed to read request body: %v", err)
		h.sendAuthError(c, "Failed to read request")
		return
	}

	// 恢复请求体，供后续解析使用
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	if len(bodyBytes) > 0 {
		bodyPreview := bodyBytes
		if len(bodyPreview) > 200 {
			bodyPreview = bodyPreview[:200]
		}
		log.Printf("OpenConnect: Request body (first %d bytes): %s", len(bodyPreview), string(bodyPreview))
	}

	// 1. 首先尝试解析 XML（即使 Content-Type 不是 xml，OpenConnect 也可能发送 XML）
	// 检查请求体是否以 XML 开头
	var authReq AuthRequest
	var xmlParsed bool
	if len(bodyBytes) > 0 && bytes.HasPrefix(bytes.TrimSpace(bodyBytes), []byte("<?xml")) {
		log.Printf("OpenConnect: Detected XML format in request body")
		log.Printf("OpenConnect: Full XML body: %s", string(bodyBytes))

		if err := xml.Unmarshal(bodyBytes, &authReq); err != nil {
			log.Printf("OpenConnect: Failed to parse XML: %v", err)
			log.Printf("OpenConnect: XML body content: %s", string(bodyBytes))
			// 如果 XML 解析失败，继续尝试其他方法
		} else {
			xmlParsed = true
			username = authReq.Auth.Username
			password = authReq.Auth.Password
			// 如果是第二步认证，可能只有password-token，没有password
			passwordTokenFromXML := authReq.Auth.PasswordToken
			log.Printf("OpenConnect: XML parsed - type: '%s', username: '%s', password length: %d, has password-token: %v",
				authReq.Type, username, len(password), passwordTokenFromXML != "")

			// 检查是否是初始化请求（type="init" 或 type="auth-reply"但没有凭证）
			if (authReq.Type == "init" || authReq.Type == "auth-reply") && username == "" && password == "" && passwordTokenFromXML == "" {
				log.Printf("OpenConnect: Initial request detected (type=%s, no credentials), returning auth form", authReq.Type)
				// 返回认证表单，让客户端输入用户名和密码
				h.sendAuthForm(c)
				return
			}

			if username != "" && (password != "" || passwordTokenFromXML != "") {
				log.Printf("OpenConnect: ✓ Parsed XML successfully - username: %s", username)
			} else {
				log.Printf("OpenConnect: ⚠️  XML parsed but username or credentials is empty")
			}
		}
	} else {
		log.Printf("OpenConnect: Request body does not start with <?xml, trying form parsing")
	}

	// 2. 如果 XML 解析失败或没有解析到，尝试表单解析
	if username == "" || password == "" {
		// 恢复请求体用于表单解析
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// 尝试从 POST 表单获取（application/x-www-form-urlencoded）
		if err := c.Request.ParseForm(); err == nil {
			username = c.Request.PostForm.Get("username")
			password = c.Request.PostForm.Get("password")
			if username != "" || password != "" {
				log.Printf("OpenConnect: ✓ Parsed from POST form - username: %s", username)
			}
		}

		// 如果表单为空，尝试从 URL 查询参数获取
		if username == "" || password == "" {
			username = c.Query("username")
			password = c.Query("password")
			if username != "" || password != "" {
				log.Printf("OpenConnect: ✓ Parsed from query - username: %s", username)
			}
		}
	}

	// 3. 最后尝试 Basic Auth（如果前面都没解析到）
	if username == "" || password == "" {
		u, p, ok := c.Request.BasicAuth()
		if ok {
			username = u
			password = p
			log.Printf("OpenConnect: ✓ Using Basic Auth - username: %s", username)
		}
	}

	// 检查是否有凭证（password或password-token）
	// 如果是第二步认证，可能只有password-token，没有password
	// 使用之前解析的XML数据（避免重复解析）
	var hasPasswordToken bool
	if xmlParsed {
		hasPasswordToken = authReq.Auth.PasswordToken != ""
		// 如果XML中有username但之前没提取到，现在提取
		if username == "" && authReq.Auth.Username != "" {
			username = authReq.Auth.Username
			log.Printf("OpenConnect: Extracted username from XML: %s", username)
		}
		// 如果XML中有password但之前没提取到，现在提取
		if password == "" && authReq.Auth.Password != "" {
			password = authReq.Auth.Password
			log.Printf("OpenConnect: Extracted password from XML (length: %d)", len(password))
		}
	}
	// 如果XML中没有，检查表单
	if !hasPasswordToken {
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		if err := c.Request.ParseForm(); err == nil {
			hasPasswordToken = c.Request.PostForm.Get("password-token") != ""
			// 如果表单中有username但之前没提取到，现在提取
			if username == "" {
				formUsername := c.Request.PostForm.Get("username")
				if formUsername != "" {
					username = formUsername
					log.Printf("OpenConnect: Extracted username from form: %s", username)
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
	// 兼容性说明：
	// 1. LDAP用户：Source字段为'ldap'，登录时使用LDAP服务器认证，数据库不存储密码
	// 2. 系统账户：Source字段为'system'，登录时使用数据库认证（bcrypt哈希）
	// 3. 系统根据Source字段自动识别账户类型，无需密码格式判断
	// 4. LDAP用户登录使用uid（英文账户名），系统账户可以使用任意用户名
	if ldapAuth != nil && ldapConfig.Enabled {
		// 先检查用户是否存在于数据库中
		var existingUser models.User
		userExistsInDB := database.DB.Where("username = ?", username).First(&existingUser).Error == nil

		// 如果用户存在，检查是LDAP用户还是系统账户
		if userExistsInDB {
			// 根据Source字段判断用户类型
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
					database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").
						Where("username = ?", username).First(&user)
					// 计算用户的策略（从用户组获取）
					if policy := user.GetPolicy(); policy != nil {
						user.PolicyID = policy.ID
						user.Policy = *policy
					}

					isLDAPAuth = true
					log.Printf("OpenConnect: ✓ LDAP user %s authenticated (password correct, OTP correct)", username)
					// OTP验证成功，继续后续的认证成功流程
					// 注意：这里跳过了LDAP密码认证部分，因为已经在第一步完成了
				} else {
					// 第一步：先进行LDAP密码认证
					// 如果用户启用了OTP但没有提供OTP代码，说明是第一步，只验证密码
					ldapUser, err := ldapAuth.Authenticate(username, password)
					if err == nil {
						// LDAP 认证成功，同步用户到本地数据库
						if err := database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").
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
								// PasswordHash 留空，LDAP用户不需要存储密码（认证由LDAP服务器完成）
							}
							// 序列化LDAP原始属性为JSON（用于扩展）
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
											log.Printf("OpenConnect: Warning: Failed to create default user group: %v", err)
										} else {
											// 关联默认策略
											if err := database.DB.Model(&defaultGroup).Association("Policies").Append(&defaultPolicy); err != nil {
												log.Printf("OpenConnect: Warning: Failed to assign default policy to default group: %v", err)
											}
											log.Printf("OpenConnect: ✓ Created default user group")
										}
									}
								}
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
							database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").
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
								database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").
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
						// LDAP 认证失败，用户是LDAP用户，不应该fallback到本地认证
						// 因为LDAP用户的密码存储在LDAP服务器中，本地数据库没有密码
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
				// LDAP 认证成功，创建新用户
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
				// 序列化LDAP原始属性为JSON（用于扩展）
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
				var defaultGroup models.UserGroup
				groupName := "default"
				if ldapUser.IsAdmin {
					groupName = "admin"
				}
				if err := database.DB.Where("name = ?", groupName).First(&defaultGroup).Error; err == nil {
					database.DB.Model(&user).Association("Groups").Append(&defaultGroup)
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
		if err := database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").
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
					database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").
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
	if !h.config.VPN.AllowMultiClientLogin && user.Connected {
		log.Printf("OpenConnect: User %s already connected, multi-client login disabled", username)
		h.sendAuthError(c, "该账号已在线，已禁止多端同时登录")
		return
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
		database.DB.Save(&user)

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

	// 构建路由信息（根据用户策略）
	// 使用 Split-Tunnel 模式，避免接管所有流量导致路由环路
	var splitIncludeRoutes []string

	// 注意：不包含VPN网络本身（10.8.0.0/24），只包含数据库中的策略路由

	log.Printf("OpenConnect: User %s policyID=%d, routes count=%d", user.Username, user.PolicyID, len(user.Policy.Routes))
	// 打印所有路由详情
	for i, route := range user.Policy.Routes {
		log.Printf("OpenConnect: User %s route %d: %s", user.Username, i+1, route.Network)
	}
	if user.PolicyID != 0 && len(user.Policy.Routes) > 0 {
		// Split-tunnel mode: 只添加策略路由，不包含VPN网络本身
		for _, route := range user.Policy.Routes {
			// 跳过VPN网络本身，只添加策略路由
			if route.Network != h.config.VPN.Network {
				splitIncludeRoutes = append(splitIncludeRoutes, route.Network)
			}
		}
		log.Printf("OpenConnect: User %s - Split tunnel mode with %d policy routes (excluding VPN network): %v", user.Username, len(splitIncludeRoutes), splitIncludeRoutes)
	} else {
		// 没有策略路由
		log.Printf("OpenConnect: User %s - No policy routes configured", user.Username)
	}

	// 构建 split-include XML（每个路由一行，正确的缩进）
	// 注意：不包含VPN网络本身（10.8.0.0/24），只包含数据库中的策略路由
	// 格式要求：IP + 掩码分开写
	routeXML := ""
	for _, route := range splitIncludeRoutes {
		// 解析 CIDR 格式（如 192.168.0.0/16）为 IP 和掩码
		_, ipNet, err := net.ParseCIDR(route)
		if err != nil {
			log.Printf("OpenConnect: Failed to parse route %s: %v", route, err)
			continue
		}
		network := ipNet.IP.String()
		netmask := net.IP(ipNet.Mask).String()
		routeXML += "\n\t\t<cstp:split-include>"
		routeXML += "\n\t\t\t<cstp:network>" + network + "</cstp:network>"
		routeXML += "\n\t\t\t<cstp:netmask>" + netmask + "</cstp:netmask>"
		routeXML += "\n\t\t</cstp:split-include>"
	}

	// 获取服务器地址（用于添加主机路由保护）
	serverHost := c.Request.Host
	if colonPos := strings.Index(serverHost, ":"); colonPos != -1 {
		serverHost = serverHost[:colonPos]
	}

	// 检查serverHost是否是IP地址
	isIP := net.ParseIP(serverHost) != nil
	noSplitDNSXML := ""
	if !isIP {
		// 只有当serverHost是域名时才配置no-split-dns
		// no-split-dns用于指定哪些域名不使用VPN DNS解析
		noSplitDNSXML = "\n\t\t<!-- no-split-dns: 指定哪些域名不使用VPN DNS解析 -->\n\t\t<cstp:no-split-dns>" + serverHost + "</cstp:no-split-dns>"
	}

	// 获取DNS服务器配置（从策略中获取，如果没有则使用默认DNS）
	userDNSServers := getDNSServers(&user.Policy)

	// 构建DNS服务器列表，顺序为：
	// 1. DNS拦截器（用于域名管理功能，走VPN）
	// 2. 用户配置的DNS（从策略中获取）
	// 注意：不通过CSTP下发公网DNS，让客户端使用系统默认DNS（不走VPN）
	// 这样可以避免OpenConnect客户端为公网DNS IP自动添加路由到VPN
	var dnsServers []string

	// 只添加DNS拦截器作为DNS服务器（用于域名管理功能）
	if h.vpnServer != nil && h.vpnServer.GetDNSInterceptor() != nil {
		// 获取VPN服务器IP地址（用于DNS拦截器）
		// 优先使用TUN设备的实际IP地址（支持多服务器横向扩容）
		var dnsInterceptorIP string
		if tunDevice := h.vpnServer.GetTUNDevice(); tunDevice != nil {
			if tunIP, err := tunDevice.GetIP(); err == nil {
				dnsInterceptorIP = tunIP.String()
				log.Printf("OpenConnect: DNS interceptor enabled, using TUN device IP %s as fallback DNS (multi-server support)", dnsInterceptorIP)
			}
		}

		// 如果无法获取TUN设备IP，回退到VPN网关IP（通常是.1）
		if dnsInterceptorIP == "" {
			_, ipNet, err := net.ParseCIDR(h.config.VPN.Network)
			if err == nil {
				gatewayIP := make(net.IP, len(ipNet.IP))
				copy(gatewayIP, ipNet.IP)
				gatewayIP[len(gatewayIP)-1] = 1 // VPN网关IP（通常是.1）
				dnsInterceptorIP = gatewayIP.String()
				log.Printf("OpenConnect: DNS interceptor enabled, using VPN gateway %s as fallback DNS", dnsInterceptorIP)
			}
		}

		if dnsInterceptorIP != "" {
			// 将DNS拦截器地址添加到DNS服务器列表（用于域名管理功能）
			// 注意：不通过CSTP下发公网DNS，让客户端使用系统默认DNS（不走VPN）
			// 这样可以避免OpenConnect客户端为公网DNS IP自动添加路由到VPN
			dnsServers = append(dnsServers, dnsInterceptorIP)
			log.Printf("OpenConnect: DNS interceptor enabled, using %s as DNS server for domain-based split tunneling", dnsInterceptorIP)
			log.Printf("OpenConnect: Public DNS (114.114.114.114) not configured in CSTP - client will use system default DNS (no VPN route)")
		}
	}

	// 添加用户配置的DNS（从策略中获取）
	if len(userDNSServers) > 0 {
		dnsServers = append(dnsServers, userDNSServers...)
		log.Printf("OpenConnect: Added user-configured DNS servers: %v", userDNSServers)
	}
	dnsXML := ""
	for _, dns := range dnsServers {
		if dns != "" {
			dnsXML += "\n\t\t\t<cstp:server>" + dns + "</cstp:server>"
		}
	}

	// 构建完整的 XML 响应
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth" aggregate-auth-version="2">
	<session-token>` + sessionID + `</session-token>

	<auth>
		<banner>欢迎连接 ZVPN</banner>
	</auth>

	<auth id="success">
		<banner>认证成功，正在建立隧道...</banner>
	</auth>

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

		<!-- Split-Tunnel 配置：只路由特定网段，不接管默认路由 -->
		<!-- 明确禁用默认路由，只走 split-tunnel -->
		<cstp:default-route>false</cstp:default-route>
		
		<!-- 包含的路由（只有这些网段走 VPN） -->
		<!-- 注意：只使用split-include来明确指定需要路由的网段 -->` + routeXML + noSplitDNSXML + `

		<!-- 超时配置 -->
		<cstp:idle-timeout>7200</cstp:idle-timeout>
		<cstp:session-timeout>86400</cstp:session-timeout>

		<!-- DTLS 配置（启用以提升性能） -->` + getDTLSConfig(h.config, c.Request.Host) + `

		<!-- 心跳和保活 -->
		<cstp:keepalive>20</cstp:keepalive>
		<cstp:dpd>20</cstp:dpd>

		<!-- 压缩 -->
		<cstp:compression>` + getCompressionType(h.config) + `</cstp:compression>
	</cstp:config>
</config-auth>`

	// 打印完整的XML响应（用于调试路由策略问题）
	log.Printf("OpenConnect: Full XML response for user %s:", user.Username)
	log.Println(xml)
	log.Printf("OpenConnect: Sending auth response to user %s (IP: %s, routes: %v)", user.Username, user.VPNIP, splitIncludeRoutes)

	c.Data(http.StatusOK, "text/xml; charset=utf-8", []byte(xml))
}

// sendAuthForm 发送认证表单（用于初始化请求）
func (h *Handler) sendAuthForm(c *gin.Context) {
	serverURL := "https://" + c.Request.Host

	xml := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
    <version who="sg">0.1(1)0</version>
    <auth id="main">
        <title>ZVPN Login</title>
        <message>Please enter your username and password.</message>
        <form method="post" action="/auth">
            <input type="text" name="username" label="Username:" />
            <input type="password" name="password" label="Password:" />
        </form>
    </auth>
    <config>
        <profile-url>` + serverURL + `/profile.xml</profile-url>
    </config>
</config-auth>`
	c.Header("Content-Type", "text/xml; charset=utf-8")
	c.Data(http.StatusOK, "text/xml; charset=utf-8", []byte(xml))
}

// sendAuthError 发送认证错误
func (h *Handler) sendAuthError(c *gin.Context, message string) {
	// 返回符合 OpenConnect 协议的 XML 错误响应
	// 使用字符串构建，确保格式完全正确
	serverURL := "https://" + c.Request.Host

	xml := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-fail" aggregate-auth-version="2">
    <version who="sg">0.1(1)0</version>
    <auth id="main">
        <title>Authentication Failed</title>
        <message>` + message + `</message>
        <form method="post" action="/auth">
            <input type="text" name="username" label="Username:" />
            <input type="password" name="password" label="Password:" />
        </form>
    </auth>
    <config>
        <profile-url>` + serverURL + `/profile.xml</profile-url>
    </config>
</config-auth>`

	// 设置正确的 Content-Type，避免客户端误认为是 Basic Auth
	c.Header("Content-Type", "text/xml; charset=utf-8")
	// 不要返回 401，返回 200 但 type="auth-fail"，这样客户端不会认为是 Basic Auth
	c.Data(http.StatusOK, "text/xml; charset=utf-8", []byte(xml))
}

// generatePasswordToken 生成密码验证token（用于多步骤认证）
func (h *Handler) generatePasswordToken(username string) string {
	timestamp := time.Now().Unix()
	message := fmt.Sprintf("%s:%d", username, timestamp)

	// 使用默认密钥（用于生成密码验证token）
	// 在生产环境中，应该使用配置的密钥
	secret := "zvpn-default-secret-key-change-in-production"

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

	// 验证签名（使用默认密钥，生产环境应使用配置的密钥）
	secret := "zvpn-default-secret-key-change-in-production"

	message := fmt.Sprintf("%s:%s", tokenUsername, timestampStr)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	expectedSignature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

// sendOTPRequest 发送OTP代码输入请求（多步骤认证的第二步）
func (h *Handler) sendOTPRequest(c *gin.Context, username string, errorMessage string) {
	serverURL := "https://" + c.Request.Host

	// 生成密码验证token
	passwordToken := h.generatePasswordToken(username)

	message := "Password verified. Please enter your OTP code from your authenticator app."
	if errorMessage != "" {
		message = errorMessage
	}

	xml := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
    <version who="sg">0.1(1)0</version>
    <auth id="otp">
        <title>OTP Authentication</title>
        <message>` + message + `</message>
        <form method="post" action="/auth">
            <input type="hidden" name="username" value="` + username + `" />
            <input type="hidden" name="password-token" value="` + passwordToken + `" />
            <input type="text" name="otp-code" label="OTP Code (6 digits):" />
        </form>
    </auth>
    <config>
        <profile-url>` + serverURL + `/profile.xml</profile-url>
    </config>
</config-auth>`

	c.Header("Content-Type", "text/xml; charset=utf-8")
	c.Data(http.StatusOK, "text/xml; charset=utf-8", []byte(xml))
}

// sendOTPSetupRequest 发送OTP配置请求（首次登录时）
func (h *Handler) sendOTPSetupRequest(c *gin.Context, username string) {
	serverURL := "https://" + c.Request.Host

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
		// 使用用户现有的secret（不更新）
		secret = user.OTPSecret
	} else {
		// 生成新的OTP密钥
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

	// 生成二维码图片
	// 注意：如果用户已有secret，生成的二维码可能不匹配，但验证时会使用正确的secret
	img, err := key.Image(200, 200)
	if err != nil {
		log.Printf("OpenConnect: Failed to generate QR code for user %s: %v", username, err)
		h.sendAuthError(c, "Failed to generate QR code")
		return
	}

	// 将图片转换为base64
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

	// 临时保存OTP密钥到用户（但不启用，等用户验证OTP后再启用）
	user.OTPSecret = secret
	// 注意：这里不设置OTPEnabled为true，等用户验证OTP代码后再启用
	if err := database.DB.Save(&user).Error; err != nil {
		log.Printf("OpenConnect: Failed to save OTP secret for user %s: %v", username, err)
		h.sendAuthError(c, "Failed to save OTP secret")
		return
	}

	message := "Please scan the QR code with your authenticator app (e.g., Google Authenticator), then enter the OTP code to complete setup."

	xml := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
    <version who="sg">0.1(1)0</version>
    <auth id="otp-setup">
        <title>OTP Setup Required</title>
        <message>` + message + `</message>
        <banner>Scan this QR code with your authenticator app:</banner>
        <img src="` + qrCode + `" alt="OTP QR Code" style="max-width: 200px; display: block; margin: 10px auto;" />
        <form method="post" action="/auth">
            <input type="hidden" name="username" value="` + username + `" />
            <input type="hidden" name="password-token" value="` + passwordToken + `" />
            <input type="hidden" name="otp-setup" value="true" />
            <input type="text" name="otp-code" label="OTP Code (6 digits):" />
        </form>
    </auth>
    <config>
        <profile-url>` + serverURL + `/profile.xml</profile-url>
    </config>
</config-auth>`

	c.Header("Content-Type", "text/xml; charset=utf-8")
	c.Data(http.StatusOK, "text/xml; charset=utf-8", []byte(xml))
}

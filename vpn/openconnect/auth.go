package openconnect

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fisker/zvpn/auth"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/handlers"
	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/vpn"
	"github.com/fisker/zvpn/vpn/policy"
	"github.com/gin-gonic/gin"
)

func validateSecureHeaders(c *gin.Context) bool {
	xAggregateAuth := c.Request.Header.Get("X-Aggregate-Auth")
	xTranscendVersion := c.Request.Header.Get("X-Transcend-Version")
	userAgent := strings.ToLower(c.GetHeader("User-Agent"))
	mobileLicense := strings.ToLower(c.Request.Header.Get("X-Cstp-License"))

	isOpenConnectClient := strings.Contains(userAgent, "openconnect") ||
		strings.Contains(userAgent, "anyconnect") ||
		strings.Contains(userAgent, "cisco secure client") ||
		strings.Contains(userAgent, "cisco anyconnect")

	// 检测移动端客户端
	isMobileClient := mobileLicense == "mobile" ||
		strings.Contains(userAgent, "android") ||
		strings.Contains(userAgent, "iphone") ||
		strings.Contains(userAgent, "ipad") ||
		strings.Contains(userAgent, "ios")

	if isOpenConnectClient {
		// 对于移动端客户端，放宽头部检查要求
		if isMobileClient {
			// 移动端客户端可能不发送这些头部，或者值不同，允许通过
			if xAggregateAuth == "" && xTranscendVersion == "" {
				log.Printf("OpenConnect: Mobile client detected (User-Agent: %s), allowing without X-Aggregate-Auth/X-Transcend-Version headers",
					userAgent)
				return true
			}
		}

		// PC 端客户端必须发送正确的头部
		if xAggregateAuth != "1" || xTranscendVersion != "1" {
			log.Printf("OpenConnect: REJECTED - Missing required headers for %s (X-Aggregate-Auth: %s, X-Transcend-Version: %s)",
				userAgent, xAggregateAuth, xTranscendVersion)
			c.AbortWithStatus(http.StatusForbidden)
			return false
		}
		return true
	}

	return true
}

func (h *Handler) GetConfig(c *gin.Context) {
	select {
	case <-c.Request.Context().Done():
		return
	default:
	}

	connection := strings.ToLower(c.GetHeader("Connection"))
	userAgent := strings.ToLower(c.GetHeader("User-Agent"))
	if connection == "close" && (strings.Contains(userAgent, "anyconnect") || strings.Contains(userAgent, "openconnect")) {
		c.Header("Connection", "close")
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	if !validateSecureHeaders(c) {
		return
	}

	xAggregateAuth := c.GetHeader("X-Aggregate-Auth")
	xTranscendVersion := c.GetHeader("X-Transcend-Version")
	mobileLicense := strings.ToLower(c.GetHeader("X-Cstp-License"))

	// 检测移动端客户端
	isMobileClient := mobileLicense == "mobile" ||
		strings.Contains(userAgent, "android") ||
		strings.Contains(userAgent, "iphone") ||
		strings.Contains(userAgent, "ipad") ||
		strings.Contains(userAgent, "ios")

	// 对于移动端客户端，放宽检测要求
	isVPNClient := (xAggregateAuth == "1" && xTranscendVersion == "1") ||
		strings.Contains(userAgent, "openconnect") ||
		strings.Contains(userAgent, "anyconnect") ||
		strings.Contains(userAgent, "cisco secure client") ||
		strings.Contains(userAgent, "cisco anyconnect") ||
		isMobileClient // 移动端客户端即使没有标准头部也认为是 VPN 客户端

	if !isVPNClient && c.Request.Method == "POST" {
		h.sendAuthForm(c)
		return
	}

	bodyBytes, err := c.GetRawData()
	if err != nil {
		h.sendAuthForm(c)
		return
	}

	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	var authReq AuthRequest
	requestType := "init"

	if len(bodyBytes) > 0 {
		if bytes.HasPrefix(bytes.TrimSpace(bodyBytes), []byte("<?xml")) {
			if err := xml.Unmarshal(bodyBytes, &authReq); err == nil {
				requestType = authReq.Type
			}
		} else {
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			if err := c.Request.ParseForm(); err == nil {
				username := c.Request.PostForm.Get("username")
				password := c.Request.PostForm.Get("password")
				otpCode := c.Request.PostForm.Get("otp-code")
				passwordToken := c.Request.PostForm.Get("password-token")
				if username != "" && (password != "" || (otpCode != "" && passwordToken != "")) {
					h.Authenticate(c)
					return
				}
			}
		}
	}

	switch requestType {
	case "init":
		h.sendAuthForm(c)
		return
	case "logout":
		h.handleLogout(c)
		return
	case "auth-reply":
		h.Authenticate(c)
		return
	default:
		h.sendAuthForm(c)
		return
	}
}

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

type AuthRequest struct {
	XMLName xml.Name `xml:"config-auth"`
	Type    string   `xml:"type,attr"`
	Opaque  struct {
		TunnelGroup string `xml:"tunnel-group"`
		GroupSelect string `xml:"group-select"`
	} `xml:"opaque"`
	Auth struct {
		Username      string `xml:"username"`
		Password      string `xml:"password"`
		PasswordToken string `xml:"password-token"`
		OTPCode       string `xml:"otp-code"`
	} `xml:"auth"`
}

func (h *Handler) Authenticate(c *gin.Context) {
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	log.Printf("OpenConnect: Authentication request from %s (User-Agent: %s)", clientIP, userAgent)

	if !validateSecureHeaders(c) {
		log.Printf("OpenConnect: REJECTED - validateSecureHeaders failed for client %s", clientIP)
		return
	}

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
		h.sendAuthError(c, "Failed to read request")
		return
	}

	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	var authReq AuthRequest
	var xmlParsed bool
	if len(bodyBytes) > 0 && bytes.HasPrefix(bytes.TrimSpace(bodyBytes), []byte("<?xml")) {
		if err := xml.Unmarshal(bodyBytes, &authReq); err == nil {
			xmlParsed = true
			username = authReq.Auth.Username
			password = authReq.Auth.Password
			passwordTokenFromXML := authReq.Auth.PasswordToken

			if (authReq.Type == "init" || authReq.Type == "auth-reply") && username == "" && password == "" && passwordTokenFromXML == "" {
				h.sendAuthForm(c)
				return
			}
		}
	}

	if username == "" || password == "" {
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		if err := c.Request.ParseForm(); err == nil {
			username = c.Request.PostForm.Get("username")
			password = c.Request.PostForm.Get("password")
		}

		if username == "" || password == "" {
			username = c.Query("username")
			password = c.Query("password")
		}
	}

	if username == "" || password == "" {
		u, p, ok := c.Request.BasicAuth()
		if ok {
			username = u
			password = p
		}
	}

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

	if !hasPasswordToken {
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		if err := c.Request.ParseForm(); err == nil {
			hasPasswordToken = c.Request.PostForm.Get("password-token") != ""
			if username == "" {
				username = c.Request.PostForm.Get("username")
			}
			if password == "" {
				password = c.Request.PostForm.Get("password")
			}
		}
	}

	if username == "" || (password == "" && !hasPasswordToken) {
		h.sendAuthError(c, "Username and password required")
		return
	}

	var user models.User
	var isLDAPAuth bool

	var ldapConfig models.LDAPConfig
	if err := database.DB.First(&ldapConfig).Error; err != nil {

		ldapConfig = models.LDAPConfig{Enabled: false}
	}

	var ldapAuth *auth.LDAPAuthenticator
	if ldapConfig.Enabled {

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

	if ldapAuth != nil && ldapConfig.Enabled {
		var existingUser models.User
		userExistsInDB := database.DB.Where("username = ?", username).First(&existingUser).Error == nil

		if userExistsInDB {
			if existingUser.Source == models.UserSourceLDAP {

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

					c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
					if err := c.Request.ParseForm(); err == nil {
						otpCodeFromRequest = c.Request.PostForm.Get("otp-code")
						passwordTokenFromRequest = c.Request.PostForm.Get("password-token")
					}
				}

				if existingUser.OTPEnabled && existingUser.OTPSecret != "" && otpCodeFromRequest != "" && passwordTokenFromRequest != "" {

					if !h.verifyPasswordToken(passwordTokenFromRequest, username) {
						log.Printf("OpenConnect: Invalid password token for LDAP user %s (OTP step 2)", username)
						h.sendAuthError(c, "Session expired. Please login again.")
						return
					}

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

					database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").Preload("Groups.Policies.ExcludeRoutes").
						Where("username = ?", username).First(&user)

					if policy := user.GetPolicy(); policy != nil {
						user.PolicyID = policy.ID
						user.Policy = *policy
					}

					isLDAPAuth = true
					log.Printf("OpenConnect: ✓ LDAP user %s authenticated (password correct, OTP correct)", username)

				} else {

					ldapUser, err := ldapAuth.Authenticate(username, password)
					if err == nil {

						if err := database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").Preload("Groups.Policies.ExcludeRoutes").
							Where("username = ?", username).First(&user).Error; err != nil {

							user = models.User{
								Username: username,
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
								log.Printf("OpenConnect: Failed to create LDAP user %s: %v", username, err)
								h.sendAuthError(c, "Failed to create user")
								return
							}

							var defaultGroup models.UserGroup

							groupName := "admin"
							if err := database.DB.Where("name = ?", groupName).First(&defaultGroup).Error; err != nil {
								log.Printf("OpenConnect: Warning: Default user group 'admin' not found, LDAP user %s will have no groups (may affect VPN access)", username)
							}

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

							database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").Preload("Groups.Policies.ExcludeRoutes").
								Where("username = ?", username).First(&user)

							if policy := user.GetPolicy(); policy != nil {
								user.PolicyID = policy.ID
								user.Policy = *policy
							}
						} else {

							if !user.IsActive {
								log.Printf("OpenConnect: User %s is disabled, rejecting LDAP authentication", username)
								h.sendAuthError(c, "您的账户已被禁用，无法连接VPN。请联系管理员激活账户。")
								return
							}

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
								if err := database.DB.Save(&user).Error; err != nil {
									log.Printf("OpenConnect: Failed to update LDAP user %s: %v", username, err)
								} else {
									log.Printf("OpenConnect: ✓ LDAP user synced: %s (email: %s, fullname: %s, admin: %v)",
										username, ldapUser.Email, ldapUser.FullName, ldapUser.IsAdmin)
								}

								database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").Preload("Groups.Policies.ExcludeRoutes").
									Where("username = ?", username).First(&user)

								if policy := user.GetPolicy(); policy != nil {
									user.PolicyID = policy.ID
									user.Policy = *policy
								}
							}
						}

						isLDAPAuth = true
						log.Printf("OpenConnect: ✓ User %s authenticated via LDAP (password correct)", username)

						if user.OTPEnabled && user.OTPSecret != "" {
							log.Printf("OpenConnect: LDAP password correct for user %s, requesting OTP code", username)
							h.sendOTPRequest(c, username, "")
							return
						}

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

				log.Printf("OpenConnect: User %s is a system account (source: %s), skipping LDAP authentication", username, existingUser.Source)

			}
		} else {

			var ldapPassword = password
			ldapUser, err := ldapAuth.Authenticate(username, ldapPassword)
			if err == nil {
				user = models.User{
					Username: username,
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
					log.Printf("OpenConnect: Failed to create LDAP user %s: %v", username, err)
					h.sendAuthError(c, "Failed to create user")
					return
				}

				var defaultGroup models.UserGroup
				groupName := "admin"
				if err := database.DB.Where("name = ?", groupName).First(&defaultGroup).Error; err == nil {
					database.DB.Model(&user).Association("Groups").Append(&defaultGroup)
				} else {
					log.Printf("OpenConnect: Warning: Default user group 'admin' not found, LDAP user %s will have no groups (may affect VPN access)", username)
				}

				database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").
					Where("username = ?", username).First(&user)

				if policy := user.GetPolicy(); policy != nil {
					user.PolicyID = policy.ID
					user.Policy = *policy
				}

				isLDAPAuth = true
				log.Printf("OpenConnect: ✓ LDAP user created and authenticated: %s", username)
			} else {

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

	if !isLDAPAuth {
		if err := database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").Preload("Groups.Policies.ExcludeRoutes").
			Where("username = ?", username).First(&user).Error; err != nil {
			log.Printf("OpenConnect: User not found: %s", username)

			auditLogger := policy.GetAuditLogger()
			if auditLogger != nil {
				auditLogger.LogAuthWithIP(0, username, models.AuditLogActionLogin, "failed",
					fmt.Sprintf("User not found. Source IP: %s", clientIP), clientIP, 0)
			}

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

			auditLogger := policy.GetAuditLogger()
			if auditLogger != nil {
				clientIP := c.ClientIP()
				auditLogger.LogAuthWithIP(user.ID, username, models.AuditLogActionLogin, "failed",
					fmt.Sprintf("Account disabled. Source IP: %s", clientIP), clientIP, 0)
			}
			h.sendAuthError(c, "您的账户已被禁用，无法连接VPN。请联系管理员激活账户。")
			return
		}

		if user.OTPEnabled && user.OTPSecret != "" {

			var otpCode string
			var passwordToken string
			if len(bodyBytes) > 0 && bytes.HasPrefix(bytes.TrimSpace(bodyBytes), []byte("<?xml")) {
				var authReq AuthRequest
				if err := xml.Unmarshal(bodyBytes, &authReq); err == nil {
					otpCode = authReq.Auth.OTPCode
					passwordToken = authReq.Auth.PasswordToken

					if authReq.Auth.Username != "" {
						username = authReq.Auth.Username
					}
					log.Printf("OpenConnect: XML parsed for OTP step - username: %s, has OTP: %v, has token: %v",
						username, otpCode != "", passwordToken != "")
				}
			}
			if otpCode == "" || passwordToken == "" {

				c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				if err := c.Request.ParseForm(); err == nil {
					otpCode = c.Request.PostForm.Get("otp-code")
					passwordToken = c.Request.PostForm.Get("password-token")

					if formUsername := c.Request.PostForm.Get("username"); formUsername != "" {
						username = formUsername
					}
					log.Printf("OpenConnect: Form parsed for OTP step - username: %s, has OTP: %v, has token: %v",
						username, otpCode != "", passwordToken != "")
				}
			}

			var isOTPSetup bool
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			if err := c.Request.ParseForm(); err == nil {
				if c.Request.PostForm.Get("otp-setup") == "true" {
					isOTPSetup = true
				}
			}

			if otpCode != "" && passwordToken != "" {

				if !h.verifyPasswordToken(passwordToken, username) {
					log.Printf("OpenConnect: Invalid password token for user %s (OTP step 2)", username)
					h.sendAuthError(c, "Session expired. Please login again.")
					return
				}

				if isOTPSetup {

					if err := database.DB.Where("username = ?", username).First(&user).Error; err != nil {
						log.Printf("OpenConnect: Failed to reload user %s for OTP setup", username)
						h.sendAuthError(c, "User not found")
						return
					}

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

					user.OTPEnabled = true
					if err := database.DB.Save(&user).Error; err != nil {
						log.Printf("OpenConnect: Failed to enable OTP for user %s: %v", username, err)
						h.sendAuthError(c, "Failed to enable OTP")
						return
					}

					database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").Preload("Groups.Policies.ExcludeRoutes").
						Where("username = ?", username).First(&user)
					log.Printf("OpenConnect: User %s OTP setup completed and enabled", username)
				} else {

					otpAuth := auth.NewOTPAuthenticator("ZVPN")
					if !otpAuth.ValidateOTP(user.OTPSecret, otpCode) {
						log.Printf("OpenConnect: Invalid OTP code for user %s", username)

						auditLogger := policy.GetAuditLogger()
						if auditLogger != nil {
							auditLogger.LogAuthWithIP(user.ID, username, models.AuditLogActionLogin, "failed",
								fmt.Sprintf("Invalid OTP code. Source IP: %s", clientIP), clientIP, 0)
						}

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

				if !user.CheckPassword(password) {
					log.Printf("OpenConnect: Invalid password for user %s (OTP enabled, step 1)", username)

					auditLogger := policy.GetAuditLogger()
					if auditLogger != nil {
						auditLogger.LogAuthWithIP(user.ID, username, models.AuditLogActionLogin, "failed",
							fmt.Sprintf("Invalid password (OTP enabled). Source IP: %s", clientIP), clientIP, 0)
					}

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

				log.Printf("OpenConnect: Password correct for user %s, requesting OTP code", username)
				h.sendOTPRequest(c, username, "")
				return
			}
		} else if user.OTPEnabled && user.OTPSecret == "" {

			if !user.CheckPassword(password) {
				log.Printf("OpenConnect: Invalid password for user %s (OTP enabled but not configured)", username)

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

			log.Printf("OpenConnect: Password correct for user %s, requesting OTP setup (first login)", username)
			h.sendOTPSetupRequest(c, username)
			return
		} else {

			if !user.CheckPassword(password) {
				log.Printf("OpenConnect: Invalid password for user %s", username)

				auditLogger := policy.GetAuditLogger()
				if auditLogger != nil {
					auditLogger.LogAuthWithIP(user.ID, username, models.AuditLogActionLogin, "failed",
						fmt.Sprintf("Invalid password. Source IP: %s", clientIP), clientIP, 0)
				}

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
			log.Printf("OpenConnect: User %s authenticated successfully (OTP disabled)", username)
		}
	}

	if !h.config.VPN.AllowMultiClientLogin && user.Connected {

		if h.vpnServer != nil {
			_, hasActiveConnection := h.vpnServer.GetClient(user.ID)
			if !hasActiveConnection {

				log.Printf("OpenConnect: User %s marked as connected but no active connection found, resetting status", username)
				user.Connected = false
				user.VPNIP = ""
				if err := database.DB.Model(&user).Select("connected", "vpn_ip", "updated_at").Updates(user).Error; err != nil {
					log.Printf("OpenConnect: Failed to reset user connection status: %v", err)
				} else {
					log.Printf("OpenConnect: User %s connection status reset successfully", username)
				}
			} else {

				log.Printf("OpenConnect: REJECTED - User %s already connected (VPN IP: %s), multi-client login disabled", username, user.VPNIP)
				log.Printf("OpenConnect: Client IP: %s, User-Agent: %s", clientIP, c.GetHeader("User-Agent"))
				h.sendAuthError(c, "该账号已在线，已禁止多端同时登录")
				return
			}
		} else {

			log.Printf("OpenConnect: REJECTED - User %s already connected (VPN IP: %s), multi-client login disabled (VPN server not initialized)", username, user.VPNIP)
			log.Printf("OpenConnect: Client IP: %s, User-Agent: %s", clientIP, c.GetHeader("User-Agent"))
			h.sendAuthError(c, "该账号已在线，已禁止多端同时登录")
			return
		}
	}

	sessionIDOnly := fmt.Sprintf("%s-%d", username, user.ID)
	timestamp := time.Now().Unix()
	tokenInput := fmt.Sprintf("%s-%d", sessionIDOnly, timestamp)
	hash := md5.Sum([]byte(tokenInput))
	sessionToken := strings.ToUpper(hex.EncodeToString(hash[:]))

	session := models.Session{
		UserID:    user.ID,
		Token:     sessionToken,
		IPAddress: clientIP,
		UserAgent: c.GetHeader("User-Agent"),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Active:    true,
	}
	if err := database.DB.Create(&session).Error; err != nil {
		log.Printf("OpenConnect: Failed to create session for user %s: %v", username, err)
		h.sendAuthError(c, "Failed to create session")
		return
	}

	log.Printf("OpenConnect: Created session for user %s (sessionID: %s, token: %s..., expires at: %s)",
		username, sessionIDOnly, sessionToken[:16], session.ExpiresAt.Format(time.RFC3339))

	if user.VPNIP == "" {
		_, ipNet, _ := net.ParseCIDR(h.config.VPN.Network)
		ipPool, err := vpn.NewIPPool(ipNet)
		if err != nil {
			h.sendAuthError(c, "IP allocation failed")
			return
		}

		var gatewayIP net.IP
		if h.vpnServer != nil {
			gatewayIP = h.vpnServer.GetVPNGatewayIP()
		}
		if gatewayIP == nil {

			gatewayIP = make(net.IP, len(ipNet.IP))
			copy(gatewayIP, ipNet.IP)
			gatewayIP[len(gatewayIP)-1] = 1
		}

		vpnIP, err := ipPool.Allocate()
		if err != nil {
			h.sendAuthError(c, "No available IPs")
			return
		}

		if vpnIP.Equal(gatewayIP) {
			vpnIP, err = ipPool.Allocate()
			if err != nil {
				h.sendAuthError(c, "No available IPs")
				return
			}
		}

		user.VPNIP = vpnIP.String()

		if err := database.DB.Model(&user).Select("vpn_ip", "updated_at").Updates(map[string]interface{}{
			"vpn_ip": user.VPNIP,
		}).Error; err != nil {
			log.Printf("OpenConnect: Warning - Failed to save VPN IP for user %s: %v", user.Username, err)
		}

		log.Printf("OpenConnect: Allocated IP %s to user %s (gateway: %s)",
			user.VPNIP, user.Username, gatewayIP.String())
	}

	log.Printf("OpenConnect: User %s authenticated successfully", username)

	if h.bruteforceProtection != nil {
		h.bruteforceProtection.RecordSuccess(clientIP)
	}

	var freshUser models.User
	if err := database.DB.Where("id = ?", user.ID).First(&freshUser).Error; err == nil {

		user.TunnelMode = freshUser.TunnelMode
	} else {
		log.Printf("OpenConnect: Warning - Failed to reload user %s for TunnelMode: %v", user.Username, err)
	}

	if policy := user.GetPolicy(); policy != nil {
		user.PolicyID = policy.ID
		user.Policy = *policy
	}

	_, ipNet, _ := net.ParseCIDR(h.config.VPN.Network)

	gatewayIP := make(net.IP, len(ipNet.IP))
	copy(gatewayIP, ipNet.IP)
	gatewayIP[len(gatewayIP)-1] = 1

	cookie := &http.Cookie{
		Name:     "webvpn",
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(c.Writer, cookie)
	log.Printf("OpenConnect: Setting webvpn cookie (sessionID: %s, token: %s)", sessionIDOnly, sessionToken)

	certInfo := h.getServerCertInfo()
	certHash := certInfo.SHA1Hash
	if certHash == "" {
		certHash = "0000000000000000000000000000000000000000"
	}

	if c.Request.TLS != nil {
	}

	profileHash := h.getProfileHash(c)
	if profileHash == "" {
		profileHash = "0000000000000000000000000000000000000000"
	}

	bannerText := handlers.GetBannerText()

	var bannerEscaped string
	if bannerText != "" {
		buf := new(strings.Builder)
		xml.EscapeText(buf, []byte(bannerText))
		bannerEscaped = buf.String()
	}

	xml := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
    <session-id>` + sessionToken + `</session-id>
    <session-token>` + sessionToken + `</session-token>
    <auth id="success">
        <banner>` + bannerEscaped + `</banner>
        <message id="0" param1="" param2=""></message>
    </auth>
    <capabilities>
        <crypto-supported>ssl-dhe</crypto-supported>
    </capabilities>
    <config client="vpn" type="private">
        <vpn-base-config>
            <server-cert-hash>` + certHash + `</server-cert-hash>
        </vpn-base-config>
        <opaque is-for="vpn-client"></opaque>
        <vpn-profile-manifest>
            <vpn rev="1.0">
                <file type="profile" service-type="user">
                    <uri>/profile.xml</uri>
                    <hash type="sha1">` + profileHash + `</hash>
                </file>
            </vpn>
        </vpn-profile-manifest>
    </config>
</config-auth>`

	c.Writer.Header().Del("Server")
	c.Writer.Header().Del("X-Powered-By")
	c.Header("X-Aggregate-Auth", "1")
	c.Header("Connection", "keep-alive")
	c.Header("Cache-Control", "no-store,no-cache")
	c.Header("Pragma", "no-cache")
	c.Header("Content-Type", "text/xml; charset=utf-8")
	c.Header("Content-Length", strconv.Itoa(len(xml)))

	log.Printf("OpenConnect: Authentication successful for user %s (session: %s)", user.Username, sessionToken[:8]+"...")
	c.Data(http.StatusOK, "text/xml; charset=utf-8", []byte(xml))
}

func (h *Handler) handleLogout(c *gin.Context) {
	c.SetCookie("webvpn", "", -1, "/", "", true, true)

	xml := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
	<logout>
		<message>Logout successful</message>
	</logout>
</config-auth>`

	h.setAnyConnectResponseHeaders(c)
	c.Header("Content-Type", "text/xml; charset=utf-8")
	c.Header("Content-Length", strconv.Itoa(len(xml)))

	c.Data(http.StatusOK, "text/xml; charset=utf-8", []byte(xml))
}

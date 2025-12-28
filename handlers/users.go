package handlers

import (
	"encoding/base64"
	"fmt"
	"image/png"
	"log"
	"net/http"
	"strings"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/vpn/policy"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
)

type UserHandler struct {
	config *config.Config
}

func NewUserHandler(cfg *config.Config) *UserHandler {
	return &UserHandler{config: cfg}
}

type CreateUserRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email"`
	FullName string `json:"full_name"` // 中文名/全名（可选）
	IsAdmin  bool   `json:"is_admin"`
	GroupIDs []uint `json:"group_ids" binding:"required"` // 必须指定用户组
}

type UpdateUserRequest struct {
	Email      string `json:"email"`
	FullName   string `json:"full_name"` // 中文名/全名（可选）
	IsAdmin    bool   `json:"is_admin"`  // 管理员状态
	IsActive   bool   `json:"is_active"`
	GroupIDs   []uint `json:"group_ids"`   // 更新用户组
	Password   string `json:"password"`    // 密码（可选，留空则不修改）
	TunnelMode string `json:"tunnel_mode"` // 隧道模式: split(分隧道) 或 full(全局)
}

func (h *UserHandler) ListUsers(c *gin.Context) {
	var users []models.User
	if err := database.DB.Preload("Groups").Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 清除密码哈希，不返回策略信息（策略只在用户组中管理）
	for i := range users {
		users[i].PasswordHash = ""
	}

	c.JSON(http.StatusOK, users)
}

func (h *UserHandler) GetUser(c *gin.Context) {
	id := c.Param("id")
	var user models.User
	if err := database.DB.Preload("Groups").First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	user.PasswordHash = ""
	// 不返回策略信息（策略只在用户组中管理）
	c.JSON(http.StatusOK, user)
}

func (h *UserHandler) CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证用户组是否存在（必填）
	if len(req.GroupIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户必须属于至少一个用户组"})
		return
	}

	var groups []models.UserGroup
	if err := database.DB.Find(&groups, req.GroupIDs).Error; err != nil || len(groups) != len(req.GroupIDs) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "部分用户组不存在"})
		return
	}

	user := &models.User{
		Username: req.Username,
		Email:    req.Email,
		FullName: req.FullName,
		IsAdmin:  req.IsAdmin,
		IsActive: true,
		Source:   models.UserSourceSystem, // 系统账户
		Groups:   groups,
	}

	if err := user.SetPassword(req.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	if err := database.DB.Create(user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 记录配置变更审计日志
	auditLogger := policy.GetAuditLogger()
	if auditLogger != nil {
		operatorID, _ := c.Get("user_id")
		operatorIDUint := uint(0)
		if id, ok := operatorID.(uint); ok {
			operatorIDUint = id
		}
		auditLogger.WriteLogDirectly(models.AuditLog{
			UserID:       operatorIDUint,
			Type:         models.AuditLogTypeConfig,
			Action:       models.AuditLogActionAllow, // 使用allow表示创建操作
			Protocol:     "https",                    // 配置操作通过Web界面，使用HTTPS
			ResourceType: "user",
			ResourcePath: fmt.Sprintf("user:%s", user.Username),
			Result:       "success",
			Reason:       fmt.Sprintf("User created: %s (ID: %d, Admin: %v)", user.Username, user.ID, user.IsAdmin),
		})
	}

	// 预加载用户组（不加载策略，策略只在用户组中管理）
	database.DB.Preload("Groups").First(user, user.ID)

	user.PasswordHash = ""
	// 不返回策略信息
	c.JSON(http.StatusCreated, user)
}

func (h *UserHandler) UpdateUser(c *gin.Context) {
	id := c.Param("id")
	var user models.User
	if err := database.DB.Preload("Groups").First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Email != "" {
		user.Email = req.Email
	}
	// 更新FullName（如果提供了非空值则更新）
	// 注意：空字符串不会更新，保持原值（如果需要清空，前端需要明确传递空字符串）
	if req.FullName != "" {
		user.FullName = req.FullName
	}
	// 更新IsAdmin
	user.IsAdmin = req.IsAdmin
	user.IsActive = req.IsActive

	// 更新隧道模式（如果提供了）
	updateTunnelMode := false
	if req.TunnelMode != "" {
		if req.TunnelMode != "split" && req.TunnelMode != "full" {
			log.Printf("UpdateUser: Invalid tunnel_mode value: '%s'", req.TunnelMode)
			c.JSON(http.StatusBadRequest, gin.H{"error": "tunnel_mode must be 'split' or 'full'"})
			return
		}
		user.TunnelMode = req.TunnelMode
		updateTunnelMode = true
	}

	// 更新用户组（如果提供了，必须至少一个）
	if req.GroupIDs != nil {
		if len(req.GroupIDs) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "用户必须属于至少一个用户组"})
			return
		}
		var groups []models.UserGroup
		if err := database.DB.Find(&groups, req.GroupIDs).Error; err != nil || len(groups) != len(req.GroupIDs) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "部分用户组不存在"})
			return
		}
		// 更新关联关系
		if err := database.DB.Model(&user).Association("Groups").Replace(groups); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	// 如果没有提供用户组字段（nil），保持原有用户组不变

	// 处理密码更新（如果提供了密码字段）
	updatePassword := false
	if req.Password != "" {
		// 检查是否是LDAP用户
		if user.Source == models.UserSourceLDAP {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot change password for LDAP user. Password is managed by LDAP server."})
			return
		}

		// 设置新密码
		if err := user.SetPassword(req.Password); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		updatePassword = true
		log.Printf("UpdateUser: Password will be updated for user '%s'", user.Username)
	}

	// 使用 Select 明确指定要更新的字段
	// 只更新实际需要更新的字段，避免意外覆盖其他字段
	updateFields := []string{"email", "full_name", "is_admin", "is_active", "updated_at"}
	if updateTunnelMode {
		updateFields = append(updateFields, "tunnel_mode")
	}
	if updatePassword {
		updateFields = append(updateFields, "password_hash")
	}
	if err := database.DB.Model(&user).Select(updateFields).Updates(user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 记录配置变更审计日志
	auditLogger := policy.GetAuditLogger()
	if auditLogger != nil {
		operatorID, _ := c.Get("user_id")
		operatorIDUint := uint(0)
		if id, ok := operatorID.(uint); ok {
			operatorIDUint = id
		}
		auditLogger.WriteLogDirectly(models.AuditLog{
			UserID:       operatorIDUint,
			Type:         models.AuditLogTypeConfig,
			Action:       models.AuditLogActionAllow,
			Protocol:     "https", // 配置操作通过Web界面，使用HTTPS
			ResourceType: "user",
			ResourcePath: fmt.Sprintf("user:%s", user.Username),
			Result:       "success",
			Reason:       fmt.Sprintf("User updated: %s (ID: %d, Admin: %v, Active: %v)", user.Username, user.ID, user.IsAdmin, user.IsActive),
		})
	}

	// 预加载用户组（不加载策略，策略只在用户组中管理）
	database.DB.Preload("Groups").First(&user, user.ID)

	user.PasswordHash = ""
	// 不返回策略信息
	c.JSON(http.StatusOK, user)
}

func (h *UserHandler) DeleteUser(c *gin.Context) {
	id := c.Param("id")

	// 先获取用户信息用于审计日志
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 记录配置变更审计日志
	auditLogger := policy.GetAuditLogger()
	if auditLogger != nil {
		operatorID, _ := c.Get("user_id")
		operatorIDUint := uint(0)
		if id, ok := operatorID.(uint); ok {
			operatorIDUint = id
		}
		auditLogger.WriteLogDirectly(models.AuditLog{
			UserID:       operatorIDUint,
			Type:         models.AuditLogTypeConfig,
			Action:       models.AuditLogActionDeny, // 使用deny表示删除操作
			Protocol:     "https",                   // 配置操作通过Web界面，使用HTTPS
			ResourceType: "user",
			ResourcePath: fmt.Sprintf("user:%s", user.Username),
			Result:       "success",
			Reason:       fmt.Sprintf("User deleted: %s (ID: %d)", user.Username, user.ID),
		})
	}

	// 开始事务，确保所有删除操作原子性
	tx := database.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 1. 删除用户组关联关系（user_group_users 中间表）
	if err := tx.Model(&user).Association("Groups").Clear(); err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to remove user from groups: %v", err)})
		return
	}

	// 2. 删除用户的所有会话（sessions 表）
	if err := tx.Where("user_id = ?", user.ID).Unscoped().Delete(&models.Session{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete user sessions: %v", err)})
		return
	}

	// 3. 删除用户本身
	if err := tx.Unscoped().Delete(&user).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete user: %v", err)})
		return
	}

	// 提交事务
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to commit transaction: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

func (h *UserHandler) ChangePassword(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("ChangePassword: Invalid request for user ID %s: %v", id, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		log.Printf("ChangePassword: User ID %s not found: %v", id, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	log.Printf("ChangePassword: Changing password for user '%s' (ID: %d, Source: %s)", user.Username, user.ID, user.Source)

	// 检查是否是LDAP用户
	if user.Source == models.UserSourceLDAP {
		log.Printf("ChangePassword: Cannot change password for LDAP user '%s' (password is managed by LDAP server)", user.Username)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot change password for LDAP user. Password is managed by LDAP server."})
		return
	}

	// 保存旧密码哈希长度用于日志
	oldPasswordHashLen := len(user.PasswordHash)

	if err := user.SetPassword(req.Password); err != nil {
		log.Printf("ChangePassword: Failed to hash password for user '%s': %v", user.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	log.Printf("ChangePassword: Password hashed successfully for user '%s' (old hash length: %d, new hash length: %d)",
		user.Username, oldPasswordHashLen, len(user.PasswordHash))

	// 使用 Select 明确指定只更新 password_hash 字段，避免其他字段被覆盖
	// 这样可以确保密码修改不会影响其他字段
	if err := database.DB.Model(&user).Select("password_hash", "updated_at").Updates(user).Error; err != nil {
		log.Printf("ChangePassword: Failed to save password for user '%s': %v", user.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 验证密码是否真的被更新了
	var verifyUser models.User
	if err := database.DB.Select("password_hash").First(&verifyUser, user.ID).Error; err == nil {
		if verifyUser.PasswordHash == user.PasswordHash {
			log.Printf("ChangePassword: Password verified successfully for user '%s' (hash length: %d)",
				user.Username, len(verifyUser.PasswordHash))
		} else {
			log.Printf("ChangePassword: WARNING - Password hash mismatch for user '%s' (expected length: %d, actual length: %d)",
				user.Username, len(user.PasswordHash), len(verifyUser.PasswordHash))
		}
	}

	log.Printf("ChangePassword: Password changed successfully for user '%s'", user.Username)
	c.JSON(http.StatusOK, gin.H{"message": "Password changed"})
}

// GetOTP 获取用户OTP状态
func (h *UserHandler) GetOTP(c *gin.Context) {
	id := c.Param("id")
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"enabled": user.OTPEnabled,
	})
}

// GenerateOTP 为用户生成OTP密钥
func (h *UserHandler) GenerateOTP(c *gin.Context) {
	id := c.Param("id")
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 生成OTP密钥和key对象（用于生成二维码）
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "ZVPN",
		AccountName: user.Username,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate OTP key"})
		return
	}

	secret := key.Secret()
	url := key.URL()

	// 生成二维码图片
	img, err := key.Image(200, 200)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate QR code"})
		return
	}

	// 将图片转换为base64
	var buf strings.Builder
	buf.WriteString("data:image/png;base64,")
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	if err := png.Encode(encoder, img); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode QR code"})
		return
	}
	encoder.Close()
	qrCode := buf.String()

	// 保存OTP密钥到用户
	// 使用 Select 明确指定只更新 OTP 相关字段，避免覆盖密码
	user.OTPSecret = secret
	user.OTPEnabled = true
	if err := database.DB.Model(&user).Select("otp_secret", "otp_enabled", "updated_at").Updates(user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save OTP secret"})
		return
	}

	// 记录OTP配置变更审计日志
	auditLogger := policy.GetAuditLogger()
	if auditLogger != nil {
		operatorID, _ := c.Get("user_id")
		operatorIDUint := uint(0)
		if id, ok := operatorID.(uint); ok {
			operatorIDUint = id
		}
		auditLogger.WriteLogDirectly(models.AuditLog{
			UserID:       operatorIDUint,
			Type:         models.AuditLogTypeConfig,
			Action:       models.AuditLogActionAllow,
			Protocol:     "https", // 配置操作通过Web界面，使用HTTPS
			ResourceType: "otp",
			ResourcePath: fmt.Sprintf("user:%s", user.Username),
			Result:       "success",
			Reason:       fmt.Sprintf("OTP enabled for user: %s (ID: %d)", user.Username, user.ID),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"secret":  secret,
		"qr_code": qrCode,
		"url":     url,
		"enabled": true,
		"message": "OTP密钥生成成功，请妥善保管",
	})
}

// DisableOTP 禁用用户OTP
func (h *UserHandler) DisableOTP(c *gin.Context) {
	id := c.Param("id")
	var user models.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 清除OTP密钥并禁用
	// 使用 Select 明确指定只更新 OTP 相关字段，避免覆盖密码
	user.OTPSecret = ""
	user.OTPEnabled = false
	if err := database.DB.Model(&user).Select("otp_secret", "otp_enabled", "updated_at").Updates(user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable OTP"})
		return
	}

	// 记录OTP配置变更审计日志
	auditLogger := policy.GetAuditLogger()
	if auditLogger != nil {
		operatorID, _ := c.Get("user_id")
		operatorIDUint := uint(0)
		if id, ok := operatorID.(uint); ok {
			operatorIDUint = id
		}
		auditLogger.WriteLogDirectly(models.AuditLog{
			UserID:       operatorIDUint,
			Type:         models.AuditLogTypeConfig,
			Action:       models.AuditLogActionDeny,
			Protocol:     "https", // 配置操作通过Web界面，使用HTTPS
			ResourceType: "otp",
			ResourcePath: fmt.Sprintf("user:%s", user.Username),
			Result:       "success",
			Reason:       fmt.Sprintf("OTP disabled for user: %s (ID: %d)", user.Username, user.ID),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "OTP认证已禁用",
		"enabled": false,
	})
}

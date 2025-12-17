package handlers

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/fisker/zvpn/auth"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
	"gorm.io/gorm"
)

type LDAPConfigHandler struct{}

func NewLDAPConfigHandler() *LDAPConfigHandler {
	return &LDAPConfigHandler{}
}

// getLDAPConfig 获取LDAP配置（内部函数）
func getLDAPConfig() (*models.LDAPConfig, error) {
	var config models.LDAPConfig
	err := database.DB.First(&config).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			// 如果不存在，创建默认配置
			config = models.LDAPConfig{
				Enabled:       false,
				Host:          "",
				Port:          389,
				UseSSL:        false,
				BindDN:        "",
				BindPassword:  "",
				BaseDN:        "",
				UserFilter:    "(uid=%s)",
				AdminGroup:    "",
				SkipTLSVerify: false,
			}
			if err := database.DB.Create(&config).Error; err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	return &config, nil
}

// saveLDAPConfig 保存LDAP配置（内部函数）
func saveLDAPConfig(config *models.LDAPConfig) error {
	var existing models.LDAPConfig
	if err := database.DB.First(&existing).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			// 不存在则创建
			return database.DB.Create(config).Error
		}
		return err
	}
	// 存在则更新
	config.ID = existing.ID
	return database.DB.Save(config).Error
}

// convertToAuthLDAPConfig 将models.LDAPConfig转换为auth.LDAPConfig
func convertToAuthLDAPConfig(config *models.LDAPConfig) *auth.LDAPConfig {
	// 获取属性映射配置
	mapping := config.GetAttributeMapping()

	return &auth.LDAPConfig{
		Enabled:       config.Enabled,
		Host:          config.Host,
		Port:          config.Port,
		UseSSL:        config.UseSSL,
		BindDN:        config.BindDN,
		BindPassword:  config.BindPassword,
		BaseDN:        config.BaseDN,
		UserFilter:    config.UserFilter,
		AdminGroup:    config.AdminGroup,
		SkipTLSVerify: config.SkipTLSVerify,
		AttributeMapping: auth.AttributeMapping{
			UsernameAttribute: mapping.UsernameAttribute,
			EmailAttribute:    mapping.EmailAttribute,
			FullNameAttribute: mapping.FullNameAttribute,
			MemberOfAttribute: mapping.MemberOfAttribute,
		},
	}
}

// GetLDAPConfig 获取LDAP配置
func (h *LDAPConfigHandler) GetLDAPConfig(c *gin.Context) {
	config, err := getLDAPConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 不返回密码字段
	response := gin.H{
		"id":              config.ID,
		"enabled":         config.Enabled,
		"host":            config.Host,
		"port":            config.Port,
		"use_ssl":         config.UseSSL,
		"bind_dn":         config.BindDN,
		"base_dn":         config.BaseDN,
		"user_filter":     config.UserFilter,
		"admin_group":     config.AdminGroup,
		"skip_tls_verify": config.SkipTLSVerify,
		"created_at":      config.CreatedAt,
		"updated_at":      config.UpdatedAt,
	}

	c.JSON(http.StatusOK, response)
}

// UpdateLDAPConfig 更新LDAP配置
func (h *LDAPConfigHandler) UpdateLDAPConfig(c *gin.Context) {
	var req struct {
		Enabled          bool   `json:"enabled"`
		Host             string `json:"host"`
		Port             int    `json:"port"`
		UseSSL           bool   `json:"use_ssl"`
		BindDN           string `json:"bind_dn"`
		BindPassword     string `json:"bind_password"`
		BaseDN           string `json:"base_dn"`
		UserFilter       string `json:"user_filter"`
		AdminGroup       string `json:"admin_group"`
		SkipTLSVerify    bool   `json:"skip_tls_verify"`
		AttributeMapping string `json:"attribute_mapping"` // JSON格式的属性映射
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 获取现有配置
	config, err := getLDAPConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 更新配置
	config.Enabled = req.Enabled
	config.Host = req.Host
	config.Port = req.Port
	if config.Port == 0 {
		config.Port = 389 // 默认端口
	}
	config.UseSSL = req.UseSSL
	config.BindDN = req.BindDN
	// 只有提供了新密码才更新
	if req.BindPassword != "" {
		config.BindPassword = req.BindPassword
	}
	config.BaseDN = req.BaseDN
	config.UserFilter = req.UserFilter
	if config.UserFilter == "" {
		config.UserFilter = "(uid=%s)" // 默认过滤器
	}
	config.AdminGroup = req.AdminGroup
	config.SkipTLSVerify = req.SkipTLSVerify
	// 更新属性映射配置（如果提供）
	if req.AttributeMapping != "" {
		// 验证JSON格式
		var testMapping models.LDAPAttributeMapping
		if err := json.Unmarshal([]byte(req.AttributeMapping), &testMapping); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("属性映射配置格式错误: %v", err)})
			return
		}
		config.AttributeMapping = req.AttributeMapping
	}

	if err := saveLDAPConfig(config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 返回更新后的配置（不包含密码）
	response := gin.H{
		"id":                config.ID,
		"enabled":           config.Enabled,
		"host":              config.Host,
		"port":              config.Port,
		"use_ssl":           config.UseSSL,
		"bind_dn":           config.BindDN,
		"base_dn":           config.BaseDN,
		"user_filter":       config.UserFilter,
		"admin_group":       config.AdminGroup,
		"skip_tls_verify":   config.SkipTLSVerify,
		"attribute_mapping": config.AttributeMapping,
		"updated_at":        config.UpdatedAt,
	}

	c.JSON(http.StatusOK, response)
}

// GetLDAPStatus 获取LDAP配置状态（公开接口）
func (h *LDAPConfigHandler) GetLDAPStatus(c *gin.Context) {
	config, err := getLDAPConfig()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"enabled": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"enabled": config.Enabled,
	})
}

// TestLDAPConnection 测试LDAP连接
func (h *LDAPConfigHandler) TestLDAPConnection(c *gin.Context) {
	config, err := getLDAPConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if !config.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "LDAP未启用"})
		return
	}

	// 验证必填字段
	if config.Host == "" || config.BindDN == "" || config.BaseDN == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "LDAP配置不完整：请填写Host、BindDN和BaseDN",
		})
		return
	}

	// 测试连接
	address := fmt.Sprintf("%s:%d", config.Host, config.Port)
	var conn *ldap.Conn
	var connErr error

	if config.UseSSL {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: config.SkipTLSVerify,
		}
		conn, connErr = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		conn, connErr = ldap.Dial("tcp", address)
	}

	if connErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("无法连接到LDAP服务器 %s: %v", address, connErr),
		})
		return
	}
	defer conn.Close()

	// 测试管理员账号绑定
	if err := conn.Bind(config.BindDN, config.BindPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("LDAP绑定失败（请检查BindDN和BindPassword）: %v", err),
		})
		return
	}

	// 测试BaseDN搜索（可选，验证BaseDN是否正确）
	searchRequest := ldap.NewSearchRequest(
		config.BaseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)
	if _, err := conn.Search(searchRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("BaseDN验证失败（请检查BaseDN是否正确）: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "LDAP连接测试成功",
	})
}

// TestLDAPAuth 测试LDAP用户认证（需要用户名和密码）
func (h *LDAPConfigHandler) TestLDAPAuth(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("参数错误: %v", err),
		})
		return
	}

	config, err := getLDAPConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	if !config.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "LDAP未启用",
		})
		return
	}

	// 验证必填字段
	if config.Host == "" || config.BindDN == "" || config.BaseDN == "" || config.UserFilter == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "LDAP配置不完整：请填写Host、BindDN、BaseDN和UserFilter",
		})
		return
	}

	// 连接LDAP服务器
	address := fmt.Sprintf("%s:%d", config.Host, config.Port)
	var conn *ldap.Conn
	var connErr error

	if config.UseSSL {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: config.SkipTLSVerify,
		}
		conn, connErr = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		conn, connErr = ldap.Dial("tcp", address)
	}

	if connErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("无法连接到LDAP服务器 %s: %v", address, connErr),
		})
		return
	}
	defer conn.Close()

	// 使用管理员账号绑定
	if err := conn.Bind(config.BindDN, config.BindPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("LDAP管理员绑定失败: %v", err),
		})
		return
	}

	// 构建搜索过滤器（支持 %s 和 {0} 格式）
	escapedUsername := ldap.EscapeFilter(req.Username)
	filter := config.UserFilter
	if strings.Contains(filter, "{0}") {
		filter = strings.ReplaceAll(filter, "{0}", escapedUsername)
	} else if strings.Contains(filter, "%s") {
		filter = fmt.Sprintf(filter, escapedUsername)
	} else {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("UserFilter格式错误：必须包含 %%s 或 {0} 占位符，当前值: %s", config.UserFilter),
		})
		return
	}

	// 获取属性映射配置
	mapping := config.GetAttributeMapping()
	emailAttr := mapping.EmailAttribute
	if emailAttr == "" {
		emailAttr = "mail"
	}
	fullNameAttr := mapping.FullNameAttribute
	if fullNameAttr == "" {
		fullNameAttr = "displayName"
	}
	memberOfAttr := mapping.MemberOfAttribute
	if memberOfAttr == "" {
		memberOfAttr = "memberOf"
	}

	// 构建属性列表（包含配置的属性以及常见的fallback属性）
	attributes := []string{"dn", "cn", emailAttr, fullNameAttr, memberOfAttr}
	// 添加常见的fallback属性
	attributes = append(attributes, "uid", "sAMAccountName")

	// 搜索用户
	searchRequest := ldap.NewSearchRequest(
		config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("搜索用户失败（请检查UserFilter和BaseDN）: %v", err),
		})
		return
	}

	if len(result.Entries) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("用户 '%s' 未找到（请检查UserFilter和BaseDN）", req.Username),
		})
		return
	}

	if len(result.Entries) > 1 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("找到多个匹配的用户 '%s'（UserFilter可能不够精确）", req.Username),
		})
		return
	}

	userDN := result.Entries[0].DN
	userInfo := result.Entries[0]

	// 使用用户凭据验证
	if err := conn.Bind(userDN, req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("用户认证失败（密码错误）: %v", err),
		})
		return
	}

	// 检查用户是否是管理员（如果配置了管理员组）
	isAdmin := false
	adminInfo := ""
	if config.AdminGroup != "" {
		memberOfList := userInfo.GetAttributeValues(memberOfAttr)
		for _, memberOf := range memberOfList {
			if memberOf == config.AdminGroup {
				isAdmin = true
				break
			}
		}
		if isAdmin {
			adminInfo = fmt.Sprintf("，用户属于管理员组: %s", config.AdminGroup)
		} else {
			adminInfo = fmt.Sprintf("，用户不属于管理员组: %s", config.AdminGroup)
		}
	}

	// 获取用户信息（使用配置的属性映射）
	email := userInfo.GetAttributeValue(emailAttr)
	fullName := userInfo.GetAttributeValue(fullNameAttr)
	// 如果全名为空，尝试使用cn作为fallback
	if fullName == "" {
		fullName = userInfo.GetAttributeValue("cn")
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("用户认证成功%s", adminInfo),
		"user": gin.H{
			"dn":        userDN,
			"username":  req.Username,
			"email":     email,
			"full_name": fullName,
			"is_admin":  isAdmin,
		},
	})
}

// SyncLDAPUsers 同步 LDAP 用户到本地数据库
func (h *LDAPConfigHandler) SyncLDAPUsers(c *gin.Context) {
	config, err := getLDAPConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	if !config.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "LDAP未启用",
		})
		return
	}

	// 验证必填字段
	if config.Host == "" || config.BindDN == "" || config.BaseDN == "" || config.UserFilter == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "LDAP配置不完整：请填写Host、BindDN、BaseDN和UserFilter",
		})
		return
	}

	// 创建 LDAP 认证器（使用属性映射配置）
	authConfig := convertToAuthLDAPConfig(config)
	ldapAuth := auth.NewLDAPAuthenticator(authConfig)

	// 搜索所有 LDAP 用户
	ldapUsers, err := ldapAuth.SearchAllUsers()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   fmt.Sprintf("搜索LDAP用户失败: %v", err),
		})
		return
	}

	if len(ldapUsers) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "未找到LDAP用户",
			"synced":  0,
			"created": 0,
			"updated": 0,
		})
		return
	}

	// 确保默认用户组存在
	var defaultGroup models.UserGroup
	var adminGroup models.UserGroup

	// 查找或创建 default 组
	if err := database.DB.Where("name = ?", "default").First(&defaultGroup).Error; err != nil {
		var defaultPolicy models.Policy
		if err := database.DB.Where("name = ?", "default").First(&defaultPolicy).Error; err == nil {
			defaultGroup = models.UserGroup{
				Name:        "default",
				Description: "默认用户组",
			}
			if err := database.DB.Create(&defaultGroup).Error; err == nil {
				database.DB.Model(&defaultGroup).Association("Policies").Append(&defaultPolicy)
			}
		}
	}

	// 查找 admin 组（如果不存在则跳过，不影响普通用户分配）
	if err := database.DB.Where("name = ?", "admin").First(&adminGroup).Error; err != nil {
		log.Printf("Warning: Admin group not found, admin users will be assigned to default group")
		adminGroup.ID = 0 // 确保ID为0，表示不存在
	}

	// 批量查询已存在的用户（建立用户名映射）
	var existingUsers []models.User
	usernames := make([]string, 0, len(ldapUsers))
	for _, ldapUser := range ldapUsers {
		usernames = append(usernames, ldapUser.Username)
	}
	if len(usernames) > 0 {
		database.DB.Where("username IN ?", usernames).Find(&existingUsers)
	}

	// 建立用户名到用户的映射
	existingUserMap := make(map[string]*models.User)
	for i := range existingUsers {
		existingUserMap[existingUsers[i].Username] = &existingUsers[i]
	}

	// 分离需要创建和更新的用户
	var usersToCreate []models.User
	var usersToUpdate []models.User
	userGroupMap := make(map[string]*models.UserGroup) // 记录每个用户应该分配的用户组

	for _, ldapUser := range ldapUsers {
		if existingUser, exists := existingUserMap[ldapUser.Username]; exists {
			// 用户已存在，检查是否需要更新
			needsUpdate := false
			// 确保Source字段正确设置为LDAP
			if existingUser.Source != models.UserSourceLDAP {
				existingUser.Source = models.UserSourceLDAP
				existingUser.PasswordHash = "" // 清空密码（LDAP用户不需要密码）
				needsUpdate = true
			}
			if existingUser.Email != ldapUser.Email && ldapUser.Email != "" {
				existingUser.Email = ldapUser.Email
				needsUpdate = true
			}
			if existingUser.IsAdmin != ldapUser.IsAdmin {
				existingUser.IsAdmin = ldapUser.IsAdmin
				needsUpdate = true
			}
			// 更新LDAP属性
			if existingUser.LDAPDN != ldapUser.DN && ldapUser.DN != "" {
				existingUser.LDAPDN = ldapUser.DN
				needsUpdate = true
			}
			if existingUser.FullName != ldapUser.FullName && ldapUser.FullName != "" {
				existingUser.FullName = ldapUser.FullName
				needsUpdate = true
			}
			// 更新LDAP原始属性JSON（用于扩展）
			if len(ldapUser.Attributes) > 0 {
				if attrsJSON, err := json.Marshal(ldapUser.Attributes); err == nil {
					if existingUser.LDAPAttributes != string(attrsJSON) {
						existingUser.LDAPAttributes = string(attrsJSON)
						needsUpdate = true
					}
				}
			}
			if needsUpdate {
				usersToUpdate = append(usersToUpdate, *existingUser)
			}

			// 确定用户组
			groupToAssign := &defaultGroup
			if ldapUser.IsAdmin && adminGroup.ID > 0 {
				groupToAssign = &adminGroup
			}
			userGroupMap[ldapUser.Username] = groupToAssign
		} else {
			// 用户不存在，准备创建
			user := models.User{
				Username: ldapUser.Username,
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
			usersToCreate = append(usersToCreate, user)

			// 确定用户组
			groupToAssign := &defaultGroup
			if ldapUser.IsAdmin && adminGroup.ID > 0 {
				groupToAssign = &adminGroup
			}
			userGroupMap[ldapUser.Username] = groupToAssign
		}
	}

	// 批量创建新用户
	createdCount := 0
	errorCount := 0
	var errors []string
	var createdUsernames []string // 记录成功创建的用户名，用于后续组分配

	if len(usersToCreate) > 0 {
		// 使用 CreateInBatches 批量插入（每批100条）
		// GORM的CreateInBatches会自动填充ID字段
		if err := database.DB.CreateInBatches(usersToCreate, 100).Error; err != nil {
			log.Printf("Error batch creating users: %v", err)
			errorCount += len(usersToCreate)
			errors = append(errors, fmt.Sprintf("批量创建用户失败: %v", err))
		} else {
			createdCount = len(usersToCreate)
			// 记录成功创建的用户名
			for _, user := range usersToCreate {
				createdUsernames = append(createdUsernames, user.Username)
			}
		}
	}

	// 批量更新已存在的用户
	updatedCount := 0
	if len(usersToUpdate) > 0 {
		// 使用 Select 明确指定只更新 LDAP 相关字段，避免覆盖其他字段
		// 注意：LDAP用户的密码会被清空（password_hash = ""），因为密码存储在LDAP服务器中
		updateFields := []string{"source", "password_hash", "email", "is_admin", "ldap_dn", "full_name", "ldap_attributes", "updated_at"}
		for _, user := range usersToUpdate {
			if err := database.DB.Model(&user).Select(updateFields).Updates(user).Error; err != nil {
				errorCount++
				errors = append(errors, fmt.Sprintf("用户 %s: 更新失败: %v", user.Username, err))
				log.Printf("Warning: Failed to update user %s: %v", user.Username, err)
			} else {
				updatedCount++
			}
		}
	}

	// 批量分配用户组关系
	// 确保至少有一个有效的用户组
	if defaultGroup.ID == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "默认用户组不存在，无法分配用户组",
		})
		return
	}

	// 重新查询所有需要分配组的用户（包括新创建和已存在的）
	// 这样可以确保获取到新创建用户的ID
	var allUsers []models.User
	if len(usernames) > 0 {
		database.DB.Where("username IN ?", usernames).Find(&allUsers)
	}

	// 建立用户ID到用户组的映射
	userGroupAssignments := make(map[uint]*models.UserGroup)
	for _, user := range allUsers {
		if group, ok := userGroupMap[user.Username]; ok && group != nil && group.ID > 0 {
			userGroupAssignments[user.ID] = group
		} else {
			// 如果没有找到对应的组，使用默认组
			userGroupAssignments[user.ID] = &defaultGroup
		}
	}

	// 批量分配用户组（使用事务提高性能）
	if len(userGroupAssignments) > 0 {
		tx := database.DB.Begin()
		hasError := false
		defer func() {
			if r := recover(); r != nil {
				tx.Rollback()
				log.Printf("Panic in user group assignment: %v", r)
			} else if hasError {
				tx.Rollback()
			}
		}()

		// 检查每个用户是否已经有组，如果没有则添加
		for userID, group := range userGroupAssignments {
			var user models.User
			if err := tx.First(&user, userID).Error; err != nil {
				log.Printf("Warning: User with ID %d not found for group assignment", userID)
				continue
			}

			// 检查用户是否已经有组
			// Count() 方法返回 int64，不是 error
			groupCount := tx.Model(&user).Association("Groups").Count()
			if groupCount == 0 {
				// 用户没有组，添加默认组
				if err := tx.Model(&user).Association("Groups").Append(group); err != nil {
					log.Printf("Warning: Failed to assign group '%s' to user %s: %v", group.Name, user.Username, err)
					hasError = true
					// 继续处理其他用户，不中断
				}
			}
		}

		if !hasError {
			if err := tx.Commit().Error; err != nil {
				log.Printf("Error committing user group assignments: %v", err)
				hasError = true
				tx.Rollback()
			}
		} else {
			tx.Rollback()
		}
	}

	response := gin.H{
		"success": true,
		"message": fmt.Sprintf("同步完成：共 %d 个用户，创建 %d 个，更新 %d 个", len(ldapUsers), createdCount, updatedCount),
		"total":   len(ldapUsers),
		"created": createdCount,
		"updated": updatedCount,
		"errors":  errorCount,
	}

	if len(errors) > 0 {
		response["error_details"] = errors
	}

	c.JSON(http.StatusOK, response)
}

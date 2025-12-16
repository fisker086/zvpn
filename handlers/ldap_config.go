package handlers

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/go-ldap/ldap/v3"
	"github.com/gin-gonic/gin"
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

// GetLDAPConfig 获取LDAP配置
func (h *LDAPConfigHandler) GetLDAPConfig(c *gin.Context) {
	config, err := getLDAPConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 不返回密码字段
	response := gin.H{
		"id":             config.ID,
		"enabled":        config.Enabled,
		"host":           config.Host,
		"port":           config.Port,
		"use_ssl":        config.UseSSL,
		"bind_dn":        config.BindDN,
		"base_dn":        config.BaseDN,
		"user_filter":    config.UserFilter,
		"admin_group":    config.AdminGroup,
		"skip_tls_verify": config.SkipTLSVerify,
		"created_at":     config.CreatedAt,
		"updated_at":     config.UpdatedAt,
	}

	c.JSON(http.StatusOK, response)
}

// UpdateLDAPConfig 更新LDAP配置
func (h *LDAPConfigHandler) UpdateLDAPConfig(c *gin.Context) {
	var req struct {
		Enabled       bool   `json:"enabled"`
		Host          string `json:"host"`
		Port          int    `json:"port"`
		UseSSL        bool   `json:"use_ssl"`
		BindDN        string `json:"bind_dn"`
		BindPassword  string `json:"bind_password"`
		BaseDN        string `json:"base_dn"`
		UserFilter    string `json:"user_filter"`
		AdminGroup    string `json:"admin_group"`
		SkipTLSVerify bool   `json:"skip_tls_verify"`
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

	if err := saveLDAPConfig(config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 返回更新后的配置（不包含密码）
	response := gin.H{
		"id":             config.ID,
		"enabled":        config.Enabled,
		"host":           config.Host,
		"port":           config.Port,
		"use_ssl":        config.UseSSL,
		"bind_dn":        config.BindDN,
		"base_dn":        config.BaseDN,
		"user_filter":    config.UserFilter,
		"admin_group":    config.AdminGroup,
		"skip_tls_verify": config.SkipTLSVerify,
		"updated_at":     config.UpdatedAt,
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


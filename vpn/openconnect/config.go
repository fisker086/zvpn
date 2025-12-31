package openconnect

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/gin-gonic/gin"
)

// VPNConfigXML VPN配置文件结构（符合 AnyConnect 标准格式，兼容 OpenConnect 和 AnyConnect 客户端）
type VPNConfigXML struct {
	XMLName           xml.Name `xml:"AnyConnectProfile"`
	XMLNS             string   `xml:"xmlns,attr"`
	XMLNSXSI          string   `xml:"xmlns:xsi,attr"`
	XSISchemaLocation string   `xml:"xsi:schemaLocation,attr"`

	ClientInitialization struct {
		UseStartBeforeLogon struct {
			UserControllable bool   `xml:"UserControllable,attr"`
			Value            string `xml:",chardata"`
		} `xml:"UseStartBeforeLogon"`
		StrictCertificateTrust    string `xml:"StrictCertificateTrust"`
		RestrictPreferenceCaching string `xml:"RestrictPreferenceCaching"`
		BypassDownloader          string `xml:"BypassDownloader"`
		AutoUpdate                struct {
			UserControllable bool   `xml:"UserControllable,attr"`
			Value            string `xml:",chardata"`
		} `xml:"AutoUpdate"`
		LocalLanAccess struct {
			UserControllable bool   `xml:"UserControllable,attr"`
			Value            string `xml:",chardata"`
		} `xml:"LocalLanAccess"`
		WindowsVPNEstablishment string `xml:"WindowsVPNEstablishment"`
		LinuxVPNEstablishment   string `xml:"LinuxVPNEstablishment"`
		CertEnrollmentPin       string `xml:"CertEnrollmentPin"`
		CertificateMatch        struct {
			KeyUsage struct {
				MatchKey string `xml:"MatchKey"`
			} `xml:"KeyUsage"`
			ExtendedKeyUsage struct {
				ExtendedMatchKey string `xml:"ExtendedMatchKey"`
			} `xml:"ExtendedKeyUsage"`
		} `xml:"CertificateMatch"`
	} `xml:"ClientInitialization"`

	ServerList struct {
		HostEntry []struct {
			HostName    string `xml:"HostName"`
			HostAddress string `xml:"HostAddress"`
		} `xml:"HostEntry"`
	} `xml:"ServerList"`

	// 添加缺失的配置段
	ServerCertificate struct {
		DoNotValidateCertificate bool `xml:"DoNotValidateCertificate,attr"`
		ValidateCertificateTrust bool `xml:"ValidateCertificateTrust,attr"`
	} `xml:"ServerCertificate"`

	SessionManagement struct {
		SessionTimer struct {
			Timeout       int    `xml:"Timeout"`
			AlertInterval int    `xml:"AlertInterval"`
			Reconnect     string `xml:"Reconnect"`
		} `xml:"SessionTimer"`
		IdleTimeout struct {
			Timeout       int    `xml:"Timeout"`
			AlertInterval int    `xml:"AlertInterval"`
			Reconnect     string `xml:"Reconnect"`
		} `xml:"IdleTimeout"`
	} `xml:"SessionManagement"`

	NativeEnforcement struct {
		ApplicationLauncher struct {
			Enabled bool `xml:"Enabled,attr"`
		} `xml:"ApplicationLauncher"`
	} `xml:"NativeEnforcement"`

	WebSecurity struct {
		Enabled bool `xml:"Enabled,attr"`
	} `xml:"WebSecurity"`
}

// GetProfile 返回VPN配置文件（统一使用 AnyConnect 标准格式，兼容 OpenConnect 和 AnyConnect 客户端）
func (h *Handler) GetProfile(c *gin.Context) {
	_ = h.clientDetector.Detect(c)

	// 创建VPN配置（使用标准 AnyConnect 格式）
	config := VPNConfigXML{
		XMLNS:             "http://schemas.xmlsoap.org/encoding/",
		XMLNSXSI:          "http://www.w3.org/2001/XMLSchema-instance",
		XSISchemaLocation: "http://schemas.xmlsoap.org/encoding/ AnyConnectProfile.xsd",
	}

	// 设置客户端初始化配置
	config.ClientInitialization.UseStartBeforeLogon.UserControllable = false
	config.ClientInitialization.UseStartBeforeLogon.Value = "false"
	config.ClientInitialization.StrictCertificateTrust = "false"
	config.ClientInitialization.RestrictPreferenceCaching = "false"
	config.ClientInitialization.BypassDownloader = "true"
	config.ClientInitialization.AutoUpdate.UserControllable = false
	config.ClientInitialization.AutoUpdate.Value = "false"
	config.ClientInitialization.LocalLanAccess.UserControllable = true
	config.ClientInitialization.LocalLanAccess.Value = "true"
	config.ClientInitialization.WindowsVPNEstablishment = "AllowRemoteUsers"
	config.ClientInitialization.LinuxVPNEstablishment = "AllowRemoteUsers"
	config.ClientInitialization.CertEnrollmentPin = "pinAllowed"
	config.ClientInitialization.CertificateMatch.KeyUsage.MatchKey = "Digital_Signature"
	config.ClientInitialization.CertificateMatch.ExtendedKeyUsage.ExtendedMatchKey = "ClientAuth"

	// 参考 ocserv：根据证书类型设置服务器证书配置（与 GetProfile 保持一致）
	isSelfSigned := h.isSelfSignedCertificateForProfile()
	if isSelfSigned {
		config.ServerCertificate.DoNotValidateCertificate = true
		config.ServerCertificate.ValidateCertificateTrust = false
	} else {
		config.ServerCertificate.DoNotValidateCertificate = false
		config.ServerCertificate.ValidateCertificateTrust = true
	}

	// 设置会话管理配置
	config.SessionManagement.SessionTimer.Timeout = 1209600 // 14天
	config.SessionManagement.SessionTimer.AlertInterval = 60
	config.SessionManagement.SessionTimer.Reconnect = "true"
	config.SessionManagement.IdleTimeout.Timeout = 0 // 禁用空闲超时
	config.SessionManagement.IdleTimeout.AlertInterval = 0
	config.SessionManagement.IdleTimeout.Reconnect = "true"

	// 设置本地强制执行配置
	config.NativeEnforcement.ApplicationLauncher.Enabled = false

	// 设置Web安全配置
	config.WebSecurity.Enabled = false

	// 设置服务器列表
	hostAddress := c.Request.Host
	// 如果端口是443，则不需要在HostAddress中包含端口（443是默认端口）
	hostAddress = strings.Replace(hostAddress, ":443", "", 1)

	// 获取 VPN 配置名称（显示在客户端连接列表中的名称）
	vpnProfileName := h.config.VPN.VPNProfileName
	if vpnProfileName == "" {
		vpnProfileName = "ZVPN" // 默认值
	}

	// 添加服务器条目（支持多个 HostEntry）
	config.ServerList.HostEntry = []struct {
		HostName    string `xml:"HostName"`
		HostAddress string `xml:"HostAddress"`
	}{
		{
			HostName:    vpnProfileName,
			HostAddress: hostAddress,
		},
	}

	// 生成XML
	xmlData, err := xml.MarshalIndent(config, "", "    ")
	if err != nil {
		log.Printf("OpenConnect: Failed to marshal VPN config: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate config"})
		return
	}

	// 添加 XML 声明
	xmlOutput := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" + string(xmlData)

	c.Header("Content-Type", "text/xml; charset=utf-8")
	c.Header("Content-Length", strconv.Itoa(len(xmlOutput)))
	c.Header("Content-Disposition", "attachment; filename=zvpn.xml")
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")
	c.Header("Connection", h.getConnectionHeader(c))

	c.Data(http.StatusOK, "text/xml; charset=utf-8", []byte(xmlOutput))

	if flusher, ok := c.Writer.(http.Flusher); ok {
		flusher.Flush()
	}
}

// getProfileHash 计算 profile.xml 的 SHA1 hash（用于 vpn-profile-manifest）
func (h *Handler) getProfileHash(c *gin.Context) string {
	// 生成与 GetProfile 相同的 XML 内容
	config := VPNConfigXML{
		XMLNS:             "http://schemas.xmlsoap.org/encoding/",
		XMLNSXSI:          "http://www.w3.org/2001/XMLSchema-instance",
		XSISchemaLocation: "http://schemas.xmlsoap.org/encoding/ AnyConnectProfile.xsd",
	}

	// 设置客户端初始化配置（与 GetProfile 相同）
	config.ClientInitialization.UseStartBeforeLogon.UserControllable = false
	config.ClientInitialization.UseStartBeforeLogon.Value = "false"
	config.ClientInitialization.StrictCertificateTrust = "false"
	config.ClientInitialization.RestrictPreferenceCaching = "false"
	config.ClientInitialization.BypassDownloader = "true"
	config.ClientInitialization.AutoUpdate.UserControllable = false
	config.ClientInitialization.AutoUpdate.Value = "false"
	config.ClientInitialization.LocalLanAccess.UserControllable = true
	config.ClientInitialization.LocalLanAccess.Value = "true"
	config.ClientInitialization.WindowsVPNEstablishment = "AllowRemoteUsers"
	config.ClientInitialization.LinuxVPNEstablishment = "AllowRemoteUsers"
	config.ClientInitialization.CertEnrollmentPin = "pinAllowed"
	config.ClientInitialization.CertificateMatch.KeyUsage.MatchKey = "Digital_Signature"
	config.ClientInitialization.CertificateMatch.ExtendedKeyUsage.ExtendedMatchKey = "ClientAuth"

	// 参考 ocserv：根据证书类型设置服务器证书配置
	// 如果是自签名证书，允许客户端不验证证书（通过证书固定接受）
	isSelfSigned := h.isSelfSignedCertificateForProfile()
	if isSelfSigned {
		// 自签名证书：允许客户端不验证证书（通过证书固定接受）
		// 这类似于 ocserv 的行为，允许使用自签名证书
		config.ServerCertificate.DoNotValidateCertificate = true
		config.ServerCertificate.ValidateCertificateTrust = false
		log.Printf("OpenConnect: Self-signed certificate detected in profile.xml (hash calc), allowing certificate pinning (ocserv-style)")
	} else {
		// 受信任的证书：正常验证
		config.ServerCertificate.DoNotValidateCertificate = false
		config.ServerCertificate.ValidateCertificateTrust = true
	}

	// 设置会话管理配置
	config.SessionManagement.SessionTimer.Timeout = 1209600 // 14天
	config.SessionManagement.SessionTimer.AlertInterval = 60
	config.SessionManagement.SessionTimer.Reconnect = "true"
	config.SessionManagement.IdleTimeout.Timeout = 0 // 禁用空闲超时
	config.SessionManagement.IdleTimeout.AlertInterval = 0
	config.SessionManagement.IdleTimeout.Reconnect = "true"

	// 设置本地强制执行配置
	config.NativeEnforcement.ApplicationLauncher.Enabled = false

	// 设置Web安全配置
	config.WebSecurity.Enabled = false

	// 设置服务器列表
	hostAddress := c.Request.Host
	hostAddress = strings.Replace(hostAddress, ":443", "", 1)

	// 获取 VPN 配置名称（显示在客户端连接列表中的名称）
	vpnProfileName := h.config.VPN.VPNProfileName
	if vpnProfileName == "" {
		vpnProfileName = "ZVPN" // 默认值
	}

	config.ServerList.HostEntry = []struct {
		HostName    string `xml:"HostName"`
		HostAddress string `xml:"HostAddress"`
	}{
		{
			HostName:    vpnProfileName,
			HostAddress: hostAddress,
		},
	}

	// 生成XML
	xmlData, err := xml.MarshalIndent(config, "", "    ")
	if err != nil {
		log.Printf("OpenConnect: Failed to marshal VPN config for hash calculation: %v", err)
		return "632a4988b0ee146fd9e43be712edecba2a385ce6" // 返回默认值
	}

	// 添加 XML 声明（与 GetProfile 保持一致）
	xmlOutput := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" + string(xmlData)

	// 计算 SHA1 hash
	hash := sha1.Sum([]byte(xmlOutput))
	return hex.EncodeToString(hash[:])
}

// isSelfSignedCertificateForProfile 检测是否为自签名证书（用于 profile.xml）
func (h *Handler) isSelfSignedCertificateForProfile() bool {
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

// VPNConfig 获取VPN配置信息
func (h *Handler) VPNConfig(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// 从数据库中获取用户信息
	var user models.User
	if err := database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").
		Where("username = ?", username).First(&user).Error; err != nil {
		log.Printf("OpenConnect: 获取用户信息失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user information"})
		return
	}

	// 从用户策略获取DNS服务器
	var dnsServers []string
	if policy := user.GetPolicy(); policy != nil {
		dnsServers = getDNSServers(policy)
	}

	// 返回实际的VPN配置信息
	c.JSON(http.StatusOK, gin.H{
		"ip":       user.VPNIP,
		"dns":      dnsServers,
		"username": user.Username,
	})
}

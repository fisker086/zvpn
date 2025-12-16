package openconnect

import (
	"encoding/xml"
	"log"
	"net/http"

	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/gin-gonic/gin"
)

// VPNConfigXML VPN配置文件结构
type VPNConfigXML struct {
	XMLName      xml.Name `xml:"AnyConnectProfile"`
	Version      string   `xml:"Version,attr"`
	ClientConfig struct {
		ProfileName string `xml:"ProfileName"`
		ServerList  struct {
			HostEntry struct {
				HostName          string `xml:"HostName"`
				HostAddress       string `xml:"HostAddress"`
				UserName          string `xml:"UserName"`
				PrimaryProtocol   string `xml:"PrimaryProtocol"`
				PrimaryPort       int    `xml:"PrimaryPort"`
				SecondaryProtocol string `xml:"SecondaryProtocol,omitempty"`
				SecondaryPort     int    `xml:"SecondaryPort,omitempty"`
			} `xml:"HostEntry"`
		} `xml:"ServerList"`
		NativeClient struct {
			Enabled            bool   `xml:"Enabled,attr"`
			VPNProtocol        string `xml:"VPNProtocol"`
			EnableAutomaticVPN bool   `xml:"EnableAutomaticVPN"`
		} `xml:"NativeClient"`
		Preferences struct {
			AutoReconnect                                                               bool   `xml:"AutoReconnect,attr"`
			AutoReconnectBehavior                                                       string `xml:"AutoReconnectBehavior"`
			AutoReconnectBehaviorData                                                   string `xml:"AutoReconnectBehaviorData"`
			AutoReconnectBehaviorExpiry                                                 string `xml:"AutoReconnectBehaviorExpiry"`
			AutoReconnectBehaviorReport                                                 string `xml:"AutoReconnectBehaviorReport"`
			UserGroupSelection                                                          string `xml:"UserGroupSelection"`
			UserGroupSelectionSaveBeforeConnect                                         string `xml:"UserGroupSelectionSaveBeforeConnect"`
			EnableStartBeforeLogin                                                      bool   `xml:"EnableStartBeforeLogin"`
			StartBeforeLoginConnectVPN                                                  bool   `xml:"StartBeforeLoginConnectVPN"`
			ShowPreconnectMessage                                                       bool   `xml:"ShowPreconnectMessage"`
			PreconnectMessageText                                                       string `xml:"PreconnectMessageText"`
			AutoUpdate                                                                  bool   `xml:"AutoUpdate"`
			AutoUpdatePrompt                                                            bool   `xml:"AutoUpdatePrompt"`
			AutoUpdateBranch                                                            string `xml:"AutoUpdateBranch"`
			AutoUpdateServer                                                            string `xml:"AutoUpdateServer"`
			AutoUpdateServerCertificateCheck                                            bool   `xml:"AutoUpdateServerCertificateCheck"`
			BlockUntrustedServers                                                       bool   `xml:"BlockUntrustedServers"`
			AllowLocalProxyConnections                                                  bool   `xml:"AllowLocalProxyConnections"`
			ProxySettings                                                               string `xml:"ProxySettings"`
			ProxyHost                                                                   string `xml:"ProxyHost"`
			ProxyPort                                                                   int    `xml:"ProxyPort"`
			ProxyAuthRequired                                                           bool   `xml:"ProxyAuthRequired"`
			ProxyUser                                                                   string `xml:"ProxyUser"`
			ProxyPassword                                                               string `xml:"ProxyPassword"`
			CertificateStore                                                            string `xml:"CertificateStore"`
			CertificateStoreOverride                                                    bool   `xml:"CertificateStoreOverride"`
			CertificateStoreName                                                        string `xml:"CertificateStoreName"`
			CertificateStoreNameOverride                                                bool   `xml:"CertificateStoreNameOverride"`
			PrivateKeyStore                                                             string `xml:"PrivateKeyStore"`
			PrivateKeyStoreOverride                                                     bool   `xml:"PrivateKeyStoreOverride"`
			PrivateKeyStoreName                                                         string `xml:"PrivateKeyStoreName"`
			PrivateKeyStoreNameOverride                                                 bool   `xml:"PrivateKeyStoreNameOverride"`
			CertificateSource                                                           string `xml:"CertificateSource"`
			CertificateSourceOverride                                                   bool   `xml:"CertificateSourceOverride"`
			CertificateSourceName                                                       string `xml:"CertificateSourceName"`
			CertificateSourceNameOverride                                               bool   `xml:"CertificateSourceNameOverride"`
			CertificateSelectionMethod                                                  string `xml:"CertificateSelectionMethod"`
			CertificateSelectionMethodOverride                                          bool   `xml:"CertificateSelectionMethodOverride"`
			CertificateSelectionMethodName                                              string `xml:"CertificateSelectionMethodName"`
			CertificateSelectionMethodNameOverride                                      bool   `xml:"CertificateSelectionMethodNameOverride"`
			CertificateValidationMethod                                                 string `xml:"CertificateValidationMethod"`
			CertificateValidationMethodOverride                                         bool   `xml:"CertificateValidationMethodOverride"`
			CertificateValidationMethodName                                             string `xml:"CertificateValidationMethodName"`
			CertificateValidationMethodNameOverride                                     bool   `xml:"CertificateValidationMethodNameOverride"`
			CertificateValidationMethodType                                             string `xml:"CertificateValidationMethodType"`
			CertificateValidationMethodTypeOverride                                     bool   `xml:"CertificateValidationMethodTypeOverride"`
			CertificateValidationMethodTypeName                                         string `xml:"CertificateValidationMethodTypeName"`
			CertificateValidationMethodTypeNameOverride                                 bool   `xml:"CertificateValidationMethodTypeNameOverride"`
			CertificateValidationMethodTypeValue                                        string `xml:"CertificateValidationMethodTypeValue"`
			CertificateValidationMethodTypeValueOverride                                bool   `xml:"CertificateValidationMethodTypeValueOverride"`
			CertificateValidationMethodTypeValueName                                    string `xml:"CertificateValidationMethodTypeValueName"`
			CertificateValidationMethodTypeValueNameOverride                            bool   `xml:"CertificateValidationMethodTypeValueNameOverride"`
			CertificateValidationMethodTypeValueDescription                             string `xml:"CertificateValidationMethodTypeValueDescription"`
			CertificateValidationMethodTypeValueDescriptionOverride                     bool   `xml:"CertificateValidationMethodTypeValueDescriptionOverride"`
			CertificateValidationMethodTypeValueHelp                                    string `xml:"CertificateValidationMethodTypeValueHelp"`
			CertificateValidationMethodTypeValueHelpOverride                            bool   `xml:"CertificateValidationMethodTypeValueHelpOverride"`
			CertificateValidationMethodTypeValueExample                                 string `xml:"CertificateValidationMethodTypeValueExample"`
			CertificateValidationMethodTypeValueExampleOverride                         bool   `xml:"CertificateValidationMethodTypeValueExampleOverride"`
			CertificateValidationMethodTypeValueDefault                                 string `xml:"CertificateValidationMethodTypeValueDefault"`
			CertificateValidationMethodTypeValueDefaultOverride                         bool   `xml:"CertificateValidationMethodTypeValueDefaultOverride"`
			CertificateValidationMethodTypeValueRequired                                bool   `xml:"CertificateValidationMethodTypeValueRequired"`
			CertificateValidationMethodTypeValueRequiredOverride                        bool   `xml:"CertificateValidationMethodTypeValueRequiredOverride"`
			CertificateValidationMethodTypeValueReadOnly                                bool   `xml:"CertificateValidationMethodTypeValueReadOnly"`
			CertificateValidationMethodTypeValueReadOnlyOverride                        bool   `xml:"CertificateValidationMethodTypeValueReadOnlyOverride"`
			CertificateValidationMethodTypeValueHidden                                  bool   `xml:"CertificateValidationMethodTypeValueHidden"`
			CertificateValidationMethodTypeValueHiddenOverride                          bool   `xml:"CertificateValidationMethodTypeValueHiddenOverride"`
			CertificateValidationMethodTypeValueSecure                                  bool   `xml:"CertificateValidationMethodTypeValueSecure"`
			CertificateValidationMethodTypeValueSecureOverride                          bool   `xml:"CertificateValidationMethodTypeValueSecureOverride"`
			CertificateValidationMethodTypeValueMasked                                  bool   `xml:"CertificateValidationMethodTypeValueMasked"`
			CertificateValidationMethodTypeValueMaskedOverride                          bool   `xml:"CertificateValidationMethodTypeValueMaskedOverride"`
			CertificateValidationMethodTypeValueEncrypted                               bool   `xml:"CertificateValidationMethodTypeValueEncrypted"`
			CertificateValidationMethodTypeValueEncryptedOverride                       bool   `xml:"CertificateValidationMethodTypeValueEncryptedOverride"`
			CertificateValidationMethodTypeValueSigned                                  bool   `xml:"CertificateValidationMethodTypeValueSigned"`
			CertificateValidationMethodTypeValueSignedOverride                          bool   `xml:"CertificateValidationMethodTypeValueSignedOverride"`
			CertificateValidationMethodTypeValueVerified                                bool   `xml:"CertificateValidationMethodTypeValueVerified"`
			CertificateValidationMethodTypeValueVerifiedOverride                        bool   `xml:"CertificateValidationMethodTypeValueVerifiedOverride"`
			CertificateValidationMethodTypeValueValidated                               bool   `xml:"CertificateValidationMethodTypeValueValidated"`
			CertificateValidationMethodTypeValueValidatedOverride                       bool   `xml:"CertificateValidationMethodTypeValueValidatedOverride"`
			CertificateValidationMethodTypeValueApproved                                bool   `xml:"CertificateValidationMethodTypeValueApproved"`
			CertificateValidationMethodTypeValueApprovedOverride                        bool   `xml:"CertificateValidationMethodTypeValueApprovedOverride"`
			CertificateValidationMethodTypeValueRevoked                                 bool   `xml:"CertificateValidationMethodTypeValueRevoked"`
			CertificateValidationMethodTypeValueRevokedOverride                         bool   `xml:"CertificateValidationMethodTypeValueRevokedOverride"`
			CertificateValidationMethodTypeValueExpired                                 bool   `xml:"CertificateValidationMethodTypeValueExpired"`
			CertificateValidationMethodTypeValueExpiredOverride                         bool   `xml:"CertificateValidationMethodTypeValueExpiredOverride"`
			CertificateValidationMethodTypeValueNotBefore                               bool   `xml:"CertificateValidationMethodTypeValueNotBefore"`
			CertificateValidationMethodTypeValueNotBeforeOverride                       bool   `xml:"CertificateValidationMethodTypeValueNotBeforeOverride"`
			CertificateValidationMethodTypeValueNotAfter                                bool   `xml:"CertificateValidationMethodTypeValueNotAfter"`
			CertificateValidationMethodTypeValueNotAfterOverride                        bool   `xml:"CertificateValidationMethodTypeValueNotAfterOverride"`
			CertificateValidationMethodTypeValueSubject                                 bool   `xml:"CertificateValidationMethodTypeValueSubject"`
			CertificateValidationMethodTypeValueSubjectOverride                         bool   `xml:"CertificateValidationMethodTypeValueSubjectOverride"`
			CertificateValidationMethodTypeValueIssuer                                  bool   `xml:"CertificateValidationMethodTypeValueIssuer"`
			CertificateValidationMethodTypeValueIssuerOverride                          bool   `xml:"CertificateValidationMethodTypeValueIssuerOverride"`
			CertificateValidationMethodTypeValueSerialNumber                            bool   `xml:"CertificateValidationMethodTypeValueSerialNumber"`
			CertificateValidationMethodTypeValueSerialNumberOverride                    bool   `xml:"CertificateValidationMethodTypeValueSerialNumberOverride"`
			CertificateValidationMethodTypeValueThumbprint                              bool   `xml:"CertificateValidationMethodTypeValueThumbprint"`
			CertificateValidationMethodTypeValueThumbprintOverride                      bool   `xml:"CertificateValidationMethodTypeValueThumbprintOverride"`
			CertificateValidationMethodTypeValueSignatureAlgorithm                      bool   `xml:"CertificateValidationMethodTypeValueSignatureAlgorithm"`
			CertificateValidationMethodTypeValueSignatureAlgorithmOverride              bool   `xml:"CertificateValidationMethodTypeValueSignatureAlgorithmOverride"`
			CertificateValidationMethodTypeValuePublicKeyAlgorithm                      bool   `xml:"CertificateValidationMethodTypeValuePublicKeyAlgorithm"`
			CertificateValidationMethodTypeValuePublicKeyAlgorithmOverride              bool   `xml:"CertificateValidationMethodTypeValuePublicKeyAlgorithmOverride"`
			CertificateValidationMethodTypeValuePublicKeySize                           bool   `xml:"CertificateValidationMethodTypeValuePublicKeySize"`
			CertificateValidationMethodTypeValuePublicKeySizeOverride                   bool   `xml:"CertificateValidationMethodTypeValuePublicKeySizeOverride"`
			CertificateValidationMethodTypeValuePublicKeyExponent                       bool   `xml:"CertificateValidationMethodTypeValuePublicKeyExponent"`
			CertificateValidationMethodTypeValuePublicKeyExponentOverride               bool   `xml:"CertificateValidationMethodTypeValuePublicKeyExponentOverride"`
			CertificateValidationMethodTypeValuePublicKeyModulus                        bool   `xml:"CertificateValidationMethodTypeValuePublicKeyModulus"`
			CertificateValidationMethodTypeValuePublicKeyModulusOverride                bool   `xml:"CertificateValidationMethodTypeValuePublicKeyModulusOverride"`
			CertificateValidationMethodTypeValuePublicKeyExponentSize                   bool   `xml:"CertificateValidationMethodTypeValuePublicKeyExponentSize"`
			CertificateValidationMethodTypeValuePublicKeyExponentSizeOverride           bool   `xml:"CertificateValidationMethodTypeValuePublicKeyExponentSizeOverride"`
			CertificateValidationMethodTypeValuePublicKeyModulusSize                    bool   `xml:"CertificateValidationMethodTypeValuePublicKeyModulusSize"`
			CertificateValidationMethodTypeValuePublicKeyModulusSizeOverride            bool   `xml:"CertificateValidationMethodTypeValuePublicKeyModulusSizeOverride"`
			CertificateValidationMethodTypeValuePublicKeyExponentValue                  bool   `xml:"CertificateValidationMethodTypeValuePublicKeyExponentValue"`
			CertificateValidationMethodTypeValuePublicKeyExponentValueOverride          bool   `xml:"CertificateValidationMethodTypeValuePublicKeyExponentValueOverride"`
			CertificateValidationMethodTypeValuePublicKeyModulusValue                   bool   `xml:"CertificateValidationMethodTypeValuePublicKeyModulusValue"`
			CertificateValidationMethodTypeValuePublicKeyModulusValueOverride           bool   `xml:"CertificateValidationMethodTypeValuePublicKeyModulusValueOverride"`
			CertificateValidationMethodTypeValuePublicKeyExponentSizeValue              bool   `xml:"CertificateValidationMethodTypeValuePublicKeyExponentSizeValue"`
			CertificateValidationMethodTypeValuePublicKeyExponentSizeValueOverride      bool   `xml:"CertificateValidationMethodTypeValuePublicKeyExponentSizeValueOverride"`
			CertificateValidationMethodTypeValuePublicKeyModulusSizeValue               bool   `xml:"CertificateValidationMethodTypeValuePublicKeyModulusSizeValue"`
			CertificateValidationMethodTypeValuePublicKeyModulusSizeValueOverride       bool   `xml:"CertificateValidationMethodTypeValuePublicKeyModulusSizeValueOverride"`
			CertificateValidationMethodTypeValuePublicKeyExponentValueValue             bool   `xml:"CertificateValidationMethodTypeValuePublicKeyExponentValueValue"`
			CertificateValidationMethodTypeValuePublicKeyExponentValueValueOverride     bool   `xml:"CertificateValidationMethodTypeValuePublicKeyExponentValueValueOverride"`
			CertificateValidationMethodTypeValuePublicKeyModulusValueValue              bool   `xml:"CertificateValidationMethodTypeValuePublicKeyModulusValueValue"`
			CertificateValidationMethodTypeValuePublicKeyModulusValueValueOverride      bool   `xml:"CertificateValidationMethodTypeValuePublicKeyModulusValueValueOverride"`
			CertificateValidationMethodTypeValuePublicKeyExponentSizeValueName          bool   `xml:"CertificateValidationMethodTypeValuePublicKeyExponentSizeValueName"`
			CertificateValidationMethodTypeValuePublicKeyExponentSizeValueNameOverride  bool   `xml:"CertificateValidationMethodTypeValuePublicKeyExponentSizeValueNameOverride"`
			CertificateValidationMethodTypeValuePublicKeyModulusSizeValueName           bool   `xml:"CertificateValidationMethodTypeValuePublicKeyModulusSizeValueName"`
			CertificateValidationMethodTypeValuePublicKeyModulusSizeValueNameOverride   bool   `xml:"CertificateValidationMethodTypeValuePublicKeyModulusSizeValueNameOverride"`
			CertificateValidationMethodTypeValuePublicKeyExponentValueValueName         bool   `xml:"CertificateValidationMethodTypeValuePublicKeyExponentValueValueName"`
			CertificateValidationMethodTypeValuePublicKeyExponentValueValueNameOverride bool   `xml:"CertificateValidationMethodTypeValuePublicKeyExponentValueValueNameOverride"`
			CertificateValidationMethodTypeValuePublicKeyModulusValueValueName          bool   `xml:"CertificateValidationMethodTypeValuePublicKeyModulusValueValueName"`
			CertificateValidationMethodTypeValuePublicKeyModulusValueValueNameOverride  bool   `xml:"CertificateValidationMethodTypeValuePublicKeyModulusValueValueNameOverride"`
		}
	}
}

// GetProfile 返回VPN配置文件
func (h *Handler) GetProfile(c *gin.Context) {
	// 创建VPN配置
	config := VPNConfigXML{
		Version: "1.0.0",
	}
	config.ClientConfig.ProfileName = "ZVPN"
	config.ClientConfig.ServerList.HostEntry.HostName = "zvpn"
	config.ClientConfig.ServerList.HostEntry.HostAddress = c.Request.Host
	config.ClientConfig.ServerList.HostEntry.PrimaryProtocol = "https"
	config.ClientConfig.ServerList.HostEntry.PrimaryPort = 443
	config.ClientConfig.NativeClient.Enabled = true
	config.ClientConfig.NativeClient.VPNProtocol = "anyconnect"
	config.ClientConfig.NativeClient.EnableAutomaticVPN = false

	// 设置偏好
	config.ClientConfig.Preferences.AutoReconnect = true
	config.ClientConfig.Preferences.AutoReconnectBehavior = "disconnect"
	config.ClientConfig.Preferences.UserGroupSelection = "false"
	config.ClientConfig.Preferences.EnableStartBeforeLogin = false
	config.ClientConfig.Preferences.StartBeforeLoginConnectVPN = false
	config.ClientConfig.Preferences.ShowPreconnectMessage = false
	config.ClientConfig.Preferences.AutoUpdate = false
	config.ClientConfig.Preferences.BlockUntrustedServers = false
	config.ClientConfig.Preferences.AllowLocalProxyConnections = true
	config.ClientConfig.Preferences.ProxySettings = "none"

	// 生成XML
	xmlData, err := xml.MarshalIndent(config, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal VPN config: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate config"})
		return
	}

	// 设置响应头
	c.Header("Content-Type", "application/xml")
	c.Header("Content-Disposition", "attachment; filename=zvpn.xml")
	c.String(http.StatusOK, string(xmlData))
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

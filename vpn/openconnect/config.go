package openconnect

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/handlers"
	"github.com/fisker/zvpn/models"
	"github.com/gin-gonic/gin"
)

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
		RestrictTunnelProtocols   string `xml:"RestrictTunnelProtocols,omitempty"`
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
}

func (h *Handler) generateProfileXML(c *gin.Context) (string, error) {

	config := VPNConfigXML{
		XMLNS:             "http://schemas.xmlsoap.org/encoding/",
		XMLNSXSI:          "http://www.w3.org/2001/XMLSchema-instance",
		XSISchemaLocation: "http://schemas.xmlsoap.org/encoding/ AnyConnectProfile.xsd",
	}

	config.ClientInitialization.UseStartBeforeLogon.UserControllable = false
	config.ClientInitialization.UseStartBeforeLogon.Value = "false"
	config.ClientInitialization.StrictCertificateTrust = "false"
	config.ClientInitialization.RestrictPreferenceCaching = "false"

	config.ClientInitialization.RestrictTunnelProtocols = "SSL,IPSec"
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

	hostAddress := c.Request.Host

	if !strings.Contains(hostAddress, ":") {
		port := h.config.VPN.OpenConnectPort
		if port == "" {
			port = "443"
		}
		hostAddress = hostAddress + ":" + port
	}

	vpnProfileName := handlers.GetVPNProfileName()

	config.ServerList.HostEntry = []struct {
		HostName    string `xml:"HostName"`
		HostAddress string `xml:"HostAddress"`
	}{
		{
			HostName:    vpnProfileName,
			HostAddress: hostAddress,
		},
	}

	xmlData, err := xml.MarshalIndent(config, "", "    ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal VPN config: %w", err)
	}

	xmlStr := string(xmlData)
	if strings.Contains(xmlStr, "xmlns=\"&lt;") || strings.Contains(xmlStr, "xmlns=\"<") {
	}

	xmlOutput := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" + xmlStr

	return xmlOutput, nil
}

func (h *Handler) GetProfile(c *gin.Context) {

	xmlOutput, err := h.generateProfileXML(c)
	if err != nil {
		log.Printf("OpenConnect: Failed to generate profile XML: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate config"})
		return
	}

	c.Writer.Header().Del("Server")
	c.Writer.Header().Del("X-Powered-By")
	c.Header("X-CSTP-Version", "1")
	c.Header("X-Transcend-Version", "1")
	c.Header("X-Aggregate-Auth", "1")
	c.Header("Content-Type", "text/xml; charset=utf-8")
	c.Header("Content-Length", strconv.Itoa(len(xmlOutput)))
	c.Header("Cache-Control", "no-store,no-cache")
	c.Header("Pragma", "no-cache")
	c.Header("Connection", "keep-alive")

	c.Data(http.StatusOK, "text/xml; charset=utf-8", []byte(xmlOutput))

	if flusher, ok := c.Writer.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (h *Handler) getProfileHash(c *gin.Context) string {

	xmlOutput, err := h.generateProfileXML(c)
	if err != nil {
		log.Printf("OpenConnect: Failed to generate profile XML for hash calculation: %v", err)
		return "632a4988b0ee146fd9e43be712edecba2a385ce6"
	}

	hash := sha1.Sum([]byte(xmlOutput))
	hashStr := hex.EncodeToString(hash[:])

	return hashStr
}

func (h *Handler) VPNConfig(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var user models.User
	if err := database.DB.Preload("Groups").Preload("Groups.Policies").Preload("Groups.Policies.Routes").
		Where("username = ?", username).First(&user).Error; err != nil {
		log.Printf("OpenConnect: 获取用户信息失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user information"})
		return
	}

	var dnsServers []string
	if policy := user.GetPolicy(); policy != nil {
		dnsServers = getDNSServers(policy)
	}

	c.JSON(http.StatusOK, gin.H{
		"ip":       user.VPNIP,
		"dns":      dnsServers,
		"username": user.Username,
	})
}

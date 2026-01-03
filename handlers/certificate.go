package handlers

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type CertificateManager interface {
	AddSNICert(sni string, certFile, keyFile string) error
	AddSNICertFromBytes(sni string, certBytes, keyBytes []byte) error
	RemoveSNICert(sni string) error
	GetSNICerts() map[string]CertInfo
	GetDefaultCert() *CertInfo
	UpdateDefaultCert(certFile, keyFile string) error
	UpdateDefaultCertFromBytes(certBytes, keyBytes []byte) error
	UpdateDefaultCertFromBytesAndSave(certBytes, keyBytes []byte) error // 保存到配置文件路径（参考 anylink）
}

type CertInfo struct {
	SNI           string    `json:"sni"`            // SNI 域名
	CommonName    string    `json:"common_name"`    // 证书 CN
	DNSNames      []string  `json:"dns_names"`      // DNS 名称列表
	Issuer        string    `json:"issuer"`         // 颁发者
	NotBefore     time.Time `json:"not_before"`     // 有效期开始
	NotAfter      time.Time `json:"not_after"`      // 有效期结束
	DaysRemaining int       `json:"days_remaining"` // 剩余天数
	IsExpired     bool      `json:"is_expired"`     // 是否过期
	IsDefault     bool      `json:"is_default"`     // 是否为默认证书
}

type CertificateHandler struct {
	certManager CertificateManager
}

func NewCertificateHandler() *CertificateHandler {
	return &CertificateHandler{}
}

func (h *CertificateHandler) SetCertificateManager(cm CertificateManager) {
	h.certManager = cm
}

func (h *CertificateHandler) ListCertificates(c *gin.Context) {
	if h.certManager == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Certificate manager not available"})
		return
	}

	sniCerts := h.certManager.GetSNICerts()

	defaultCert := h.certManager.GetDefaultCert()

	response := gin.H{
		"default_cert": defaultCert,
		"sni_certs":    sniCerts,
		"total":        len(sniCerts),
	}

	c.JSON(http.StatusOK, response)
}

func (h *CertificateHandler) AddSNICertificate(c *gin.Context) {
	if h.certManager == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Certificate manager not available"})
		return
	}

	contentType := c.GetHeader("Content-Type")

	if strings.HasPrefix(contentType, "multipart/form-data") {
		certFile, err := c.FormFile("cert")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cert file is required: " + err.Error()})
			return
		}

		keyFile, err := c.FormFile("key")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "key file is required: " + err.Error()})
			return
		}

		certF, err := certFile.Open()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to open cert file: " + err.Error()})
			return
		}
		defer certF.Close()

		keyF, err := keyFile.Open()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to open key file: " + err.Error()})
			return
		}
		defer keyF.Close()

		certBytes := make([]byte, certFile.Size)
		keyBytes := make([]byte, keyFile.Size)

		if _, err := certF.Read(certBytes); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read cert file: " + err.Error()})
			return
		}

		if _, err := keyF.Read(keyBytes); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read key file: " + err.Error()})
			return
		}

		sni := c.PostForm("sni")
		if sni == "" {
			certBlock, _ := pem.Decode(certBytes)
			if certBlock != nil {
				cert, err := x509.ParseCertificate(certBlock.Bytes)
				if err == nil && cert.Subject.CommonName != "" {
					sni = cert.Subject.CommonName
				} else if len(cert.DNSNames) > 0 {
					sni = cert.DNSNames[0]
				}
			}
		}

		if sni == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "SNI is required or certificate must have CN/DNS Names"})
			return
		}

		certBlock, _ := pem.Decode(certBytes)
		if certBlock == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate PEM format"})
			return
		}

		_, err = x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate format: " + err.Error()})
			return
		}

		err = h.certManager.AddSNICertFromBytes(sni, certBytes, keyBytes)
		if err != nil {
			log.Printf("Failed to add SNI certificate: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Certificate added successfully",
			"sni":     sni,
		})
		return
	}

	var req struct {
		SNI      string `json:"sni" binding:"required"`
		CertFile string `json:"cert_file,omitempty"` // 文件路径（可选）
		KeyFile  string `json:"key_file,omitempty"`  // 文件路径（可选）
		CertData string `json:"cert_data,omitempty"` // 证书内容（PEM格式）
		KeyData  string `json:"key_data,omitempty"`  // 私钥内容（PEM格式）
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.SNI = strings.TrimSpace(req.SNI)
	if req.SNI == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SNI cannot be empty"})
		return
	}

	var err error

	if req.CertFile != "" && req.KeyFile != "" {
		err = h.certManager.AddSNICert(req.SNI, req.CertFile, req.KeyFile)
	} else if req.CertData != "" && req.KeyData != "" {
		certBlock, _ := pem.Decode([]byte(req.CertData))
		if certBlock == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate PEM format"})
			return
		}

		keyBlock, _ := pem.Decode([]byte(req.KeyData))
		if keyBlock == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid key PEM format"})
			return
		}

		_, err = x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate format: " + err.Error()})
			return
		}

		err = h.certManager.AddSNICertFromBytes(req.SNI, []byte(req.CertData), []byte(req.KeyData))
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Either cert_file/key_file or cert_data/key_data must be provided"})
		return
	}

	if err != nil {
		log.Printf("Failed to add SNI certificate: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Certificate added successfully",
		"sni":     req.SNI,
	})
}

func (h *CertificateHandler) RemoveSNICertificate(c *gin.Context) {
	if h.certManager == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Certificate manager not available"})
		return
	}

	sni := c.Param("sni")
	if sni == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "SNI parameter is required"})
		return
	}

	err := h.certManager.RemoveSNICert(sni)
	if err != nil {
		log.Printf("Failed to remove SNI certificate: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Certificate removed successfully",
		"sni":     sni,
	})
}

func (h *CertificateHandler) UpdateDefaultCertificate(c *gin.Context) {
	if h.certManager == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Certificate manager not available"})
		return
	}

	contentType := c.GetHeader("Content-Type")

	if strings.HasPrefix(contentType, "multipart/form-data") {
		certFile, err := c.FormFile("cert")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cert file is required: " + err.Error()})
			return
		}

		keyFile, err := c.FormFile("key")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "key file is required: " + err.Error()})
			return
		}

		certF, err := certFile.Open()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to open cert file: " + err.Error()})
			return
		}
		defer certF.Close()

		keyF, err := keyFile.Open()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to open key file: " + err.Error()})
			return
		}
		defer keyF.Close()

		certBytes := make([]byte, certFile.Size)
		keyBytes := make([]byte, keyFile.Size)

		if _, err := certF.Read(certBytes); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read cert file: " + err.Error()})
			return
		}

		if _, err := keyF.Read(keyBytes); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read key file: " + err.Error()})
			return
		}

		certBlock, _ := pem.Decode(certBytes)
		if certBlock == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate PEM format"})
			return
		}

		_, err = x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate format: " + err.Error()})
			return
		}

		err = h.certManager.UpdateDefaultCertFromBytesAndSave(certBytes, keyBytes)
		if err != nil {
			log.Printf("Failed to update default certificate: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "Default certificate updated successfully and saved to config file path",
		})
		return
	}

	var req struct {
		CertFile string `json:"cert_file,omitempty"` // 文件路径（可选）
		KeyFile  string `json:"key_file,omitempty"`  // 文件路径（可选）
		CertData string `json:"cert_data,omitempty"` // 证书内容（PEM格式）
		KeyData  string `json:"key_data,omitempty"`  // 私钥内容（PEM格式）
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var err error

	if req.CertFile != "" && req.KeyFile != "" {
		err = h.certManager.UpdateDefaultCert(req.CertFile, req.KeyFile)
	} else if req.CertData != "" && req.KeyData != "" {
		certBlock, _ := pem.Decode([]byte(req.CertData))
		if certBlock == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate PEM format"})
			return
		}

		keyBlock, _ := pem.Decode([]byte(req.KeyData))
		if keyBlock == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid key PEM format"})
			return
		}

		_, err = x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid certificate format: " + err.Error()})
			return
		}

		err = h.certManager.UpdateDefaultCertFromBytes([]byte(req.CertData), []byte(req.KeyData))
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Either cert_file/key_file or cert_data/key_data must be provided"})
		return
	}

	if err != nil {
		log.Printf("Failed to update default certificate: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Default certificate updated successfully",
	})
}


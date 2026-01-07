package openconnect

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"log"
	"os"
	"strings"

	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
)

type ServerCertInfo struct {
	SHA1Hash     string
	SHA256Hash   string
	IsSelfSigned bool
}

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

	sha256Hash := h.getServerCertSHA256Hash()
	if sha256Hash != "" {
		info.SHA256Hash = sha256Hash
	}

	info.IsSelfSigned = h.isSelfSignedCertificate()

	return info
}

func (h *Handler) getServerCertHash() string {
	cert, err := h.getDefaultCertificate()
	if err != nil {
		log.Printf("OpenConnect: Failed to get default certificate: %v", err)
		return ""
	}
	if cert == nil {
		return ""
	}

	issuer := cert.Issuer.String()
	isDevCert := strings.Contains(issuer, "mkcert") ||
		strings.Contains(issuer, "development") ||
		strings.Contains(issuer, "self-signed") ||
		cert.Issuer.String() == cert.Subject.String()

	if isDevCert {
		log.Printf("OpenConnect: WARNING - This appears to be a development/self-signed certificate")
		log.Printf("OpenConnect: AnyConnect clients may show certificate verification warnings")
		log.Printf("OpenConnect: For production use, please use a certificate from a trusted CA (e.g., Let's Encrypt)")
	}

	hash := sha1.Sum(cert.Raw)
	hashStr := strings.ToUpper(hex.EncodeToString(hash[:]))

	sha256Hash := sha256.Sum256(cert.Raw)
	sha256HashStr := base64.StdEncoding.EncodeToString(sha256Hash[:])

	log.Printf("OpenConnect: Server certificate SHA1 hash: %s", hashStr)
	if isDevCert {
		log.Printf("OpenConnect: For OpenConnect clients with self-signed cert, use: --servercert=pin-sha256:%s", sha256HashStr)
		log.Printf("OpenConnect: Or install the CA certificate (mkcert -install) on the client machine")
	}
	return hashStr
}

func (h *Handler) getServerCertSHA256Hash() string {
	cert, err := h.getDefaultCertificate()
	if err != nil {
		return ""
	}
	if cert == nil {
		return ""
	}

	sha256Hash := sha256.Sum256(cert.Raw)
	return base64.StdEncoding.EncodeToString(sha256Hash[:])
}

func (h *Handler) isSelfSignedCertificate() bool {
	cert, err := h.getDefaultCertificate()
	if err != nil {
		return false
	}
	if cert == nil {
		return false
	}

	issuer := cert.Issuer.String()
	subject := cert.Subject.String()

	isSelfSigned := issuer == subject ||
		strings.Contains(issuer, "mkcert") ||
		strings.Contains(issuer, "development") ||
		strings.Contains(issuer, "self-signed") ||
		strings.Contains(strings.ToLower(issuer), "ca")

	return isSelfSigned
}

func (h *Handler) getDefaultCertificate() (*x509.Certificate, error) {
	var certRecord models.Certificate
	err := database.DB.Where("(sni = ? OR sni = ?) AND is_active = ?", "", "default", true).First(&certRecord).Error
	if err == nil && len(certRecord.CertData) > 0 {
		block, _ := pem.Decode(certRecord.CertData)
		if block != nil {
			cert, parseErr := x509.ParseCertificate(block.Bytes)
			if parseErr == nil {
				return cert, nil
			}
		}
	}

	certFile := h.config.VPN.CertFile
	if certFile == "" {
		certFile = "./certs/server.crt"
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

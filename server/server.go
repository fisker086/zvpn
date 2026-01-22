package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/handlers"
	"github.com/fisker/zvpn/middleware"
	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/routes"
	"github.com/fisker/zvpn/vpn"
	"github.com/fisker/zvpn/vpn/openconnect"
	"github.com/fisker/zvpn/vpn/policy"
	"github.com/gin-gonic/gin"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"gorm.io/gorm"
)

type tlsErrorLogger struct {
	normalErrors map[string]bool // 正常错误列表（不需要记录）
}

func (l *tlsErrorLogger) Write(p []byte) (n int, err error) {
	msg := string(p)
	msgLower := strings.ToLower(msg)

	isNormalError := false
	for normalErr := range l.normalErrors {
		if strings.Contains(msgLower, strings.ToLower(normalErr)) {
			isNormalError = true
			break
		}
	}

	if isNormalError {
		return len(p), nil
	}

	log.Printf("TLS: ⚠️  ERROR - %s", strings.TrimSpace(msg))

	if strings.Contains(msgLower, "handshake") {
		log.Printf("TLS: Error occurred during TLS handshake - this may indicate:")
		log.Printf("TLS:   1. Client certificate validation failure")
		log.Printf("TLS:   2. Cipher suite mismatch")
		log.Printf("TLS:   3. Protocol version incompatibility")
		log.Printf("TLS:   4. Certificate chain validation issue")
		log.Printf("TLS:   5. Network connectivity problem")
	} else if strings.Contains(msgLower, "certificate") {
		log.Printf("TLS: Certificate-related error detected")
	} else if strings.Contains(msgLower, "timeout") {
		log.Printf("TLS: Timeout error detected - connection may be slow or network unstable")
	}

	return len(p), nil
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

type certManager struct {
	certs       map[string]*tls.Certificate // SNI 域名 -> 证书（包含 "default" 键）
	defaultCert *tls.Certificate            // 默认证书（向后兼容，优先使用 certs["default"]）
	tempCert    *tls.Certificate            // 临时证书（localhost，最后的备选方案，参考 ）
	mu          sync.RWMutex                // 保护并发访问
}

func newCertManager() *certManager {
	tempCert, err := selfsign.GenerateSelfSignedWithDNS("localhost")
	if err != nil {
		log.Printf("WARNING: Failed to generate temporary certificate: %v", err)
		return &certManager{
			certs:    make(map[string]*tls.Certificate),
			tempCert: nil,
		}
	}
	return &certManager{
		certs:    make(map[string]*tls.Certificate),
		tempCert: &tempCert,
	}
}

func filterRootCertificate(cert *tls.Certificate) {
	if len(cert.Certificate) <= 1 {
		return // 只有一个证书，不需要过滤
	}

	originalLength := len(cert.Certificate)

	for len(cert.Certificate) > 1 {
		lastIdx := len(cert.Certificate) - 1
		lastCert, err := x509.ParseCertificate(cert.Certificate[lastIdx])
		if err != nil {
			break // 解析失败，停止处理
		}

		if lastCert.Issuer.String() == lastCert.Subject.String() {
			log.Printf("Certificate Manager: Filtering out root certificate (self-signed) - CN: %s, Issuer: %s",
				lastCert.Subject.CommonName, lastCert.Issuer.CommonName)
			cert.Certificate = cert.Certificate[:lastIdx]
		} else {
			break // 不是根证书，停止处理
		}
	}

	if len(cert.Certificate) < originalLength {
		log.Printf("Certificate Manager: Certificate chain filtered - Original: %d certs, After filtering: %d certs",
			originalLength, len(cert.Certificate))
	}

	if len(cert.Certificate) > 1 {
		serverCert, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil {
			intermediateCert, err := x509.ParseCertificate(cert.Certificate[1])
			if err == nil {
				if serverCert.Issuer.String() != intermediateCert.Subject.String() {
					log.Printf("Certificate Manager: ⚠️  WARNING - Certificate chain order may be incorrect!")
					log.Printf("Certificate Manager: ⚠️  Server cert issuer (%s) != Intermediate cert subject (%s)",
						serverCert.Issuer.String(), intermediateCert.Subject.String())
				}
			}
		}
	}
}

func (cm *certManager) LoadDefaultCert(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load default certificate: %w", err)
	}

	filterRootCertificate(&cert)

	if cert.Leaf == nil {
		if len(cert.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err == nil {
				cert.Leaf = leaf
			}
		}
	}

	cm.mu.Lock()
	cm.defaultCert = &cert
	cm.mu.Unlock()

	if len(cert.Certificate) < 1 {
		return fmt.Errorf("certificate chain is empty")
	}

	cm.LoadCertificate(&cert)

	log.Printf("Certificate Manager: Certificate chain loaded - Server cert: %d bytes, Chain length: %d",
		len(cert.Certificate[0]), len(cert.Certificate))

	totalSize := 0
	for i, certBytes := range cert.Certificate {
		totalSize += len(certBytes)
		if i > 0 {
			log.Printf("Certificate Manager: Chain cert #%d: %d bytes", i+1, len(certBytes))
		}
	}
	log.Printf("Certificate Manager: Total certificate chain size: %d bytes", totalSize)

	if len(cert.Certificate) > 1 {
		if cert.Leaf != nil {
			log.Printf("Certificate Manager: Server cert CN: %s, Issuer: %s",
				cert.Leaf.Subject.CommonName, cert.Leaf.Issuer.CommonName)

			if len(cert.Certificate) > 1 {
				intermediateCert, err := x509.ParseCertificate(cert.Certificate[1])
				if err == nil {
					log.Printf("Certificate Manager: Intermediate cert CN: %s, Issuer: %s",
						intermediateCert.Subject.CommonName, intermediateCert.Issuer.CommonName)

					if cert.Leaf.Issuer.String() != intermediateCert.Subject.String() {
						log.Printf("Certificate Manager: ⚠️  WARNING - Certificate chain order may be incorrect!")
						log.Printf("Certificate Manager: ⚠️  Server cert issuer (%s) != Intermediate cert subject (%s)",
							cert.Leaf.Issuer.String(), intermediateCert.Subject.String())
						log.Printf("Certificate Manager: ⚠️  Certificate order should be: server cert first, then intermediate cert")
					} else {
						log.Printf("Certificate Manager: ✓ Certificate chain order is correct")
					}

					if intermediateCert.Issuer.String() == intermediateCert.Subject.String() {
						log.Printf("Certificate Manager: ⚠️  WARNING - Intermediate cert appears to be self-signed (root cert)!")
					}
				}
			}
		}
	} else {
		log.Printf("Certificate Manager: ⚠️  WARNING - Certificate chain is incomplete (only server cert, no intermediate cert)")
		log.Printf("Certificate Manager: ⚠️  This may cause TLS handshake failures. Please ensure certificate file contains full chain.")
	}

	log.Printf("Certificate Manager: Loaded default certificate from %s, %s", certFile, keyFile)
	log.Printf("Certificate Manager: Certificate chain contains %d certificate(s)", len(cert.Certificate))
	if cert.Leaf != nil {
		log.Printf("Certificate Manager: Server cert CN: %s", cert.Leaf.Subject.CommonName)
		log.Printf("Certificate Manager: Certificate DNS Names: %v", cert.Leaf.DNSNames)

		now := time.Now()
		daysUntilExpiry := int(cert.Leaf.NotAfter.Sub(now).Hours() / 24)
		log.Printf("Certificate Manager: Certificate valid until: %s (%d days remaining)",
			cert.Leaf.NotAfter.Format("2006-01-02 15:04:05"), daysUntilExpiry)

		if daysUntilExpiry < 0 {
			log.Printf("Certificate Manager: ⚠️  FATAL - Certificate has EXPIRED! TLS connections will fail.")
		} else if daysUntilExpiry <= 7 {
			log.Printf("Certificate Manager: ⚠️  WARNING - Certificate expires in %d days - renew immediately!", daysUntilExpiry)
		} else if daysUntilExpiry <= 30 {
			log.Printf("Certificate Manager: ⚠️  WARNING - Certificate expires in %d days - plan renewal soon", daysUntilExpiry)
		}
	}

	return nil
}

func (cm *certManager) AddCert(sni string, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate for SNI %s: %w", sni, err)
	}

	filterRootCertificate(&cert)

	if cert.Leaf == nil {
		if len(cert.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err == nil {
				cert.Leaf = leaf
			}
		}
	}

	cm.mu.Lock()
	cm.certs[strings.ToLower(sni)] = &cert
	cm.mu.Unlock()

	log.Printf("Certificate Manager: Added certificate for SNI '%s' from %s, %s", sni, certFile, keyFile)
	if cert.Leaf != nil {
		log.Printf("Certificate Manager: SNI '%s' cert CN: %s, DNS Names: %v", sni, cert.Leaf.Subject.CommonName, cert.Leaf.DNSNames)
	}

	cm.LoadCertificate(&cert)

	return nil
}

func (cm *certManager) AddCertFromBytes(sni string, certBytes, keyBytes []byte) error {
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return fmt.Errorf("failed to load certificate from bytes for SNI %s: %w", sni, err)
	}

	filterRootCertificate(&cert)

	if cert.Leaf == nil {
		if len(cert.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err == nil {
				cert.Leaf = leaf
			}
		}
	}

	if err := cm.saveCertToDB(sni, certBytes, keyBytes, &cert); err != nil {
		log.Printf("WARNING: Failed to save certificate to database: %v", err)
	}

	cm.mu.Lock()
	cm.certs[strings.ToLower(sni)] = &cert
	cm.mu.Unlock()

	log.Printf("Certificate Manager: Added certificate for SNI '%s' from bytes", sni)
	if cert.Leaf != nil {
		log.Printf("Certificate Manager: SNI '%s' cert CN: %s, DNS Names: %v", sni, cert.Leaf.Subject.CommonName, cert.Leaf.DNSNames)
	}

	cm.LoadCertificate(&cert)

	return nil
}

func (cm *certManager) RemoveCert(sni string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	sniLower := strings.ToLower(sni)
	if _, exists := cm.certs[sniLower]; !exists {
		return fmt.Errorf("certificate for SNI '%s' not found", sni)
	}

	if err := database.DB.Where("sni = ?", sniLower).Delete(&models.Certificate{}).Error; err != nil {
		log.Printf("WARNING: Failed to delete certificate from database: %v", err)
	}

	delete(cm.certs, sniLower)
	log.Printf("Certificate Manager: Removed certificate for SNI '%s'", sni)
	return nil
}

func (cm *certManager) saveCertToDB(sni string, certBytes, keyBytes []byte, cert *tls.Certificate) error {
	sniLower := strings.ToLower(sni)

	certRecord := &models.Certificate{
		SNI:      sniLower,
		CertData: certBytes,
		KeyData:  keyBytes,
		IsActive: true,
	}

	if cert.Leaf != nil {
		dnsNamesBytes, _ := json.Marshal(cert.Leaf.DNSNames)
		certRecord.CommonName = cert.Leaf.Subject.CommonName
		certRecord.DNSNames = string(dnsNamesBytes)
		certRecord.Issuer = cert.Leaf.Issuer.CommonName
		certRecord.NotBefore = cert.Leaf.NotBefore
		certRecord.NotAfter = cert.Leaf.NotAfter
	}

	return database.DB.Where("sni = ?", sniLower).Assign(certRecord).FirstOrCreate(certRecord).Error
}

func (cm *certManager) loadCertsFromDB() error {
	var certs []models.Certificate
	if err := database.DB.Where("is_active = ?", true).Find(&certs).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil // 没有证书，不算错误
		}
		return fmt.Errorf("failed to load certificates from database: %w", err)
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	for _, certRecord := range certs {
		cert, err := tls.X509KeyPair(certRecord.CertData, certRecord.KeyData)
		if err != nil {
			log.Printf("WARNING: Failed to load certificate for SNI '%s' from database: %v", certRecord.SNI, err)
			continue
		}

		if cert.Leaf == nil && len(cert.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err == nil {
				cert.Leaf = leaf
			}
		}

		sniLower := strings.ToLower(certRecord.SNI)
		cm.certs[sniLower] = &cert

		cm.buildNameToCertificateUnlocked(&cert)

		log.Printf("Certificate Manager: Loaded SNI certificate '%s' from database", certRecord.SNI)
	}

	log.Printf("Certificate Manager: Loaded %d SNI certificates from database", len(certs))
	return nil
}

func (cm *certManager) GetCerts() map[string]certInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	result := make(map[string]certInfo)
	for sni, cert := range cm.certs {
		if cert.Leaf != nil {
			info := cm.certToInfo(sni, cert, false)
			result[sni] = info
		}
	}
	return result
}

func (cm *certManager) GetDefaultCertInfo() *certInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.defaultCert == nil || cm.defaultCert.Leaf == nil {
		return nil
	}

	info := cm.certToInfo("", cm.defaultCert, true)
	return &info
}

func (cm *certManager) LoadDefaultCertFromBytes(certBytes, keyBytes []byte) error {
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return fmt.Errorf("failed to load default certificate from bytes: %w", err)
	}

	if cert.Leaf == nil {
		if len(cert.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err == nil {
				cert.Leaf = leaf
			}
		}
	}

	cm.mu.Lock()
	cm.defaultCert = &cert
	cm.mu.Unlock()

	log.Printf("Certificate Manager: Loaded default certificate from bytes")
	if cert.Leaf != nil {
		log.Printf("Certificate Manager: Default cert CN: %s, DNS Names: %v", cert.Leaf.Subject.CommonName, cert.Leaf.DNSNames)
	}

	cm.LoadCertificate(&cert)

	return nil
}

type certInfo struct {
	SNI           string
	CommonName    string
	DNSNames      []string
	Issuer        string
	NotBefore     time.Time
	NotAfter      time.Time
	DaysRemaining int
	IsExpired     bool
	IsDefault     bool
}

func (cm *certManager) certToInfo(sni string, cert *tls.Certificate, isDefault bool) certInfo {
	info := certInfo{
		SNI:       sni,
		IsDefault: isDefault,
	}

	if cert.Leaf != nil {
		info.CommonName = cert.Leaf.Subject.CommonName
		info.DNSNames = cert.Leaf.DNSNames
		info.Issuer = cert.Leaf.Issuer.CommonName
		info.NotBefore = cert.Leaf.NotBefore
		info.NotAfter = cert.Leaf.NotAfter

		now := time.Now()
		daysRemaining := int(cert.Leaf.NotAfter.Sub(now).Hours() / 24)
		info.DaysRemaining = daysRemaining
		info.IsExpired = daysRemaining < 0
	}

	return info
}

func (cm *certManager) LoadCertificate(cert *tls.Certificate) {
	cm.buildNameToCertificate(cert)
}

func (cm *certManager) buildNameToCertificate(cert *tls.Certificate) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.buildNameToCertificateUnlocked(cert)
}

func (cm *certManager) buildNameToCertificateUnlocked(cert *tls.Certificate) {
	if cert.Leaf == nil {
		if len(cert.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err == nil {
				cert.Leaf = leaf
			}
		}
	}

	if cert.Leaf == nil {
		return
	}

	x509Cert := cert.Leaf
	startTime := x509Cert.NotBefore.String()
	expiredTime := x509Cert.NotAfter.String()

	cm.certs["default"] = cert

	if x509Cert.Subject.CommonName != "" && len(x509Cert.DNSNames) == 0 {
		commonName := strings.ToLower(x509Cert.Subject.CommonName)
		log.Printf("┏ Load Certificate: %s", commonName)
		log.Printf("┠╌╌ Start Time:     %s", startTime)
		log.Printf("┖╌╌ Expired Time:   %s", expiredTime)
		cm.certs[commonName] = cert
	}

	for _, san := range x509Cert.DNSNames {
		sanLower := strings.ToLower(san)
		log.Printf("┏ Load Certificate: %s", sanLower)
		log.Printf("┠╌╌ Start Time:     %s", startTime)
		log.Printf("┖╌╌ Expired Time:   %s", expiredTime)
		cm.certs[sanLower] = cert
	}
}

func matchDomain(domain string, cert *tls.Certificate) bool {
	if cert == nil || cert.Leaf == nil {
		return false
	}

	domain = strings.ToLower(domain)

	if cert.Leaf.Subject.CommonName != "" {
		cn := strings.ToLower(cert.Leaf.Subject.CommonName)
		if cn == domain {
			return true
		}
		if strings.HasPrefix(cn, "*.") {
			wildcardDomain := cn[2:]
			if strings.HasSuffix(domain, "."+wildcardDomain) || domain == wildcardDomain {
				return true
			}
		}
	}

	for _, dnsName := range cert.Leaf.DNSNames {
		dnsNameLower := strings.ToLower(dnsName)
		if dnsNameLower == domain {
			return true
		}
		if strings.HasPrefix(dnsNameLower, "*.") {
			wildcardDomain := dnsNameLower[2:]
			if strings.HasSuffix(domain, "."+wildcardDomain) || domain == wildcardDomain {
				return true
			}
		}
	}

	return false
}

func (cm *certManager) GetCertificateBySNI(serverName string) (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	name := strings.ToLower(serverName)

	if cert, ok := cm.certs[name]; ok {
		if len(cert.Certificate) == 0 {
			return nil, fmt.Errorf("certificate chain is empty")
		}
		if cert.PrivateKey == nil {
			return nil, fmt.Errorf("certificate private key is nil")
		}
		return cert, nil
	}

	if len(name) > 0 {
		labels := strings.Split(name, ".")
		if len(labels) > 1 {
			labels[0] = "*"
			wildcardName := strings.Join(labels, ".")
			if cert, ok := cm.certs[wildcardName]; ok {
				if len(cert.Certificate) == 0 {
					return nil, fmt.Errorf("certificate chain is empty")
				}
				if cert.PrivateKey == nil {
					return nil, fmt.Errorf("certificate private key is nil")
				}
				return cert, nil
			}
		}
	}

	if cert, ok := cm.certs["default"]; ok {
		if len(cert.Certificate) == 0 {
			return nil, fmt.Errorf("certificate chain is empty")
		}
		if cert.PrivateKey == nil {
			return nil, fmt.Errorf("certificate private key is nil")
		}
		return cert, nil
	}

	if cm.defaultCert != nil {
		if len(cm.defaultCert.Certificate) == 0 {
			return nil, fmt.Errorf("certificate chain is empty")
		}
		if cm.defaultCert.PrivateKey == nil {
			return nil, fmt.Errorf("certificate private key is nil")
		}
		return cm.defaultCert, nil
	}

	return cm.getTempCertificate()
}

func (cm *certManager) getTempCertificate() (*tls.Certificate, error) {
	cm.mu.RLock()
	tempCert := cm.tempCert
	cm.mu.RUnlock()

	if tempCert != nil {
		return tempCert, nil
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.tempCert != nil {
		return cm.tempCert, nil
	}

	cert, err := selfsign.GenerateSelfSignedWithDNS("localhost")
	if err != nil {
		log.Printf("TLS: ERROR - Failed to generate temporary certificate: %v", err)
		return nil, fmt.Errorf("failed to generate temporary certificate: %w", err)
	}

	cm.tempCert = &cert
	log.Printf("TLS: Generated temporary certificate (localhost) as fallback")
	return cm.tempCert, nil
}

type keepAliveResponseWriter struct {
	http.ResponseWriter
	written    bool
	statusCode int
}

func (w *keepAliveResponseWriter) WriteHeader(code int) {
	if !w.written {
		w.Header().Set("Connection", "keep-alive")
		w.written = true
		w.statusCode = code
		log.Printf("HTTP: ResponseWriter.WriteHeader called - Status: %d, Connection: %s", code, w.Header().Get("Connection"))
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *keepAliveResponseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *keepAliveResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *keepAliveResponseWriter) CloseNotify() <-chan bool {
	if cn, ok := w.ResponseWriter.(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	ch := make(chan bool)
	return ch
}

func (w *keepAliveResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("ResponseWriter does not implement http.Hijacker")
}

type connectHandler struct {
	ginHandler http.Handler
	ocHandler  *openconnect.Handler
}

func (h *connectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteAddr := r.RemoteAddr
	method := r.Method
	path := r.URL.Path
	proto := r.Proto

	isTLS := r.TLS != nil
	tlsInfo := ""
	if isTLS {
		tlsState := r.TLS
		tlsInfo = fmt.Sprintf(", TLS: version=%x, cipher=%x, serverName=%s",
			tlsState.Version, tlsState.CipherSuite, tlsState.ServerName)
	}

	log.Printf("HTTP: %s %s from %s (proto=%s%s)", method, path, remoteAddr, proto, tlsInfo)


	xAggregateAuth := r.Header.Get("X-Aggregate-Auth")
	xTranscendVersion := r.Header.Get("X-Transcend-Version")
	userAgent := strings.ToLower(r.UserAgent())

	log.Printf("HTTP: Headers - X-Aggregate-Auth=%s, X-Transcend-Version=%s, User-Agent=%s",
		xAggregateAuth, xTranscendVersion, userAgent)

	isVPNClient := (xAggregateAuth == "1" && xTranscendVersion == "1") ||
		strings.Contains(userAgent, "anyconnect") ||
		strings.Contains(userAgent, "openconnect") ||
		strings.Contains(userAgent, "cisco secure client") ||
		strings.Contains(userAgent, "cisco anyconnect") ||
		(xAggregateAuth != "" && xTranscendVersion != "") // 即使不是 "1"，只要有这些头部就可能是 VPN 客户端

	if isVPNClient {
		log.Printf("HTTP: Detected VPN client (Path: %s)", path)

		clientConnection := strings.ToLower(r.Header.Get("Connection"))
		switch method {
		case http.MethodGet:
			if clientConnection == "close" {
				log.Printf("HTTP: VPN client sent Connection: close on GET request, rejecting (Path: %s, User-Agent: %s)",
					r.URL.Path, r.UserAgent())
				w.Header().Set("Connection", "close")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		case http.MethodPost:
			if clientConnection == "close" {
				log.Printf("HTTP: VPN client sent Connection: close on POST request, forcing keep-alive (Path: %s, User-Agent: %s)",
					r.URL.Path, r.UserAgent())
				r.Header.Set("Connection", "keep-alive")
			}
		}
	} else {
		log.Printf("HTTP: Not a VPN client (Path: %s)", path)
	}

	wrappedWriter := &keepAliveResponseWriter{
		ResponseWriter: w,
		written:        false,
		statusCode:     0,
	}

	log.Printf("HTTP: Forwarding request to Gin handler (Path: %s)", path)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("HTTP: Panic in handler for %s %s: %v", method, path, r)
			if !wrappedWriter.written {
				log.Printf("HTTP: Panic recovery - Writing error response (headers not written yet)")
				wrappedWriter.WriteHeader(http.StatusInternalServerError)
				wrappedWriter.Write([]byte("Internal Server Error"))
			} else {
				log.Printf("HTTP: Panic recovery - Headers already written, cannot change status code")
			}
			panic(r)
		}
	}()

	log.Printf("HTTP: About to call Gin handler - Method: %s, Path: %s, RemoteAddr: %s", method, path, remoteAddr)

	startTime := time.Now()

	h.ginHandler.ServeHTTP(wrappedWriter, r)

	duration := time.Since(startTime)
	log.Printf("HTTP: Handler completed for %s %s - Written: %v, Status: %d, Duration: %v",
		method, path, wrappedWriter.written, wrappedWriter.statusCode, duration)

	log.Printf("HTTP: Final response headers - Connection: %s, Content-Type: %s, Content-Length: %s",
		wrappedWriter.Header().Get("Connection"),
		wrappedWriter.Header().Get("Content-Type"),
		wrappedWriter.Header().Get("Content-Length"))
}

type Server struct {
	cfg              *config.Config
	vpnServer        *vpn.VPNServer
	httpServer       *http.Server
	httpsServer      *http.Server
	ocHandler        *openconnect.Handler
	certManager      *certManager // SNI 证书管理器
	shutdownComplete chan struct{}
	ctx              context.Context
	cancel           context.CancelFunc
}

func New(cfg *config.Config, vpnServer *vpn.VPNServer) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{
		cfg:              cfg,
		vpnServer:        vpnServer,
		certManager:      newCertManager(),
		shutdownComplete: make(chan struct{}),
		ctx:              ctx,
		cancel:           cancel,
	}

	if err := server.certManager.LoadDefaultCert(cfg.VPN.CertFile, cfg.VPN.KeyFile); err != nil {
		log.Printf("ERROR: Failed to load default certificate: %v", err)
		log.Printf("ERROR: Certificate file: %s, Key file: %s", cfg.VPN.CertFile, cfg.VPN.KeyFile)
		log.Printf("ERROR: Server will start but TLS connections will fail")
	} else {
		log.Printf("Certificate Manager: Successfully loaded default certificate")
	}

	if err := server.certManager.loadCertsFromDB(); err != nil {
		log.Printf("WARNING: Failed to load SNI certificates from database: %v", err)
		log.Printf("WARNING: SNI certificates configured via UI will not be available until reloaded")
	}

	return server
}

func (s *Server) Start() error {
	s.ocHandler = openconnect.NewHandler(s.cfg, s.vpnServer)

	go s.startAuditLogFlusher()


	s.startHTTPServer()

	s.startHTTPSServer()

	if s.cfg.VPN.EnableDTLS {
		if err := s.ocHandler.StartDTLSServer(); err != nil {
			log.Printf("Failed to start DTLS server: %v (clients will use SSL/TLS only)", err)
		} else {
			log.Printf("DTLS server started on UDP port %s", s.cfg.VPN.OpenConnectPort)
		}
	}

	s.waitForShutdown()

	return nil
}

func (s *Server) startAuditLogFlusher() {
	ticker := time.NewTicker(30 * time.Second) // 每30秒刷新一次
	defer ticker.Stop()

	flushAuditLogs := func() {
		auditLogger := policy.GetAuditLogger()
		if auditLogger != nil {
			if err := auditLogger.Flush(); err != nil {
				log.Printf("Failed to flush audit logs: %v", err)
			}
		}
	}

	for {
		select {
		case <-ticker.C:
			flushAuditLogs()
		case <-s.ctx.Done():
			flushAuditLogs()
			return
		}
	}
}

func (s *Server) startHTTPServer() {
	router := routes.SetupRouter(s.cfg, s.vpnServer, s)

	s.httpServer = &http.Server{
		Addr:    s.cfg.Server.Host + ":" + s.cfg.Server.Port,
		Handler: router,
	}

	go func() {
		log.Printf("HTTP server (Management API) starting on %s:%s", s.cfg.Server.Host, s.cfg.Server.Port)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()
}

func (s *Server) startHTTPSServer() {
	router := gin.Default()
	router.Use(middleware.CorsMiddleware())

	s.ocHandler.SetupRoutes(router)

	router.NoRoute(func(c *gin.Context) {
		c.String(http.StatusNotFound, "Not Found")
	})

	customHandler := &connectHandler{
		ginHandler: router,
		ocHandler:  s.ocHandler,
	}


	cipherSuites := tls.CipherSuites()
	selectedCipherSuites := make([]uint16, 0, len(cipherSuites))
	for _, s := range cipherSuites {
		selectedCipherSuites = append(selectedCipherSuites, s.ID)
	}

	tlsConfig := &tls.Config{
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS11, // 支持 TLS 1.1 及以上版本（包括 TLS 1.2 和 1.3）
		CipherSuites: selectedCipherSuites,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {


			cert, err := s.certManager.GetCertificateBySNI(chi.ServerName)
			if err != nil {
				log.Printf("TLS: GetCertificate ERROR - SNI: %s, Error: %v", chi.ServerName, err)
			}
			return cert, err
		},
	}

	errorLogWriter := &tlsErrorLogger{
		normalErrors: map[string]bool{
			"EOF":                              true, // 客户端正常关闭连接
			"connection reset by peer":         true, // 客户端重置连接（可能是正常关闭）
			"broken pipe":                      true, // 管道断开（可能是正常关闭）
			"use of closed network connection": true, // 连接已关闭（正常情况）
		},
	}
	errorLogger := log.New(errorLogWriter, "HTTPS Server: ", log.LstdFlags|log.Lmicroseconds)

	s.httpsServer = &http.Server{
		Addr:         s.cfg.Server.Host + ":" + s.cfg.VPN.OpenConnectPort,
		Handler:      customHandler,
		TLSConfig:    tlsConfig,
		ErrorLog:     errorLogger,
		ReadTimeout:  100 * time.Second, 
		WriteTimeout: 100 * time.Second, 
	}

	go func() {
		log.Printf("HTTPS server (OpenConnect) starting on %s:%s", s.cfg.Server.Host, s.cfg.VPN.OpenConnectPort)
		log.Printf("Using default certificates: %s, %s", s.cfg.VPN.CertFile, s.cfg.VPN.KeyFile)
		log.Printf("SNI (Server Name Indication) support enabled - certificates can be configured per domain")

		s.certManager.mu.RLock()
		defaultCert := s.certManager.defaultCert
		s.certManager.mu.RUnlock()

		if defaultCert == nil {
			log.Fatalf("HTTPS: FATAL - Default certificate is nil! TLS connections will fail. Please check certificate files: %s, %s",
				s.cfg.VPN.CertFile, s.cfg.VPN.KeyFile)
		}

		if len(defaultCert.Certificate) == 0 {
			log.Fatalf("HTTPS: FATAL - Default certificate chain is empty! Please check certificate file: %s",
				s.cfg.VPN.CertFile)
		}

		if defaultCert.PrivateKey == nil {
			log.Fatalf("HTTPS: FATAL - Default certificate private key is nil! Please check key file: %s",
				s.cfg.VPN.KeyFile)
		}

		log.Printf("HTTPS: Default certificate verified - Chain length: %d, Has private key: %v",
			len(defaultCert.Certificate), defaultCert.PrivateKey != nil)

		addr := s.cfg.Server.Host + ":" + s.cfg.VPN.OpenConnectPort
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("HTTPS: Failed to listen on %s: %v", addr, err)
		}

		log.Printf("HTTPS: Listening on %s", addr)

		log.Printf("HTTPS: Starting ServeTLS on listener")
		if err := s.httpsServer.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTPS: ServeTLS error: %v (type: %T)", err, err)
			if netErr, ok := err.(net.Error); ok {
				log.Printf("HTTPS: Network error details - Temporary: %v, Timeout: %v", netErr.Temporary(), netErr.Timeout())
			}
			log.Fatalf("HTTPS server error: %v", err)
		}
		log.Printf("HTTPS: ServeTLS exited (this is normal on shutdown)")
	}()
}


func (s *Server) waitForShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	s.cancel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Printf("HTTP server forced to shutdown: %v", err)
		}
	}

	if s.httpsServer != nil {
		if err := s.httpsServer.Shutdown(ctx); err != nil {
			log.Printf("HTTPS server forced to shutdown: %v", err)
		}
	}

	if err := s.vpnServer.Stop(); err != nil {
		log.Printf("VPN server shutdown error: %v", err)
	}

	log.Println("Server exited")
	close(s.shutdownComplete)
}

func (s *Server) AddSNICert(sni string, certFile, keyFile string) error {
	return s.certManager.AddCert(sni, certFile, keyFile)
}

func (s *Server) AddSNICertFromBytes(sni string, certBytes, keyBytes []byte) error {
	return s.certManager.AddCertFromBytes(sni, certBytes, keyBytes)
}

func (s *Server) RemoveSNICert(sni string) error {
	return s.certManager.RemoveCert(sni)
}

func (s *Server) GetSNICerts() map[string]handlers.CertInfo {
	certs := s.certManager.GetCerts()
	result := make(map[string]handlers.CertInfo)
	for k, v := range certs {
		result[k] = handlers.CertInfo{
			SNI:           v.SNI,
			CommonName:    v.CommonName,
			DNSNames:      v.DNSNames,
			Issuer:        v.Issuer,
			NotBefore:     v.NotBefore,
			NotAfter:      v.NotAfter,
			DaysRemaining: v.DaysRemaining,
			IsExpired:     v.IsExpired,
			IsDefault:     v.IsDefault,
		}
	}
	return result
}

func (s *Server) GetDefaultCert() *handlers.CertInfo {
	info := s.certManager.GetDefaultCertInfo()
	if info == nil {
		return nil
	}
	return &handlers.CertInfo{
		SNI:           info.SNI,
		CommonName:    info.CommonName,
		DNSNames:      info.DNSNames,
		Issuer:        info.Issuer,
		NotBefore:     info.NotBefore,
		NotAfter:      info.NotAfter,
		DaysRemaining: info.DaysRemaining,
		IsExpired:     info.IsExpired,
		IsDefault:     info.IsDefault,
	}
}

func (s *Server) UpdateDefaultCert(certFile, keyFile string) error {
	return s.certManager.LoadDefaultCert(certFile, keyFile)
}

func (s *Server) UpdateDefaultCertFromBytes(certBytes, keyBytes []byte) error {
	return s.certManager.LoadDefaultCertFromBytes(certBytes, keyBytes)
}

func (s *Server) UpdateDefaultCertFromBytesAndSave(certBytes, keyBytes []byte) error {
	certFile := s.cfg.VPN.CertFile
	keyFile := s.cfg.VPN.KeyFile

	if err := os.WriteFile(certFile, certBytes, 0600); err != nil {
		return fmt.Errorf("failed to save certificate file: %w", err)
	}

	if err := os.WriteFile(keyFile, keyBytes, 0600); err != nil {
		return fmt.Errorf("failed to save key file: %w", err)
	}

	return s.certManager.LoadDefaultCert(certFile, keyFile)
}

type connectionLoggingListener struct {
	net.Listener
}

func (l *connectionLoggingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		log.Printf("TLS: Accept() error: %v", err)
		return nil, err
	}

	remoteAddr := conn.RemoteAddr().String()
	localAddr := conn.LocalAddr().String()
	log.Printf("TLS: New TCP connection established - Remote: %s, Local: %s (container internal address)", remoteAddr, localAddr)

	if _, ok := conn.(*net.TCPConn); ok {
		log.Printf("TLS: Connection type: TCP")
	}

	os.Stderr.Sync() // 强制刷新日志

	return conn, nil
}

type loggingConn struct {
	net.Conn
	remoteAddr string
	closed     bool
	mu         sync.Mutex
}

func (c *loggingConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.closed {
		c.closed = true
		log.Printf("TLS: Connection closed - Remote: %s", c.remoteAddr)
		os.Stderr.Sync() // 强制刷新日志
	}
	return c.Conn.Close()
}

func (c *loggingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err != nil {
		log.Printf("TLS: Write error to %s: %v", c.remoteAddr, err)
		os.Stderr.Sync()
	}
	return n, err
}

func (c *loggingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil && !c.closed {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("TLS: Read timeout from %s (this is normal if IdleTimeout is reached or during authentication)", c.remoteAddr)
		} else {
			log.Printf("TLS: Read error from %s: %v", c.remoteAddr, err)
		}
		os.Stderr.Sync()
	}
	return n, err
}

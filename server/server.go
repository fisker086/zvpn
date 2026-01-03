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

// CertInfo 证书信息
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

// certManager 证书管理器，支持 SNI (Server Name Indication)
// 参考 anylink 的实现，支持为不同域名提供不同证书
type certManager struct {
	certs       map[string]*tls.Certificate // SNI 域名 -> 证书（包含 "default" 键）
	defaultCert *tls.Certificate            // 默认证书（向后兼容，优先使用 certs["default"]）
	tempCert    *tls.Certificate            // 临时证书（localhost，最后的备选方案，参考 anylink）
	mu          sync.RWMutex                // 保护并发访问
}

// newCertManager 创建新的证书管理器
func newCertManager() *certManager {
	// 参考 anylink：初始化时生成临时证书（localhost）
	// 作为最后的备选方案，确保即使没有配置证书也能提供服务
	tempCert, err := selfsign.GenerateSelfSignedWithDNS("localhost")
	if err != nil {
		log.Printf("WARNING: Failed to generate temporary certificate: %v", err)
		// 即使生成失败，也继续初始化，只是 tempCert 为 nil
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

// filterRootCertificate 过滤掉证书链中的根证书（TLS 握手不应该发送根证书）
// 根证书的特征：颁发者和主体相同（自签名）
// 同时检查证书链顺序，确保服务器证书在前，中间证书在后
func filterRootCertificate(cert *tls.Certificate) {
	if len(cert.Certificate) <= 1 {
		return // 只有一个证书，不需要过滤
	}

	originalLength := len(cert.Certificate)

	// 检查并过滤所有可能的根证书（从后往前检查）
	for len(cert.Certificate) > 1 {
		lastIdx := len(cert.Certificate) - 1
		lastCert, err := x509.ParseCertificate(cert.Certificate[lastIdx])
		if err != nil {
			break // 解析失败，停止处理
		}

		// 如果最后一个证书是自签名的（颁发者和主体相同），则移除它
		if lastCert.Issuer.String() == lastCert.Subject.String() {
			log.Printf("Certificate Manager: Filtering out root certificate (self-signed) - CN: %s, Issuer: %s",
				lastCert.Subject.CommonName, lastCert.Issuer.CommonName)
			cert.Certificate = cert.Certificate[:lastIdx]
		} else {
			break // 不是根证书，停止处理
		}
	}

	// 记录过滤结果
	if len(cert.Certificate) < originalLength {
		log.Printf("Certificate Manager: Certificate chain filtered - Original: %d certs, After filtering: %d certs",
			originalLength, len(cert.Certificate))
	}

	// 验证证书链顺序（服务器证书在前，中间证书在后）
	if len(cert.Certificate) > 1 {
		serverCert, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil {
			intermediateCert, err := x509.ParseCertificate(cert.Certificate[1])
			if err == nil {
				// 检查服务器证书的颁发者是否与中间证书的主体匹配
				if serverCert.Issuer.String() != intermediateCert.Subject.String() {
					log.Printf("Certificate Manager: ⚠️  WARNING - Certificate chain order may be incorrect!")
					log.Printf("Certificate Manager: ⚠️  Server cert issuer (%s) != Intermediate cert subject (%s)",
						serverCert.Issuer.String(), intermediateCert.Subject.String())
				}
			}
		}
	}
}

// LoadDefaultCert 加载默认证书
func (cm *certManager) LoadDefaultCert(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load default certificate: %w", err)
	}

	// 过滤掉根证书（TLS 握手不应该发送根证书）
	filterRootCertificate(&cert)

	// 解析证书以获取域名信息
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

	// 验证证书链是否正确加载
	if len(cert.Certificate) < 1 {
		return fmt.Errorf("certificate chain is empty")
	}

	// 参考 anylink：加载证书后，自动将证书的 CN 和 DNS Names 也添加到映射中
	cm.LoadCertificate(&cert)

	// 记录证书链信息（用于调试）
	log.Printf("Certificate Manager: Certificate chain loaded - Server cert: %d bytes, Chain length: %d",
		len(cert.Certificate[0]), len(cert.Certificate))

	// 计算证书链总大小（用于诊断）
	totalSize := 0
	for i, certBytes := range cert.Certificate {
		totalSize += len(certBytes)
		if i > 0 {
			log.Printf("Certificate Manager: Chain cert #%d: %d bytes", i+1, len(certBytes))
		}
	}
	log.Printf("Certificate Manager: Total certificate chain size: %d bytes", totalSize)

	if len(cert.Certificate) > 1 {
		// 验证证书链顺序：第一个应该是服务器证书，第二个应该是中间证书
		if cert.Leaf != nil {
			log.Printf("Certificate Manager: Server cert CN: %s, Issuer: %s",
				cert.Leaf.Subject.CommonName, cert.Leaf.Issuer.CommonName)

			// 解析第二个证书（中间证书）
			if len(cert.Certificate) > 1 {
				intermediateCert, err := x509.ParseCertificate(cert.Certificate[1])
				if err == nil {
					log.Printf("Certificate Manager: Intermediate cert CN: %s, Issuer: %s",
						intermediateCert.Subject.CommonName, intermediateCert.Issuer.CommonName)

					// 检查证书链顺序：服务器证书的颁发者应该是中间证书的主体
					if cert.Leaf.Issuer.String() != intermediateCert.Subject.String() {
						log.Printf("Certificate Manager: ⚠️  WARNING - Certificate chain order may be incorrect!")
						log.Printf("Certificate Manager: ⚠️  Server cert issuer (%s) != Intermediate cert subject (%s)",
							cert.Leaf.Issuer.String(), intermediateCert.Subject.String())
						log.Printf("Certificate Manager: ⚠️  Certificate order should be: server cert first, then intermediate cert")
					} else {
						log.Printf("Certificate Manager: ✓ Certificate chain order is correct")
					}

					// 检查中间证书是否是自签名的（可能是根证书）
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

	// 参考 anylink：简单记录，不做严格检查
	log.Printf("Certificate Manager: Loaded default certificate from %s, %s", certFile, keyFile)
	log.Printf("Certificate Manager: Certificate chain contains %d certificate(s)", len(cert.Certificate))
	if cert.Leaf != nil {
		log.Printf("Certificate Manager: Server cert CN: %s", cert.Leaf.Subject.CommonName)
		log.Printf("Certificate Manager: Certificate DNS Names: %v", cert.Leaf.DNSNames)

		// 检查证书有效期
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

// AddCert 为指定 SNI 域名添加证书
func (cm *certManager) AddCert(sni string, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate for SNI %s: %w", sni, err)
	}

	// 过滤掉根证书（TLS 握手不应该发送根证书）
	filterRootCertificate(&cert)

	// 解析证书以获取域名信息
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

	// 参考 anylink：加载证书后，自动将证书的 CN 和 DNS Names 也添加到映射中
	cm.LoadCertificate(&cert)

	return nil
}

// AddCertFromBytes 从字节数据添加证书（保存到数据库）
func (cm *certManager) AddCertFromBytes(sni string, certBytes, keyBytes []byte) error {
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return fmt.Errorf("failed to load certificate from bytes for SNI %s: %w", sni, err)
	}

	// 过滤掉根证书（TLS 握手不应该发送根证书）
	filterRootCertificate(&cert)

	// 解析证书以获取域名信息
	if cert.Leaf == nil {
		if len(cert.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err == nil {
				cert.Leaf = leaf
			}
		}
	}

	// 保存到数据库
	if err := cm.saveCertToDB(sni, certBytes, keyBytes, &cert); err != nil {
		log.Printf("WARNING: Failed to save certificate to database: %v", err)
		// 继续执行，至少保存到内存
	}

	cm.mu.Lock()
	cm.certs[strings.ToLower(sni)] = &cert
	cm.mu.Unlock()

	log.Printf("Certificate Manager: Added certificate for SNI '%s' from bytes", sni)
	if cert.Leaf != nil {
		log.Printf("Certificate Manager: SNI '%s' cert CN: %s, DNS Names: %v", sni, cert.Leaf.Subject.CommonName, cert.Leaf.DNSNames)
	}

	// 参考 anylink：加载证书后，自动将证书的 CN 和 DNS Names 也添加到映射中
	cm.LoadCertificate(&cert)

	return nil
}

// RemoveCert 删除指定 SNI 域名的证书（同时从数据库删除）
func (cm *certManager) RemoveCert(sni string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	sniLower := strings.ToLower(sni)
	if _, exists := cm.certs[sniLower]; !exists {
		return fmt.Errorf("certificate for SNI '%s' not found", sni)
	}

	// 从数据库删除
	if err := database.DB.Where("sni = ?", sniLower).Delete(&models.Certificate{}).Error; err != nil {
		log.Printf("WARNING: Failed to delete certificate from database: %v", err)
		// 继续执行，至少从内存中删除
	}

	delete(cm.certs, sniLower)
	log.Printf("Certificate Manager: Removed certificate for SNI '%s'", sni)
	return nil
}

// saveCertToDB 保存证书到数据库
func (cm *certManager) saveCertToDB(sni string, certBytes, keyBytes []byte, cert *tls.Certificate) error {
	sniLower := strings.ToLower(sni)

	certRecord := &models.Certificate{
		SNI:      sniLower,
		CertData: certBytes,
		KeyData:  keyBytes,
		IsActive: true,
	}

	if cert.Leaf != nil {
		// 构建证书信息
		dnsNamesBytes, _ := json.Marshal(cert.Leaf.DNSNames)
		certRecord.CommonName = cert.Leaf.Subject.CommonName
		certRecord.DNSNames = string(dnsNamesBytes)
		certRecord.Issuer = cert.Leaf.Issuer.CommonName
		certRecord.NotBefore = cert.Leaf.NotBefore
		certRecord.NotAfter = cert.Leaf.NotAfter
	}

	// 使用 Upsert（如果存在则更新，不存在则创建）
	return database.DB.Where("sni = ?", sniLower).Assign(certRecord).FirstOrCreate(certRecord).Error
}

// loadCertsFromDB 从数据库加载所有 SNI 证书
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

		// 解析证书
		if cert.Leaf == nil && len(cert.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err == nil {
				cert.Leaf = leaf
			}
		}

		sniLower := strings.ToLower(certRecord.SNI)
		cm.certs[sniLower] = &cert

		// 自动将证书的 CN 和 DNS Names 也添加到映射中
		// 注意：这里已经持有锁，所以调用不需要锁的内部版本
		cm.buildNameToCertificateUnlocked(&cert)

		log.Printf("Certificate Manager: Loaded SNI certificate '%s' from database", certRecord.SNI)
	}

	log.Printf("Certificate Manager: Loaded %d SNI certificates from database", len(certs))
	return nil
}

// GetCerts 获取所有 SNI 证书信息
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

// GetDefaultCertInfo 获取默认证书信息
func (cm *certManager) GetDefaultCertInfo() *certInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.defaultCert == nil || cm.defaultCert.Leaf == nil {
		return nil
	}

	info := cm.certToInfo("", cm.defaultCert, true)
	return &info
}

// LoadDefaultCertFromBytes 从字节数据加载默认证书
func (cm *certManager) LoadDefaultCertFromBytes(certBytes, keyBytes []byte) error {
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return fmt.Errorf("failed to load default certificate from bytes: %w", err)
	}

	// 解析证书以获取域名信息
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

	// 参考 anylink：加载证书后，自动将证书的 CN 和 DNS Names 也添加到映射中
	cm.LoadCertificate(&cert)

	return nil
}

// certInfo 内部证书信息结构
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

// certToInfo 将证书转换为 certInfo
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

// LoadCertificate 加载证书到内存（参考 anylink 的实现）
// 当证书加载后，会自动解析 CN 和 DNS Names，并添加到证书映射中
func (cm *certManager) LoadCertificate(cert *tls.Certificate) {
	cm.buildNameToCertificate(cert)
}

// buildNameToCertificate 构建域名到证书的映射（参考 anylink）
// 注意：此函数会获取锁，如果已经持有锁，请使用 buildNameToCertificateUnlocked
func (cm *certManager) buildNameToCertificate(cert *tls.Certificate) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.buildNameToCertificateUnlocked(cert)
}

// buildNameToCertificateUnlocked 构建域名到证书的映射（不需要锁的版本）
// 调用此函数前必须已经持有 cm.mu 锁
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

	// 参考 anylink：设置默认证书（兼容不支持 SNI 的客户端）
	cm.certs["default"] = cert

	// 参考 anylink：只有当没有 DNS Names 时才添加 CN
	// 如果有 DNS Names，CN 通常会被忽略（RFC 6125）
	if x509Cert.Subject.CommonName != "" && len(x509Cert.DNSNames) == 0 {
		commonName := strings.ToLower(x509Cert.Subject.CommonName)
		log.Printf("┏ Load Certificate: %s", commonName)
		log.Printf("┠╌╌ Start Time:     %s", startTime)
		log.Printf("┖╌╌ Expired Time:   %s", expiredTime)
		cm.certs[commonName] = cert
	}

	// 添加所有 DNS Names（SAN）到映射
	for _, san := range x509Cert.DNSNames {
		sanLower := strings.ToLower(san)
		log.Printf("┏ Load Certificate: %s", sanLower)
		log.Printf("┠╌╌ Start Time:     %s", startTime)
		log.Printf("┖╌╌ Expired Time:   %s", expiredTime)
		cm.certs[sanLower] = cert
	}
}

// matchDomain 检查域名是否匹配证书的 DNS Names（支持通配符和多域名）
func matchDomain(domain string, cert *tls.Certificate) bool {
	if cert == nil || cert.Leaf == nil {
		return false
	}

	domain = strings.ToLower(domain)

	// 检查 CN（Common Name）
	if cert.Leaf.Subject.CommonName != "" {
		cn := strings.ToLower(cert.Leaf.Subject.CommonName)
		if cn == domain {
			return true
		}
		// 支持通配符 CN（如 *.example.com）
		if strings.HasPrefix(cn, "*.") {
			wildcardDomain := cn[2:]
			if strings.HasSuffix(domain, "."+wildcardDomain) || domain == wildcardDomain {
				return true
			}
		}
	}

	// 检查 DNS Names（Subject Alternative Name）
	for _, dnsName := range cert.Leaf.DNSNames {
		dnsNameLower := strings.ToLower(dnsName)
		if dnsNameLower == domain {
			return true
		}
		// 支持通配符 DNS Name（如 *.example.com）
		if strings.HasPrefix(dnsNameLower, "*.") {
			wildcardDomain := dnsNameLower[2:]
			if strings.HasSuffix(domain, "."+wildcardDomain) || domain == wildcardDomain {
				return true
			}
		}
	}

	return false
}

// GetCertificateBySNI 根据 SNI 获取证书（用于 TLS GetCertificate 回调）
// 参考 anylink 的实现：精确匹配 -> 通配符匹配 -> 默认证书
// 注意：anylink 的 GetCertificateBySNI 接收 string（ServerName），我们保持一致
func (cm *certManager) GetCertificateBySNI(serverName string) (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// 参考 anylink：Copy from tls.Config getCertificate()
	name := strings.ToLower(serverName)

	// 1. 精确匹配（参考 anylink，不做任何日志，避免干扰 TLS 握手）
	if cert, ok := cm.certs[name]; ok {
		// 检查证书和私钥是否有效（只在出错时记录）
		if len(cert.Certificate) == 0 {
			return nil, fmt.Errorf("certificate chain is empty")
		}
		if cert.PrivateKey == nil {
			return nil, fmt.Errorf("certificate private key is nil")
		}
		return cert, nil
	}

	// 2. 通配符匹配（参考 anylink 的实现）
	// anylink 的方式：将第一个标签替换为 *，然后查找
	if len(name) > 0 {
		labels := strings.Split(name, ".")
		if len(labels) > 1 {
			labels[0] = "*"
			wildcardName := strings.Join(labels, ".")
			if cert, ok := cm.certs[wildcardName]; ok {
				// 检查证书和私钥是否有效（只在出错时返回错误）
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

	// 3. 默认证书（兼容不支持 SNI 的客户端）
	if cert, ok := cm.certs["default"]; ok {
		// 检查证书和私钥是否有效（只在出错时返回错误）
		if len(cert.Certificate) == 0 {
			return nil, fmt.Errorf("certificate chain is empty")
		}
		if cert.PrivateKey == nil {
			return nil, fmt.Errorf("certificate private key is nil")
		}
		// 参考 anylink：直接返回证书指针，不深拷贝
		return cert, nil
	}

	// 4. 如果都没有，使用 defaultCert（向后兼容）
	if cm.defaultCert != nil {
		// 检查证书和私钥是否有效（只在出错时返回错误）
		if len(cm.defaultCert.Certificate) == 0 {
			return nil, fmt.Errorf("certificate chain is empty")
		}
		if cm.defaultCert.PrivateKey == nil {
			return nil, fmt.Errorf("certificate private key is nil")
		}
		return cm.defaultCert, nil
	}

	// 5. 最后的备选方案：返回临时证书（参考 anylink）
	// 使用 localhost 临时证书，确保即使没有配置证书也能提供服务
	// 客户端会看到证书警告，但连接可以继续
	return cm.getTempCertificate()
}

// getTempCertificate 获取临时证书（参考 anylink 的实现）
// 如果临时证书不存在，则生成一个新的
func (cm *certManager) getTempCertificate() (*tls.Certificate, error) {
	cm.mu.RLock()
	tempCert := cm.tempCert
	cm.mu.RUnlock()

	if tempCert != nil {
		return tempCert, nil
	}

	// 如果临时证书不存在，生成一个新的（参考 anylink 的 getTempCertificate 实现）
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// 双重检查，避免重复生成
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

// keepAliveResponseWriter 包装 http.ResponseWriter，强制设置 Connection: keep-alive
type keepAliveResponseWriter struct {
	http.ResponseWriter
	written    bool
	statusCode int
}

func (w *keepAliveResponseWriter) WriteHeader(code int) {
	if !w.written {
		// 强制设置 Connection: keep-alive
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

// Flush 实现 http.Flusher 接口
func (w *keepAliveResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// CloseNotify 实现 http.CloseNotifier 接口（用于检测客户端连接关闭）
func (w *keepAliveResponseWriter) CloseNotify() <-chan bool {
	if cn, ok := w.ResponseWriter.(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	// 如果不支持 CloseNotify，返回一个永远不会关闭的 channel
	ch := make(chan bool)
	return ch
}

// Hijack 实现 http.Hijacker 接口（用于 CONNECT 请求）
func (w *keepAliveResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("ResponseWriter does not implement http.Hijacker")
}

// connectHandler 自定义 HTTP Handler，用于拦截 CONNECT 请求
type connectHandler struct {
	ginHandler http.Handler
	ocHandler  *openconnect.Handler
}

// ServeHTTP 实现 http.Handler 接口
func (h *connectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 记录底层 HTTP 请求信息
	remoteAddr := r.RemoteAddr
	method := r.Method
	path := r.URL.Path
	proto := r.Proto

	// 检查是否是 TLS 连接
	isTLS := r.TLS != nil
	tlsInfo := ""
	if isTLS {
		tlsState := r.TLS
		tlsInfo = fmt.Sprintf(", TLS: version=%x, cipher=%x, serverName=%s",
			tlsState.Version, tlsState.CipherSuite, tlsState.ServerName)
	}

	log.Printf("HTTP: %s %s from %s (proto=%s%s)", method, path, remoteAddr, proto, tlsInfo)

	// 重要：对于 OpenConnect/AnyConnect 客户端，强制使用 keep-alive
	// 即使客户端没有明确发送 Connection: keep-alive，我们也应该保持连接打开
	// 这是 OpenConnect/AnyConnect 协议的要求：使用长连接进行多个请求

	// 参考 anylink 的实现，改进 VPN 客户端检测逻辑
	// 检测 VPN 客户端的方法：
	// 1. 通过 X-Aggregate-Auth 和 X-Transcend-Version 头部（AnyConnect 标准方法，最可靠）
	// 2. 通过 User-Agent（用于初始请求，此时可能还没有发送上述头部）
	xAggregateAuth := r.Header.Get("X-Aggregate-Auth")
	xTranscendVersion := r.Header.Get("X-Transcend-Version")
	userAgent := strings.ToLower(r.UserAgent())

	log.Printf("HTTP: Headers - X-Aggregate-Auth=%s, X-Transcend-Version=%s, User-Agent=%s",
		xAggregateAuth, xTranscendVersion, userAgent)

	// 检测是否为 VPN 客户端（参考 anylink 的检测逻辑）
	// AnyConnect 客户端会发送 X-Aggregate-Auth: 1 和 X-Transcend-Version: 1
	isVPNClient := (xAggregateAuth == "1" && xTranscendVersion == "1") ||
		strings.Contains(userAgent, "anyconnect") ||
		strings.Contains(userAgent, "openconnect") ||
		strings.Contains(userAgent, "cisco secure client") ||
		strings.Contains(userAgent, "cisco anyconnect") ||
		(xAggregateAuth != "" && xTranscendVersion != "") // 即使不是 "1"，只要有这些头部就可能是 VPN 客户端

	if isVPNClient {
		log.Printf("HTTP: Detected VPN client (Path: %s)", path)

		// 参考 anylink：对于 VPN 客户端，强制使用 keep-alive
		// GET 请求：如果客户端发送 Connection: close，直接拒绝（anylink 的行为）
		// POST 请求：强制覆盖为 keep-alive（OpenConnect 协议要求使用长连接）
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
			// POST 请求：强制覆盖 Connection: close 为 keep-alive
			if clientConnection == "close" {
				log.Printf("HTTP: VPN client sent Connection: close on POST request, forcing keep-alive (Path: %s, User-Agent: %s)",
					r.URL.Path, r.UserAgent())
				r.Header.Set("Connection", "keep-alive")
			}
		}
	} else {
		log.Printf("HTTP: Not a VPN client (Path: %s)", path)
		// 对于非 VPN 客户端（如 curl、浏览器），也确保使用 keep-alive（参考 anylink）
		// anylink 的 LinkHome 会处理 GET / 请求，返回 HTML 或配置
		// 这里不需要特殊处理，直接交给 Gin 处理即可
	}

	// 包装 ResponseWriter 以确保 keep-alive（参考 anylink 的做法）
	// 对于所有请求，都使用 keepAliveResponseWriter 包装
	wrappedWriter := &keepAliveResponseWriter{
		ResponseWriter: w,
		written:        false,
		statusCode:     0,
	}

	// 所有请求都交给 Gin 处理
	log.Printf("HTTP: Forwarding request to Gin handler (Path: %s)", path)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("HTTP: Panic in handler for %s %s: %v", method, path, r)
			// 发生 panic 时，确保返回错误响应而不是让连接异常关闭
			// 注意：如果响应已经写入，不能再修改状态码（避免 Gin 警告）
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

	// 记录请求开始时间
	startTime := time.Now()

	h.ginHandler.ServeHTTP(wrappedWriter, r)

	// 记录处理时间
	duration := time.Since(startTime)
	log.Printf("HTTP: Handler completed for %s %s - Written: %v, Status: %d, Duration: %v",
		method, path, wrappedWriter.written, wrappedWriter.statusCode, duration)

	// 检查响应头
	log.Printf("HTTP: Final response headers - Connection: %s, Content-Type: %s, Content-Length: %s",
		wrappedWriter.Header().Get("Connection"),
		wrappedWriter.Header().Get("Content-Type"),
		wrappedWriter.Header().Get("Content-Length"))
}

// Server 服务器管理器
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

// New 创建新的服务器实例
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

	// 加载默认证书
	if err := server.certManager.LoadDefaultCert(cfg.VPN.CertFile, cfg.VPN.KeyFile); err != nil {
		log.Printf("ERROR: Failed to load default certificate: %v", err)
		log.Printf("ERROR: Certificate file: %s, Key file: %s", cfg.VPN.CertFile, cfg.VPN.KeyFile)
		log.Printf("ERROR: Server will start but TLS connections will fail")
	} else {
		log.Printf("Certificate Manager: Successfully loaded default certificate")
	}

	// 从数据库加载所有 SNI 证书（启动时恢复之前配置的证书）
	if err := server.certManager.loadCertsFromDB(); err != nil {
		log.Printf("WARNING: Failed to load SNI certificates from database: %v", err)
		log.Printf("WARNING: SNI certificates configured via UI will not be available until reloaded")
	}

	return server
}

// Start 启动所有服务器
func (s *Server) Start() error {
	// 初始化 OpenConnect 处理器（默认启用）
	s.ocHandler = openconnect.NewHandler(s.cfg, s.vpnServer)

	// 启动定期刷新审计日志缓冲区的goroutine
	go s.startAuditLogFlusher()

	// 不再启动自定义VPN协议服务器

	// 启动 HTTP 管理 API 服务器
	s.startHTTPServer()

	// 启动 HTTPS OpenConnect 服务器（默认启用）
	s.startHTTPSServer()

	// 启动 DTLS UDP 服务器（如果启用）
	if s.cfg.VPN.EnableDTLS {
		if err := s.ocHandler.StartDTLSServer(); err != nil {
			log.Printf("Failed to start DTLS server: %v (clients will use SSL/TLS only)", err)
		} else {
			log.Printf("DTLS server started on UDP port %s", s.cfg.VPN.OpenConnectPort)
		}
	}

	// 等待中断信号
	s.waitForShutdown()

	return nil
}

// startAuditLogFlusher 启动定期刷新审计日志缓冲区的goroutine
func (s *Server) startAuditLogFlusher() {
	ticker := time.NewTicker(30 * time.Second) // 每30秒刷新一次
	defer ticker.Stop()

	// 刷新审计日志的辅助函数
	flushAuditLogs := func() {
		auditLogger := policy.GetAuditLogger()
		if auditLogger != nil {
			if err := auditLogger.Flush(); err != nil {
				log.Printf("Failed to flush audit logs: %v", err)
			}
		}
	}

	// 使用 for range 简化循环，同时监听关闭信号
	for {
		select {
		case <-ticker.C:
			flushAuditLogs()
		case <-s.ctx.Done():
			// 服务器关闭时，执行最后一次刷新确保数据不丢失
			flushAuditLogs()
			return
		}
	}
}

// startHTTPServer 启动 HTTP 管理 API 服务器
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

// startHTTPSServer 启动 HTTPS OpenConnect 服务器
func (s *Server) startHTTPSServer() {
	router := gin.Default()
	// CORS 中间件
	router.Use(middleware.CorsMiddleware())

	// 注册 OpenConnect 路由
	s.ocHandler.SetupRoutes(router)

	router.NoRoute(func(c *gin.Context) {
		c.String(http.StatusNotFound, "Not Found")
	})

	// 创建自定义 HTTP Handler 来拦截 CONNECT 请求
	// 因为 Gin 可能不支持 CONNECT 方法，我们需要在 HTTP 层面处理
	customHandler := &connectHandler{
		ginHandler: router,
		ocHandler:  s.ocHandler,
	}

	// 配置 TLS - 参考 anylink 的简单配置方式
	// anylink 使用最简单的 TLS 配置，不做过多的检查和日志

	// 修复 CVE-2016-2183
	// https://segmentfault.com/a/1190000038486901
	// nmap -sV --script ssl-enum-ciphers -p 443 www.example.com
	cipherSuites := tls.CipherSuites()
	selectedCipherSuites := make([]uint16, 0, len(cipherSuites))
	for _, s := range cipherSuites {
		selectedCipherSuites = append(selectedCipherSuites, s.ID)
	}

	// 设置tls信息（完全参考 anylink 的配置）
	// 注意：anylink 的配置非常简单，只有最基本的字段，GetCertificate 中只有一行 Trace 日志
	// 重要：不要添加额外的TLS配置选项，这可能导致兼容性问题
	// 保持与 anylink 完全一致的配置，确保最大兼容性
	tlsConfig := &tls.Config{
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
		// 注意：不设置 MaxVersion，让 Go 自动协商最高支持的 TLS 版本
		// 不设置 PreferServerCipherSuites，使用默认行为（客户端优先）
		CipherSuites: selectedCipherSuites,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// 记录客户端SNI信息（用于诊断证书匹配问题）
			// 注意：只在有SNI时记录，避免产生过多日志
			if chi.ServerName != "" {
				log.Printf("TLS: GetCertificate - SNI: %s, RemoteAddr: %s", chi.ServerName, chi.Conn.RemoteAddr().String())
			} else {
				log.Printf("TLS: GetCertificate - No SNI provided, RemoteAddr: %s", chi.Conn.RemoteAddr().String())
			}

			// 参考 anylink：完全一致的实现
			// anylink: base.Trace("GetCertificate ServerName", chi.ServerName)
			// anylink: return dbdata.GetCertificateBySNI(chi.ServerName)
			cert, err := s.certManager.GetCertificateBySNI(chi.ServerName)
			if err != nil {
				// 记录错误详情
				log.Printf("TLS: GetCertificate ERROR - SNI: %s, Error: %v", chi.ServerName, err)
			} else if cert != nil {
				// 验证证书链的有效性（用于诊断）
				if len(cert.Certificate) > 1 {
					// 检查证书链顺序
					serverCert, err1 := x509.ParseCertificate(cert.Certificate[0])
					intermediateCert, err2 := x509.ParseCertificate(cert.Certificate[1])
					if err1 == nil && err2 == nil {
						if serverCert.Issuer.String() != intermediateCert.Subject.String() {
							log.Printf("TLS: ⚠️  WARNING - Certificate chain order issue detected during handshake!")
							log.Printf("TLS: ⚠️  Server cert issuer: %s", serverCert.Issuer.String())
							log.Printf("TLS: ⚠️  Intermediate cert subject: %s", intermediateCert.Subject.String())
							log.Printf("TLS: ⚠️  This may cause client to reject the certificate chain")
						}
					}
				}
				// 计算证书链大小
				certSize := 0
				for _, certBytes := range cert.Certificate {
					certSize += len(certBytes)
				}

				// 记录证书信息
				if cert.Leaf != nil {
					certCN := cert.Leaf.Subject.CommonName
					certDNSNames := cert.Leaf.DNSNames
					log.Printf("TLS: Certificate selected - CN: %s, DNS Names: %v, Chain size: %d bytes (%d certs), SNI: %s",
						certCN, certDNSNames, certSize, len(cert.Certificate), chi.ServerName)

					// 检查证书是否匹配请求的SNI
					if chi.ServerName != "" {
						sniLower := strings.ToLower(chi.ServerName)
						matched := false
						if certCN != "" && strings.ToLower(certCN) == sniLower {
							matched = true
						}
						for _, dnsName := range certDNSNames {
							if strings.ToLower(dnsName) == sniLower {
								matched = true
								break
							}
						}
						if !matched {
							log.Printf("TLS: ⚠️  WARNING - Certificate does not match SNI! SNI: %s, Cert CN: %s, Cert DNS: %v",
								chi.ServerName, certCN, certDNSNames)
						}
					}
				} else {
					log.Printf("TLS: Certificate selected - Chain size: %d bytes (%d certs), SNI: %s (cert.Leaf is nil)",
						certSize, len(cert.Certificate), chi.ServerName)
				}

				// 检查证书链大小（TLS握手消息大小限制）
				// 标准以太网MTU是1500字节，减去IP和TCP头部（40字节），实际可用约1460字节
				// TLS握手消息包括：TLS记录头（5字节）+ 握手消息头（4字节）+ 证书消息
				// 如果证书链超过14KB，可能导致握手消息过大，在某些网络环境下失败
				if certSize > 14000 {
					log.Printf("TLS: ⚠️  WARNING - Large certificate chain (%d bytes) may cause TLS handshake failures on networks with small MTU or strict firewalls",
						certSize)
					log.Printf("TLS: ⚠️  Consider reducing certificate chain size or using a certificate with shorter chain")
				}
			}
			return cert, err
		},
	}

	// 使用详细的错误日志记录器（添加更多调试信息）
	errorLogger := log.New(os.Stderr, "HTTPS Server: ", log.LstdFlags|log.Lmicroseconds)

	// 参考 anylink 的服务器配置
	// 注意：对于 VPN 长连接，ReadTimeout 和 WriteTimeout 应该设置得足够长
	// 参考 TIMEOUT_FIX.md 的建议：增加超时时间以适应 OpenConnect 慢速客户端
	// ReadTimeout 设置为 0 表示不限制读取超时（让 IdleTimeout 控制空闲超时）
	// 这是关键修复：ReadTimeout=0 允许连接在等待下一个请求时不受时间限制
	// IdleTimeout 设置为 600 秒（10分钟），控制 keep-alive 连接的空闲时间
	// WriteTimeout 设置为 300 秒（5分钟），限制写入超时
	// 参考 anylink 的服务器配置（完全一致）
	s.httpsServer = &http.Server{
		Addr:         s.cfg.Server.Host + ":" + s.cfg.VPN.OpenConnectPort,
		Handler:      customHandler,
		TLSConfig:    tlsConfig,
		ErrorLog:     errorLogger,
		ReadTimeout:  100 * time.Second, // 参考 anylink：100 秒
		WriteTimeout: 100 * time.Second, // 参考 anylink：100 秒
		// 注意：anylink 没有设置 IdleTimeout，使用默认值
	}

	go func() {
		log.Printf("HTTPS server (OpenConnect) starting on %s:%s", s.cfg.Server.Host, s.cfg.VPN.OpenConnectPort)
		log.Printf("Using default certificates: %s, %s", s.cfg.VPN.CertFile, s.cfg.VPN.KeyFile)
		log.Printf("SNI (Server Name Indication) support enabled - certificates can be configured per domain")

		// 验证默认证书是否加载成功
		s.certManager.mu.RLock()
		defaultCert := s.certManager.defaultCert
		s.certManager.mu.RUnlock()

		// 严格检查证书是否加载成功
		if defaultCert == nil {
			log.Fatalf("HTTPS: FATAL - Default certificate is nil! TLS connections will fail. Please check certificate files: %s, %s",
				s.cfg.VPN.CertFile, s.cfg.VPN.KeyFile)
		}

		// 验证证书链是否有效
		if len(defaultCert.Certificate) == 0 {
			log.Fatalf("HTTPS: FATAL - Default certificate chain is empty! Please check certificate file: %s",
				s.cfg.VPN.CertFile)
		}

		// 验证私钥是否有效
		if defaultCert.PrivateKey == nil {
			log.Fatalf("HTTPS: FATAL - Default certificate private key is nil! Please check key file: %s",
				s.cfg.VPN.KeyFile)
		}

		log.Printf("HTTPS: Default certificate verified - Chain length: %d, Has private key: %v",
			len(defaultCert.Certificate), defaultCert.PrivateKey != nil)

		// 参考 anylink：使用 ServeTLS 启动 HTTPS 服务器
		// 注意：certFile 和 keyFile 传入空字符串，因为证书通过 GetCertificate 回调提供
		addr := s.cfg.Server.Host + ":" + s.cfg.VPN.OpenConnectPort
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("HTTPS: Failed to listen on %s: %v", addr, err)
		}

		log.Printf("HTTPS: Listening on %s", addr)

		// 直接使用原始 listener，不包装
		// 包装 listener 可能会干扰 TLS 握手过程，导致连接重置
		// 这与 anylink 的实现保持一致
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

// startCustomVPNServer 已移除，不再使用自定义协议

// waitForShutdown 等待关闭信号
func (s *Server) waitForShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// 通知所有后台 goroutine 停止（包括审计日志刷新器）
	s.cancel()

	// 优雅关闭
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 关闭 HTTP 服务器
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			log.Printf("HTTP server forced to shutdown: %v", err)
		}
	}

	// 关闭 HTTPS 服务器
	if s.httpsServer != nil {
		if err := s.httpsServer.Shutdown(ctx); err != nil {
			log.Printf("HTTPS server forced to shutdown: %v", err)
		}
	}

	// 关闭 VPN 服务器
	if err := s.vpnServer.Stop(); err != nil {
		log.Printf("VPN server shutdown error: %v", err)
	}

	log.Println("Server exited")
	close(s.shutdownComplete)
}

// AddSNICert 为指定 SNI 域名添加证书（公开方法，可用于动态添加证书）
// 示例用法：
//
//	server.AddSNICert("vpn1.example.com", "/path/to/cert1.pem", "/path/to/key1.pem")
//	server.AddSNICert("*.example.com", "/path/to/wildcard.pem", "/path/to/wildcard.key")
func (s *Server) AddSNICert(sni string, certFile, keyFile string) error {
	return s.certManager.AddCert(sni, certFile, keyFile)
}

// AddSNICertFromBytes 从字节数据添加 SNI 证书（用于 API 上传）
func (s *Server) AddSNICertFromBytes(sni string, certBytes, keyBytes []byte) error {
	return s.certManager.AddCertFromBytes(sni, certBytes, keyBytes)
}

// RemoveSNICert 删除指定 SNI 域名的证书
func (s *Server) RemoveSNICert(sni string) error {
	return s.certManager.RemoveCert(sni)
}

// GetSNICerts 获取所有 SNI 证书列表
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

// GetDefaultCert 获取默认证书信息
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

// UpdateDefaultCert 更新默认证书
func (s *Server) UpdateDefaultCert(certFile, keyFile string) error {
	return s.certManager.LoadDefaultCert(certFile, keyFile)
}

// UpdateDefaultCertFromBytes 从字节数据更新默认证书（仅更新内存）
func (s *Server) UpdateDefaultCertFromBytes(certBytes, keyBytes []byte) error {
	return s.certManager.LoadDefaultCertFromBytes(certBytes, keyBytes)
}

// UpdateDefaultCertFromBytesAndSave 从字节数据更新默认证书并保存到配置文件路径（参考 anylink）
func (s *Server) UpdateDefaultCertFromBytesAndSave(certBytes, keyBytes []byte) error {
	// 参考 anylink：保存到配置文件指定的路径
	certFile := s.cfg.VPN.CertFile
	keyFile := s.cfg.VPN.KeyFile

	// 保存证书文件
	if err := os.WriteFile(certFile, certBytes, 0600); err != nil {
		return fmt.Errorf("failed to save certificate file: %w", err)
	}

	// 保存私钥文件
	if err := os.WriteFile(keyFile, keyBytes, 0600); err != nil {
		return fmt.Errorf("failed to save key file: %w", err)
	}

	// 重新加载证书到内存
	return s.certManager.LoadDefaultCert(certFile, keyFile)
}

// connectionLoggingListener 包装 net.Listener，记录所有连接
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
	// 立即输出日志，不缓冲
	// 注意：Local 地址显示的是容器内部地址（如 172.27.0.3:443），这是正常的
	// Docker 端口映射（-p 443:443）在宿主机和容器之间进行，容器内部看到的仍然是容器网络
	// Remote 地址是真实的客户端地址，这才是重要的
	log.Printf("TLS: New TCP connection established - Remote: %s, Local: %s (container internal address)", remoteAddr, localAddr)

	// 检查连接类型
	if _, ok := conn.(*net.TCPConn); ok {
		log.Printf("TLS: Connection type: TCP")
	}

	os.Stderr.Sync() // 强制刷新日志

	// 参考 anylink：不包装连接，直接返回原始连接
	// 包装连接会干扰 TLS 握手过程，导致客户端在握手阶段主动关闭连接
	// 注意：不要在 Accept 阶段设置 TCP keepalive，这会干扰 TLS 握手
	// TCP keepalive is handled by the HTTP server automatically
	return conn, nil
}

// loggingConn 包装 net.Conn，记录连接关闭事件
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

// Write 记录写入错误
func (c *loggingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if err != nil {
		log.Printf("TLS: Write error to %s: %v", c.remoteAddr, err)
		os.Stderr.Sync()
	}
	return n, err
}

// Read 记录读取错误
func (c *loggingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil && !c.closed {
		// 对于超时错误，使用更温和的日志级别
		// 这可能是 IdleTimeout 触发的（正常行为）或认证阶段的超时
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("TLS: Read timeout from %s (this is normal if IdleTimeout is reached or during authentication)", c.remoteAddr)
		} else {
			log.Printf("TLS: Read error from %s: %v", c.remoteAddr, err)
		}
		os.Stderr.Sync()
	}
	return n, err
}


package openconnect

import (
	"encoding/json"
	"net"
	"strings"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/models"
)

// getDNSServers 从用户策略获取DNS服务器列表
func getDNSServers(policy *models.Policy) []string {
	if policy == nil || policy.DNSServers == "" {
		return []string{}
	}

	// 尝试解析为JSON数组
	var dnsServers []string
	err := json.Unmarshal([]byte(policy.DNSServers), &dnsServers)
	if err == nil {
		return dnsServers
	}

	// 如果JSON解析失败，尝试按逗号分割
	return strings.Split(policy.DNSServers, ",")
}

// getCompressionType 获取压缩类型（用于CSTP配置）
func getCompressionType(cfg *config.Config) string {
	if !cfg.VPN.EnableCompression {
		return "none"
	}

	compressionType := cfg.VPN.CompressionType
	if compressionType == "" {
		return "none"
	}

	// OpenConnect支持的压缩类型：none, lz4, vj
	// 我们支持lz4和gzip，但OpenConnect只支持lz4和vj
	// 所以gzip映射为none（或者我们可以只支持lz4）
	switch compressionType {
	case "lz4":
		return "lz4"
	case "gzip":
		// OpenConnect不支持gzip，使用lz4作为替代
		return "lz4"
	default:
		return "none"
	}
}

// getDTLSConfig 获取 DTLS 配置（用于CSTP配置）
// 注意：OpenConnect 客户端需要完整的 DTLS 配置，包括 host 和 port
// clientHost 是客户端实际连接的主机地址（来自 HTTP 请求的 Host 头）
func getDTLSConfig(cfg *config.Config, clientHost string) string {
	if !cfg.VPN.EnableDTLS {
		return "<cstp:dtls-enabled>false</cstp:dtls-enabled>"
	}

	// DTLS 启用，端口使用与 TCP 相同的端口（OpenConnect 默认行为）
	// 需要显式指定 dtls-host 和 dtls-port，否则客户端可能无法建立 DTLS 连接
	dtlsPort := cfg.VPN.OpenConnectPort

	// 如果 clientHost 包含端口，只保留主机部分
	if colonPos := strings.Index(clientHost, ":"); colonPos != -1 {
		clientHost = clientHost[:colonPos]
	}

	// 构建完整的 DTLS 配置
	dtlsConfig := "\n\t\t<cstp:dtls-enabled>true</cstp:dtls-enabled>"
	dtlsConfig += "\n\t\t<cstp:dtls-host>" + clientHost + "</cstp:dtls-host>"
	dtlsConfig += "\n\t\t<cstp:dtls-port>" + dtlsPort + "</cstp:dtls-port>"

	return dtlsConfig
}

// isPublicDNS 判断DNS服务器是否是公网DNS
// 常见的公网DNS：8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1, 114.114.114.114等
func isPublicDNS(dnsIP string) bool {
	ip := net.ParseIP(dnsIP)
	if ip == nil {
		return false
	}

	// 常见的公网DNS服务器IP
	publicDNSServers := []string{
		"8.8.8.8",         // Google DNS
		"8.8.4.4",         // Google DNS
		"1.1.1.1",         // Cloudflare DNS
		"1.0.0.1",         // Cloudflare DNS
		"114.114.114.114", // 114 DNS
		"223.5.5.5",       // 阿里DNS
		"119.29.29.29",    // 腾讯DNS
	}

	for _, publicDNS := range publicDNSServers {
		if ip.Equal(net.ParseIP(publicDNS)) {
			return true
		}
	}

	// 判断是否是私有IP地址（RFC 1918）
	// 如果不是私有IP，且不在已知公网DNS列表中，也认为是公网DNS
	if ip.To4() != nil {
		// 私有IP范围：
		// 10.0.0.0/8
		// 172.16.0.0/12
		// 192.168.0.0/16
		if !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return true
		}
	}

	return false
}

// shouldTunnelAllDNS 判断是否应该让所有DNS查询走VPN
// 如果启用了DNS拦截器，可以设置Tunnel-All-DNS为false
// 因为DNS拦截器（VPN网关IP）在VPN网络中，已经在split-include路由中，会自动走VPN
// 而公网DNS不在split-include路由中，不会走VPN，这样既能保证DNS拦截器工作，又能优化性能
// 如果未启用DNS拦截器，所有DNS都不走VPN
func shouldTunnelAllDNS(hasDNSInterceptor bool, dnsServers []string) bool {
	// 如果启用了DNS拦截器，设置Tunnel-All-DNS为false
	// DNS拦截器（VPN网关IP）在VPN网络中，已经在split-include路由中
	// 客户端访问DNS拦截器时会自动走VPN，DNS拦截器可以正常工作
	// 公网DNS不在split-include路由中，不会走VPN，减少延迟
	if hasDNSInterceptor {
		return false
	}

	// 如果未启用DNS拦截器，所有DNS都不走VPN
	return false
}

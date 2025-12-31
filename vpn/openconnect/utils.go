package openconnect

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
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
	clientHost = extractHostname(clientHost)

	// 构建完整的 DTLS 配置（增强版本）
	dtlsConfig := "\n\t\t<cstp:dtls-enabled>true</cstp:dtls-enabled>"
	dtlsConfig += "\n\t\t<cstp:dtls-host>" + clientHost + "</cstp:dtls-host>"
	dtlsConfig += "\n\t\t<cstp:dtls-port>" + dtlsPort + "</cstp:dtls-port>"

	// 新增：添加MTU配置（与CSTP保持一致）
	dtlsConfig += "\n\t\t<cstp:dtls-mtu>" + strconv.Itoa(cfg.VPN.MTU) + "</cstp:dtls-mtu>"

	// 新增：添加超时和保活配置（与 CSTP 保持一致）
	cstpKeepalive := cfg.VPN.CSTPKeepalive
	if cstpKeepalive == 0 {
		cstpKeepalive = 20 // 默认值：20秒（AnyConnect 标准）
	}
	cstpDPD := cfg.VPN.CSTPDPD
	if cstpDPD == 0 {
		cstpDPD = 30 // 默认值：30秒
	}
	dtlsConfig += "\n\t\t<cstp:dtls-keepalive>" + strconv.Itoa(cstpKeepalive) + "</cstp:dtls-keepalive>"
	dtlsConfig += "\n\t\t<cstp:dtls-dpd>" + strconv.Itoa(cstpDPD) + "</cstp:dtls-dpd>"

	// 优化：添加重传和握手超时配置（减少超时时间以加快连接速度）
	// 减少重传超时和握手超时可以加快DTLS连接建立速度
	dtlsConfig += "\n\t\t<cstp:dtls-retrans-timeout>30</cstp:dtls-retrans-timeout>"
	dtlsConfig += "\n\t\t<cstp:dtls-handshake-timeout>15</cstp:dtls-handshake-timeout>"

	// 新增：添加压缩配置（与CSTP一致）
	dtlsConfig += "\n\t\t<cstp:dtls-compression>" + getCompressionType(cfg) + "</cstp:dtls-compression>"

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

// getUserTunnelMode 获取用户的隧道模式（默认 split）
func getUserTunnelMode(user *models.User) string {
	tunnelMode := user.TunnelMode
	if tunnelMode == "" {
		tunnelMode = "split" // 默认分隧道模式
	}
	return tunnelMode
}

// extractHostname 从 Host header 中提取主机名（去掉端口）
func extractHostname(host string) string {
	if colonPos := strings.Index(host, ":"); colonPos != -1 {
		return host[:colonPos]
	}
	return host
}

// shouldTunnelAllDNS 判断是否应该让所有DNS查询走VPN
// tunnelMode: 用户的隧道模式（split 或 full）
// 全局模式下，所有DNS都应该走VPN，所以Tunnel-All-DNS应该为true
func shouldTunnelAllDNS(tunnelMode string) bool {
	// 全局模式：所有流量都走 VPN，DNS 也应该走 VPN
	if tunnelMode == "full" {
		return true
	}

	// 分隧道模式：DNS不走VPN，使用直接连接
	return false
}

// getLocalNetworkRoutes 获取常见的本地网络路由（私有IP地址段）
// 这些路由应该在全局模式下被排除，确保本地网络流量不走VPN
// 参考 RFC 1918 私有IP地址范围
func getLocalNetworkRoutes() []string {
	return []string{
		"10.0.0.0/8",     // 10.0.0.0 - 10.255.255.255
		"172.16.0.0/12",  // 172.16.0.0 - 172.31.255.255
		"192.168.0.0/16", // 192.168.0.0 - 192.168.255.255
		"169.254.0.0/16", // 169.254.0.0 - 169.254.255.255 (Link-local)
		"127.0.0.0/8",    // 127.0.0.0 - 127.255.255.255 (Loopback)
		"224.0.0.0/4",    // 224.0.0.0 - 239.255.255.255 (Multicast)
		"240.0.0.0/4",    // 240.0.0.0 - 255.255.255.255 (Reserved)
	}
}

// isPrivateNetwork 检查给定的CIDR是否是私有网络
func isPrivateNetwork(cidr string) bool {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	// 检查IP是否是私有IP地址（使用标准库方法）
	if ip.To4() != nil {
		// IPv4: 检查是否是私有IP
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return true
		}
		// 检查是否是组播或保留地址
		if ip[0] >= 224 {
			return true
		}
	}

	// 额外检查：与已知的私有网络段进行比较
	localRoutes := getLocalNetworkRoutes()
	for _, localRoute := range localRoutes {
		_, localNet, err := net.ParseCIDR(localRoute)
		if err != nil {
			continue
		}
		// 检查两个网络是否有重叠
		// 如果 ipNet 包含 localNet 的起始IP，或者 localNet 包含 ipNet 的起始IP，则认为重叠
		if ipNet.Contains(localNet.IP) || localNet.Contains(ipNet.IP) {
			return true
		}
	}

	return false
}

// getServerVPNIP 从VPN网络CIDR计算服务器VPN IP（通常是.1）
// 这是后端验证的关键：无论客户端如何配置，服务端都使用这个IP进行验证
func getServerVPNIP(ipNet *net.IPNet) net.IP {
	serverVPNIP := make(net.IP, len(ipNet.IP))
	copy(serverVPNIP, ipNet.IP)
	serverVPNIP[len(serverVPNIP)-1] = 1
	return serverVPNIP
}

// parseVPNNetwork 解析VPN网络配置，返回IPNet和错误
// 这是后端验证的关键：统一解析VPN网络，确保验证逻辑一致
func parseVPNNetwork(vpnNetwork string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(vpnNetwork)
	return ipNet, err
}

// isVPNInternalTraffic 判断是否是VPN内部流量（客户端到客户端或客户端到服务器）
// 这是后端验证的关键：VPN内部流量必须进行完整的策略检查
func isVPNInternalTraffic(srcIP, dstIP net.IP, ipNet *net.IPNet) bool {
	return ipNet.Contains(srcIP) && ipNet.Contains(dstIP)
}

// ErrUnsupportedIPVersion 表示不支持的IP版本（用于IPv6等）
type ErrUnsupportedIPVersion struct {
	Version int
}

func (e *ErrUnsupportedIPVersion) Error() string {
	return fmt.Sprintf("unsupported IP version: %d (only IPv4 supported)", e.Version)
}

// IsUnsupportedIPVersion 检查错误是否是IPv6等不支持的IP版本
func IsUnsupportedIPVersion(err error) bool {
	_, ok := err.(*ErrUnsupportedIPVersion)
	return ok
}

// validateIPPacket 验证IP数据包的基本格式
// 这是后端验证的关键：确保数据包格式正确，防止恶意数据包
func validateIPPacket(packet []byte) error {
	if len(packet) < 20 {
		return fmt.Errorf("packet too small: %d bytes (minimum 20)", len(packet))
	}

	// 检查IP版本
	ipVersion := packet[0] >> 4
	if ipVersion != 4 {
		return &ErrUnsupportedIPVersion{Version: int(ipVersion)}
	}

	// 检查IP头长度（IHL）
	ihl := int(packet[0] & 0x0F)
	if ihl < 5 {
		return fmt.Errorf("invalid IP header length: %d (minimum 5)", ihl)
	}

	// 检查数据包总长度
	expectedLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if expectedLen < 20 || expectedLen > len(packet) {
		return fmt.Errorf("invalid packet length: expected %d, got %d", expectedLen, len(packet))
	}

	return nil
}

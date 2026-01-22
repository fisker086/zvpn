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

func getDNSServers(policy *models.Policy) []string {
	if policy == nil || policy.DNSServers == "" {
		return []string{}
	}

	var dnsServers []string
	err := json.Unmarshal([]byte(policy.DNSServers), &dnsServers)
	if err == nil {
		return dnsServers
	}

	return strings.Split(policy.DNSServers, ",")
}

// getSplitDNSDomains 获取 Split-DNS 域名列表
func getSplitDNSDomains(policy *models.Policy) []string {
	if policy == nil || policy.SplitDNS == "" {
		return []string{}
	}

	var domains []string
	err := json.Unmarshal([]byte(policy.SplitDNS), &domains)
	if err == nil {
		return domains
	}

	// 如果 JSON 解析失败，尝试按逗号分割
	return strings.Split(policy.SplitDNS, ",")
}

func getCompressionType(cfg *config.Config) string {
	if !cfg.VPN.EnableCompression {
		return "none"
	}

	compressionType := cfg.VPN.CompressionType
	if compressionType == "" {
		return "none"
	}

	switch compressionType {
	case "lz4":
		return "lz4"
	case "gzip":
		return "lz4"
	default:
		return "none"
	}
}

func getDTLSConfig(cfg *config.Config, clientHost string, isMobile bool) string {
	if !cfg.VPN.EnableDTLS {
		return "<cstp:dtls-enabled>false</cstp:dtls-enabled>"
	}

	dtlsPort := cfg.VPN.OpenConnectPort

	clientHost = extractHostname(clientHost)

	dtlsConfig := "\n\t\t<cstp:dtls-enabled>true</cstp:dtls-enabled>"
	dtlsConfig += "\n\t\t<cstp:dtls-host>" + clientHost + "</cstp:dtls-host>"
	dtlsConfig += "\n\t\t<cstp:dtls-port>" + dtlsPort + "</cstp:dtls-port>"

	dtlsConfig += "\n\t\t<cstp:dtls-mtu>" + strconv.Itoa(cfg.VPN.MTU) + "</cstp:dtls-mtu>"

	// 根据移动端或PC端使用不同的配置
	var keepalive, dpd int
	if isMobile {
		keepalive = cfg.VPN.MobileKeepalive
		if keepalive == 0 {
			keepalive = 4
		}
		dpd = cfg.VPN.MobileDPD
		if dpd == 0 {
			dpd = 60
		}
	} else {
		keepalive = cfg.VPN.CSTPKeepalive
		if keepalive == 0 {
			keepalive = 20
		}
		dpd = cfg.VPN.CSTPDPD
		if dpd == 0 {
			dpd = 30
		}
	}
	dtlsConfig += "\n\t\t<cstp:dtls-keepalive>" + strconv.Itoa(keepalive) + "</cstp:dtls-keepalive>"
	dtlsConfig += "\n\t\t<cstp:dtls-dpd>" + strconv.Itoa(dpd) + "</cstp:dtls-dpd>"

	dtlsConfig += "\n\t\t<cstp:dtls-retrans-timeout>30</cstp:dtls-retrans-timeout>"
	dtlsConfig += "\n\t\t<cstp:dtls-handshake-timeout>15</cstp:dtls-handshake-timeout>"

	dtlsConfig += "\n\t\t<cstp:dtls-compression>" + getCompressionType(cfg) + "</cstp:dtls-compression>"

	return dtlsConfig
}

func getUserTunnelMode(user *models.User) string {
	tunnelMode := user.TunnelMode
	if tunnelMode == "" {
		tunnelMode = "split"
	}
	return tunnelMode
}

func extractHostname(host string) string {
	if colonPos := strings.Index(host, ":"); colonPos != -1 {
		return host[:colonPos]
	}
	return host
}

// isPrivateIP 判断IP是否是私有IP地址
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}
	// 10.0.0.0/8
	if ipv4[0] == 10 {
		return true
	}
	// 172.16.0.0/12
	if ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31 {
		return true
	}
	// 192.168.0.0/16
	if ipv4[0] == 192 && ipv4[1] == 168 {
		return true
	}
	return false
}

// getDNSServerNetwork 获取DNS服务器所在的网段（通常是/24）
func getDNSServerNetwork(dnsIP net.IP) string {
	if dnsIP == nil {
		return ""
	}
	ipv4 := dnsIP.To4()
	if ipv4 == nil {
		return ""
	}
	// 对于私有IP，返回 /24 网段
	if isPrivateIP(ipv4) {
		return fmt.Sprintf("%d.%d.%d.0/24", ipv4[0], ipv4[1], ipv4[2])
	}
	return ""
}

// containsSubnet 检查子网 sub 是否完全包含在子网 super 中
func containsSubnet(super, sub *net.IPNet) bool {
	// 检查 super 是否包含 sub 的起始IP
	if !super.Contains(sub.IP) {
		return false
	}
	// 检查 super 是否包含 sub 的结束IP
	// 计算 sub 的广播地址（最后一个IP）
	_, subBits := sub.Mask.Size()
	if subBits != 32 {
		return false // 只支持IPv4
	}
	// 计算子网中的最后一个IP
	subLastIP := make(net.IP, len(sub.IP))
	copy(subLastIP, sub.IP)
	for i := 0; i < 4; i++ {
		subLastIP[i] |= ^sub.Mask[i]
	}
	// 检查 super 是否包含 sub 的最后一个IP
	return super.Contains(subLastIP)
}

// optimizeRoutes 优化路由列表，去除重复和包含的子网
// 如果一个大子网包含了小子网，只保留大子网
// 如果两个子网完全相同，只保留一个
func optimizeRoutes(routes []string) []string {
	if len(routes) == 0 {
		return routes
	}

	// 解析所有路由为 IPNet
	type routeInfo struct {
		original string
		ipNet    *net.IPNet
	}
	routeInfos := make([]routeInfo, 0, len(routes))
	for _, route := range routes {
		_, ipNet, err := net.ParseCIDR(route)
		if err != nil {
			// 无效路由，跳过
			continue
		}
		routeInfos = append(routeInfos, routeInfo{
			original: route,
			ipNet:    ipNet,
		})
	}

	if len(routeInfos) == 0 {
		return []string{}
	}

	// 优化：移除被包含的子网
	optimized := make([]routeInfo, 0)
	for i, ri := range routeInfos {
		shouldKeep := true
		for j, rj := range routeInfos {
			if i == j {
				continue
			}
			// 检查掩码大小：掩码位数越小，子网越大
			riMaskSize, _ := ri.ipNet.Mask.Size()
			rjMaskSize, _ := rj.ipNet.Mask.Size()

			// 如果 rj 完全包含 ri，且 rj 更大（掩码更小），则移除 ri
			if rjMaskSize < riMaskSize && containsSubnet(rj.ipNet, ri.ipNet) {
				shouldKeep = false
				break
			}
			// 如果完全相同，只保留第一个
			if rjMaskSize == riMaskSize && ri.ipNet.IP.Equal(rj.ipNet.IP) && i > j {
				shouldKeep = false
				break
			}
		}
		if shouldKeep {
			optimized = append(optimized, ri)
		}
	}

	// 转换为字符串数组
	result := make([]string, 0, len(optimized))
	for _, ri := range optimized {
		result = append(result, ri.original)
	}

	return result
}

func getServerVPNIP(ipNet *net.IPNet) net.IP {
	serverVPNIP := make(net.IP, len(ipNet.IP))
	copy(serverVPNIP, ipNet.IP)
	serverVPNIP[len(serverVPNIP)-1] = 1
	return serverVPNIP
}

func parseVPNNetwork(vpnNetwork string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(vpnNetwork)
	return ipNet, err
}

// parseRouteNetwork 解析路由网络，支持 CIDR 格式（如 172.21.0.0/24）和子网掩码格式（如 172.21.0.0/255.255.255.0）
// 返回规范化后的 CIDR 格式和 IPNet
func parseRouteNetwork(route string) (string, *net.IPNet, error) {
	// 先尝试直接解析 CIDR 格式
	_, ipNet, err := net.ParseCIDR(route)
	if err == nil {
		// 成功解析，返回规范化格式
		return ipNet.String(), ipNet, nil
	}

	// 如果失败，尝试解析子网掩码格式（如 172.21.0.0/255.255.255.0）
	parts := strings.Split(route, "/")
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("invalid route format: %s", route)
	}

	ipStr := strings.TrimSpace(parts[0])
	maskStr := strings.TrimSpace(parts[1])

	// 检查是否是子网掩码格式（包含点）
	if strings.Contains(maskStr, ".") {
		// 解析 IP 地址
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return "", nil, fmt.Errorf("invalid IP address: %s", ipStr)
		}
		ipv4 := ip.To4()
		if ipv4 == nil {
			return "", nil, fmt.Errorf("not an IPv4 address: %s", ipStr)
		}

		// 解析子网掩码
		maskIP := net.ParseIP(maskStr)
		if maskIP == nil {
			return "", nil, fmt.Errorf("invalid subnet mask: %s", maskStr)
		}
		maskIPv4 := maskIP.To4()
		if maskIPv4 == nil {
			return "", nil, fmt.Errorf("not an IPv4 subnet mask: %s", maskStr)
		}

		// 将子网掩码转换为 net.IPMask
		mask := net.IPMask(maskIPv4)

		// 验证掩码大小（IPv4 应该是 32 位）
		_, bits := mask.Size()
		if bits != 32 {
			return "", nil, fmt.Errorf("invalid IPv4 mask size: %d", bits)
		}

		// 创建 IPNet
		ipNet = &net.IPNet{
			IP:   ipv4,
			Mask: mask,
		}

		// 规范化网络地址（确保 IP 是网络地址）
		ipNet.IP = ipNet.IP.Mask(mask)

		// 返回 CIDR 格式
		return ipNet.String(), ipNet, nil
	}

	// 如果既不是 CIDR 也不是子网掩码格式，返回错误
	return "", nil, fmt.Errorf("invalid route format: %s (expected CIDR like 172.21.0.0/24 or subnet mask like 172.21.0.0/255.255.255.0)", route)
}

// convertCIDRToSubnetMask 将 CIDR 格式转换为子网掩码格式
// 例如：14.114.114.114/32 -> 14.114.114.114/255.255.255.255
// 这是 OpenConnect/AnyConnect 协议的标准格式
func convertCIDRToSubnetMask(cidr string) string {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return cidr // 如果格式不对，返回原值
	}

	ipStr := strings.TrimSpace(parts[0])
	maskBitsStr := strings.TrimSpace(parts[1])

	// 如果已经是子网掩码格式（包含点），直接返回
	if strings.Contains(maskBitsStr, ".") {
		return cidr
	}

	// 解析 CIDR 位数
	maskBits, err := strconv.Atoi(maskBitsStr)
	if err != nil {
		return cidr // 如果解析失败，返回原值
	}

	// 将 CIDR 位数转换为子网掩码
	mask := net.CIDRMask(maskBits, 32)
	if mask == nil {
		return cidr // 如果转换失败，返回原值
	}

	// 格式化为子网掩码字符串
	maskStr := net.IP(mask).String()
	return ipStr + "/" + maskStr
}

func isVPNInternalTraffic(srcIP, dstIP net.IP, ipNet *net.IPNet) bool {
	return ipNet.Contains(srcIP) && ipNet.Contains(dstIP)
}

type ErrUnsupportedIPVersion struct {
	Version int
}

func (e *ErrUnsupportedIPVersion) Error() string {
	return fmt.Sprintf("unsupported IP version: %d (only IPv4 supported)", e.Version)
}

func IsUnsupportedIPVersion(err error) bool {
	_, ok := err.(*ErrUnsupportedIPVersion)
	return ok
}

func validateIPPacket(packet []byte) error {
	if len(packet) < 20 {
		return fmt.Errorf("packet too small: %d bytes (minimum 20)", len(packet))
	}

	ipVersion := packet[0] >> 4
	if ipVersion != 4 {
		return &ErrUnsupportedIPVersion{Version: int(ipVersion)}
	}

	ihl := int(packet[0] & 0x0F)
	if ihl < 5 {
		return fmt.Errorf("invalid IP header length: %d (minimum 5)", ihl)
	}

	expectedLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if expectedLen < 20 || expectedLen > len(packet) {
		return fmt.Errorf("invalid packet length: expected %d, got %d", expectedLen, len(packet))
	}

	return nil
}


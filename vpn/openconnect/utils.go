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

func shouldTunnelAllDNS(tunnelMode string) bool {
	return tunnelMode == "full"
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

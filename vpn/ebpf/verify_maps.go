//go:build ebpf
// +build ebpf

package ebpf

import (
	"fmt"
	"log"
	"net"
	"path/filepath"

	"github.com/cilium/ebpf"
)

const (
	// BPF pin path for shared maps between XDP and TC programs
	bpfPinPath = "/sys/fs/bpf/zvpn"
)

// getSharedMapPinPath returns the pin path for a shared map
func getSharedMapPinPath(mapName string) string {
	return filepath.Join(bpfPinPath, mapName)
}

// VerifySharedMapValues verifies that shared maps contain expected values
// This is useful for debugging map sharing between XDP and TC programs
func VerifySharedMapValues() error {
	// Check server_egress_ip map
	egressIPPath := getSharedMapPinPath("server_egress_ip")
	egressMap, err := ebpf.LoadPinnedMap(egressIPPath, nil)
	if err != nil {
		return fmt.Errorf("failed to load pinned egress IP map: %w", err)
	}
	defer egressMap.Close()

	key := uint32(0)
	var value uint32
	if err := egressMap.Lookup(key, &value); err != nil {
		return fmt.Errorf("failed to read egress IP from pinned map: %w", err)
	}

	// Convert to IP for display
	ip := net.IPv4(
		byte(value>>24),
		byte(value>>16),
		byte(value>>8),
		byte(value),
	)
	log.Printf("✅ Verified pinned map server_egress_ip: key=0, value=%s (0x%08X)", ip.String(), value)

	// Check vpn_network_config map
	vpnNetPath := getSharedMapPinPath("vpn_network_config")
	vpnNetMap, err := ebpf.LoadPinnedMap(vpnNetPath, nil)
	if err != nil {
		return fmt.Errorf("failed to load pinned VPN network config map: %w", err)
	}
	defer vpnNetMap.Close()

	// Read network address (key 0)
	netKey := uint32(0)
	var netValue uint32
	if err := vpnNetMap.Lookup(netKey, &netValue); err != nil {
		return fmt.Errorf("failed to read VPN network from pinned map: %w", err)
	}
	netIP := net.IPv4(
		byte(netValue>>24),
		byte(netValue>>16),
		byte(netValue>>8),
		byte(netValue),
	)

	// Read network mask (key 1)
	maskKey := uint32(1)
	var maskValue uint32
	if err := vpnNetMap.Lookup(maskKey, &maskValue); err != nil {
		return fmt.Errorf("failed to read VPN network mask from pinned map: %w", err)
	}
	maskIP := net.IPv4(
		byte(maskValue>>24),
		byte(maskValue>>16),
		byte(maskValue>>8),
		byte(maskValue),
	)
	log.Printf("✅ Verified pinned map vpn_network_config: network=%s (0x%08X), mask=%s (0x%08X)",
		netIP.String(), netValue, maskIP.String(), maskValue)

	return nil
}


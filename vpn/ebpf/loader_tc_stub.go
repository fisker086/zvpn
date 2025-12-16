//go:build !ebpf
// +build !ebpf

package ebpf

import (
	"fmt"
	"net"
)

// TCProgram represents an eBPF TC (Traffic Control) program for egress NAT
// Stub implementation when eBPF is not compiled
type TCProgram struct {
	ifName string
}

// LoadTCProgram loads and attaches the TC egress program to a network interface
// This is a stub implementation when eBPF is not compiled
func LoadTCProgram(ifName string) (*TCProgram, error) {
	return nil, fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// SetPublicIP sets the public IP address for NAT masquerading in TC eBPF
func (t *TCProgram) SetPublicIP(publicIP net.IP) error {
	return fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// AddVPNClient adds a VPN client IP mapping to TC eBPF map
func (t *TCProgram) AddVPNClient(vpnIP, clientIP net.IP) error {
	return fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// RemoveVPNClient removes a VPN client IP mapping from TC eBPF map
func (t *TCProgram) RemoveVPNClient(vpnIP net.IP) error {
	return fmt.Errorf("eBPF not compiled. Run: go generate ./vpn/ebpf")
}

// Close detaches and closes the TC program
func (t *TCProgram) Close() error {
	return nil
}
  

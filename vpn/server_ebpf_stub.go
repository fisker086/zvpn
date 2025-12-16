//go:build !ebpf
// +build !ebpf

package vpn

import (
	"fmt"
	"net"
)

// loadEBPFTCNATImpl loads eBPF TC program for NAT masquerading
// This is a stub implementation when eBPF is not compiled
func loadEBPFTCNATImpl(ifName string, publicIP net.IP) (interface{}, error) {
	return nil, fmt.Errorf("eBPF not compiled. Build with -tags ebpf to enable eBPF TC NAT")
}

// getTCProgram returns the TC program instance (stub)
func (s *VPNServer) getTCProgram() interface{} {
	return nil
}

// tcProgramAddVPNClient adds a VPN client to TC program (stub)
func (s *VPNServer) tcProgramAddVPNClient(vpnIP, clientIP net.IP) error {
	return nil // eBPF not compiled, skip
}

// tcProgramRemoveVPNClient removes a VPN client from TC program (stub)
func (s *VPNServer) tcProgramRemoveVPNClient(vpnIP net.IP) error {
	return nil // eBPF not compiled, skip
}

// tcProgramClose closes the TC program (stub)
func (s *VPNServer) tcProgramClose() error {
	return nil // eBPF not compiled, skip
}


//go:build ebpf
// +build ebpf

package vpn

import (
	"fmt"
	"log"
	"net"

	"github.com/fisker/zvpn/vpn/ebpf"
)

// loadEBPFTCNATImpl loads eBPF TC program for NAT masquerading
// This is the actual implementation when eBPF is compiled
func loadEBPFTCNATImpl(ifName string, publicIP net.IP, vpnNetwork string) (interface{}, error) {
	// Load TC program
	tcProg, err := ebpf.LoadTCProgram(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF TC program: %w", err)
	}

	// Set VPN network configuration
	if err := tcProg.SetVPNNetwork(vpnNetwork); err != nil {
		tcProg.Close()
		return nil, fmt.Errorf("failed to set VPN network in TC program: %w", err)
	}

	// Set public IP in TC program
	if err := tcProg.SetPublicIP(publicIP); err != nil {
		tcProg.Close()
		return nil, fmt.Errorf("failed to set public IP in TC program: %w", err)
	}

	log.Printf("✅ eBPF TC NAT: Program loaded and configured on interface %s", ifName)
	return tcProg, nil
}

// getTCProgram returns the TC program instance (type assertion helper)
func (s *VPNServer) getTCProgram() *ebpf.TCProgram {
	if s.tcProgram == nil {
		return nil
	}
	tcProg, ok := s.tcProgram.(*ebpf.TCProgram)
	if !ok {
		return nil
	}
	return tcProg
}

// tcProgramAddVPNClient adds a VPN client to TC program (type-safe wrapper)
func (s *VPNServer) tcProgramAddVPNClient(vpnIP, clientIP net.IP) error {
	tcProg := s.getTCProgram()
	if tcProg == nil {
		return nil // TC program not loaded, skip
	}
	return tcProg.AddVPNClient(vpnIP, clientIP)
}

// tcProgramRemoveVPNClient removes a VPN client from TC program (type-safe wrapper)
func (s *VPNServer) tcProgramRemoveVPNClient(vpnIP net.IP) error {
	tcProg := s.getTCProgram()
	if tcProg == nil {
		return nil // TC program not loaded, skip
	}
	return tcProg.RemoveVPNClient(vpnIP)
}

// tcProgramClose closes the TC program (type-safe wrapper)
func (s *VPNServer) tcProgramClose() error {
	tcProg := s.getTCProgram()
	if tcProg == nil {
		return nil // TC program not loaded, skip
	}
	return tcProg.Close()
}


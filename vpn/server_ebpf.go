//go:build ebpf
// +build ebpf

package vpn

import (
	"fmt"
	"log"
	"net"

	"github.com/fisker/zvpn/vpn/ebpf"
	"github.com/vishvananda/netlink"
)

// getInterfaceIP gets the first IPv4 address from the specified network interface
func getInterfaceIP(ifName string) (net.IP, error) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", ifName, err)
	}

	// Get IPv4 addresses on the interface
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("failed to list addresses on interface %s: %w", ifName, err)
	}

	// Prefer non-loopback, non-link-local addresses
	for _, addr := range addrs {
		if addr.IP != nil && addr.IP.To4() != nil {
			if !addr.IP.IsLoopback() && !addr.IP.IsLinkLocalUnicast() {
				return addr.IP, nil
			}
		}
	}

	// If no suitable address found, return the first IPv4 address
	for _, addr := range addrs {
		if addr.IP != nil && addr.IP.To4() != nil {
			return addr.IP, nil
		}
	}

	return nil, fmt.Errorf("no IPv4 address found on interface %s", ifName)
}

// loadEBPFTCNATImpl loads eBPF TC program for NAT masquerading
// This is the actual implementation when eBPF is compiled
func loadEBPFTCNATImpl(ifName string, publicIP net.IP, vpnNetwork string) (interface{}, error) {
	// Load TC program first
	tcProg, err := ebpf.LoadTCProgram(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF TC program: %w", err)
	}

	// Set VPN network configuration
	if err := tcProg.SetVPNNetwork(vpnNetwork); err != nil {
		tcProg.Close()
		return nil, fmt.Errorf("failed to set VPN network in TC program: %w", err)
	}

	// If publicIP is nil, try to get it from the interface
	if publicIP == nil {
		log.Printf("⚠️  Public IP not provided, attempting to get IP from interface %s...", ifName)
		interfaceIP, err := getInterfaceIP(ifName)
		if err != nil {
			tcProg.Close()
			return nil, fmt.Errorf("failed to get IP from interface %s: %w (public IP is required for NAT)", ifName, err)
		}
		publicIP = interfaceIP
		log.Printf("✅ Using IP from interface %s: %s", ifName, publicIP.String())
	}

	// Set public IP in TC program
	if err := tcProg.SetPublicIP(publicIP); err != nil {
		tcProg.Close()
		return nil, fmt.Errorf("failed to set public IP in TC program: %w", err)
	}

	log.Printf("✅ eBPF TC NAT: Program loaded and configured on interface %s with NAT IP %s", ifName, publicIP.String())
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


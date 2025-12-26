//go:build ebpf
// +build ebpf

package ebpf

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TCProgram represents an eBPF TC (Traffic Control) program for egress NAT
type TCProgram struct {
	objs              *tc_natObjects
	link              link.Link
	clsactLink        *clsactLink // For traditional TC clsact (when link is nil)
	ifName            string
	serverEgressIPMap *ebpf.Map
	vpnClients        *ebpf.Map
	natStats          *ebpf.Map
	vpnNetworkConfig  *ebpf.Map
}

// LoadTCProgram loads and attaches the TC egress program to a network interface
// This program performs NAT masquerading for packets from VPN clients to external networks
func LoadTCProgram(ifName string) (*TCProgram, error) {
	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load pre-compiled eBPF objects
	objs := &tc_natObjects{}
	if err := loadTc_natObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load eBPF TC objects: %w", err)
	}

	// Open network interface
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to find interface %s: %w", ifName, err)
	}

	// Attach TC egress program to interface
	// Strategy: Try TCX first (kernel 6.6+), then fallback to traditional TC clsact (kernel 4.1+)
	var tcLink link.Link

	// Try TCX first (kernel 6.6+)
	opts := link.TCXOptions{
		Program:   objs.TcNatEgress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	}
	tcLink, err = link.AttachTCX(opts)
	if err != nil {
		log.Printf("Warning: Failed to attach TC program using TCX: %v", err)
		log.Printf("TCX requires kernel 6.6+, falling back to traditional TC clsact qdisc...")

		// Fallback to traditional TC clsact qdisc using netlink (kernel 4.1+)
		clsactLink, err := attachTCClsact(ifName, iface.Index, objs.TcNatEgress)
		if err != nil {
			objs.Close()
			return nil, fmt.Errorf("failed to attach TC program: %w (tried TCX and traditional TC clsact, system will use nftables MASQUERADE as fallback)", err)
		}
		log.Printf("✅ TC egress NAT program attached using traditional TC clsact qdisc (compatible with kernel 4.1+)")
		return &TCProgram{
			objs:              objs,
			link:              nil, // No link.Link for traditional TC
			clsactLink:        clsactLink,
			ifName:            ifName,
			serverEgressIPMap: objs.ServerEgressIp,
			vpnClients:        objs.VpnClients,
			natStats:          objs.NatStats,
			vpnNetworkConfig:  objs.VpnNetworkConfig,
		}, nil
	}

	log.Printf("✅ TC egress NAT program attached using TCX (kernel 6.6+)")
	log.Printf("✅ TC egress NAT program attached to interface %s", ifName)

	return &TCProgram{
		objs:              objs,
		link:              tcLink,
		clsactLink:        nil, // Using TCX link
		ifName:            ifName,
		serverEgressIPMap: objs.ServerEgressIp,
		vpnClients:        objs.VpnClients,
		natStats:          objs.NatStats,
		vpnNetworkConfig:  objs.VpnNetworkConfig,
	}, nil
}

// SetPublicIP sets the public IP address for NAT masquerading in TC eBPF
func (t *TCProgram) SetPublicIP(publicIP net.IP) error {
	if t == nil || t.serverEgressIPMap == nil {
		return fmt.Errorf("TC program not loaded or server_egress_ip map not found")
	}

	if publicIP == nil || publicIP.To4() == nil {
		return fmt.Errorf("invalid IPv4 address")
	}

	// Convert IP to network byte order (uint32)
	ipBytes := publicIP.To4()
	ipUint32 := uint32(ipBytes[0])<<24 | uint32(ipBytes[1])<<16 | uint32(ipBytes[2])<<8 | uint32(ipBytes[3])

	// Store in map with key 0
	key := uint32(0)
	if err := t.serverEgressIPMap.Put(key, ipUint32); err != nil {
		return fmt.Errorf("failed to set egress IP in TC eBPF map: %w", err)
	}

	log.Printf("✅ TC eBPF NAT: Server egress IP set to %s", publicIP.String())
	return nil
}

// SetVPNNetwork sets the VPN network configuration in TC eBPF map
func (t *TCProgram) SetVPNNetwork(vpnNetwork string) error {
	if t == nil || t.vpnNetworkConfig == nil {
		return fmt.Errorf("TC program not loaded or vpn_network_config map not found")
	}

	// Parse VPN network CIDR
	_, ipNet, err := net.ParseCIDR(vpnNetwork)
	if err != nil {
		return fmt.Errorf("invalid VPN network CIDR: %w", err)
	}

	// Convert network address to network byte order (uint32)
	ipBytes := ipNet.IP.To4()
	if ipBytes == nil {
		return fmt.Errorf("VPN network must be IPv4")
	}
	networkUint32 := uint32(ipBytes[0])<<24 | uint32(ipBytes[1])<<16 | uint32(ipBytes[2])<<8 | uint32(ipBytes[3])

	// Convert mask to uint32
	maskBytes := ipNet.Mask
	maskUint32 := uint32(maskBytes[0])<<24 | uint32(maskBytes[1])<<16 | uint32(maskBytes[2])<<8 | uint32(maskBytes[3])

	// Store network address (key 0)
	key := uint32(0)
	if err := t.vpnNetworkConfig.Put(key, networkUint32); err != nil {
		return fmt.Errorf("failed to set VPN network address in TC eBPF map: %w", err)
	}

	// Store network mask (key 1)
	key = 1
	if err := t.vpnNetworkConfig.Put(key, maskUint32); err != nil {
		return fmt.Errorf("failed to set VPN network mask in TC eBPF map: %w", err)
	}

	log.Printf("✅ TC eBPF NAT: VPN network configured: %s (network: 0x%08X, mask: 0x%08X)", vpnNetwork, networkUint32, maskUint32)
	return nil
}

// AddVPNClient adds a VPN client IP mapping to TC eBPF map
func (t *TCProgram) AddVPNClient(vpnIP, clientIP net.IP) error {
	if t == nil || t.vpnClients == nil {
		return fmt.Errorf("TC program not loaded")
	}

	vpnIPUint32 := ipToUint32(vpnIP)
	clientIPUint32 := ipToUint32(clientIP)

	if err := t.vpnClients.Put(vpnIPUint32, clientIPUint32); err != nil {
		return fmt.Errorf("failed to add VPN client mapping to TC eBPF map: %w", err)
	}

	return nil
}

// RemoveVPNClient removes a VPN client IP mapping from TC eBPF map
func (t *TCProgram) RemoveVPNClient(vpnIP net.IP) error {
	if t == nil || t.vpnClients == nil {
		return fmt.Errorf("TC program not loaded")
	}

	vpnIPUint32 := ipToUint32(vpnIP)
	if err := t.vpnClients.Delete(vpnIPUint32); err != nil {
		return fmt.Errorf("failed to remove VPN client mapping from TC eBPF map: %w", err)
	}

	return nil
}

// Close detaches and closes the TC program
func (t *TCProgram) Close() error {
	var errs []error

	if t.link != nil {
		if err := t.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close TC link: %w", err))
		}
	}

	if t.clsactLink != nil {
		if err := t.clsactLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close clsact link: %w", err))
		}
	}

	if t.objs != nil {
		if err := t.objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close TC eBPF objects: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during TC close: %v", errs)
	}

	return nil
}

// GetNATStats returns the NAT statistics from the eBPF map
func (t *TCProgram) GetNATStats() (map[uint32]uint64, error) {
	if t == nil || t.natStats == nil {
		return nil, fmt.Errorf("TC program not loaded or stats map not found")
	}

	stats := make(map[uint32]uint64)
	// Read all stat keys (0-9)
	for i := uint32(0); i < 10; i++ {
		var value uint64
		if err := t.natStats.Lookup(i, &value); err == nil {
			stats[i] = value
		}
	}

	return stats, nil
}

// LogNATStats logs the NAT statistics for debugging
func (t *TCProgram) LogNATStats() {
	if stats, err := t.GetNATStats(); err == nil {
		log.Printf("TC NAT Stats: Total=%d, VPNNetworkCheck=%d, VPNClientFound=%d, EgressIPFound=%d, NATPerformed=%d",
			stats[4], stats[1], stats[2], stats[3], stats[0])
	}
}

// attachTCClsact attaches eBPF program to interface using traditional TC clsact qdisc
// This works on kernels 4.1+ (including 6.1) that don't support TCX
// Returns a clsactLink (not a full link.Link implementation due to unexported methods)
func attachTCClsact(ifName string, ifIndex int, prog *ebpf.Program) (*clsactLink, error) {
	// Get program file descriptor
	progFD := prog.FD()
	if progFD < 0 {
		return nil, fmt.Errorf("invalid program FD")
	}

	// Create clsact qdisc using GenericQdisc
	// clsact qdisc: handle ffff:0, parent ffff:fff1
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifIndex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	// Try to add clsact qdisc (ignore error if it already exists)
	if err := netlink.QdiscAdd(qdisc); err != nil {
		// Check if qdisc already exists
		if os.IsExist(err) {
			log.Printf("Clsact qdisc already exists on interface %s", ifName)
		} else {
			return nil, fmt.Errorf("failed to create clsact qdisc: %w", err)
		}
	} else {
		log.Printf("Created clsact qdisc on interface %s", ifName)
	}

	// Create filter to attach eBPF program to egress hook
	// For clsact, egress hook uses parent HANDLE_MIN_EGRESS
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifIndex,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           progFD,
		Name:         "tc_nat_egress",
		DirectAction: true, // Enable direct action mode for eBPF
	}

	// Add filter (attach eBPF program)
	if err := netlink.FilterAdd(filter); err != nil {
		// Clean up qdisc if filter add fails
		netlink.QdiscDel(qdisc)
		return nil, fmt.Errorf("failed to attach eBPF program to clsact qdisc: %w", err)
	}

	log.Printf("Attached eBPF program to clsact qdisc egress hook on interface %s", ifName)

	// Create a custom link type to handle cleanup
	return &clsactLink{
		ifName:  ifName,
		ifIndex: ifIndex,
		filter:  filter,
		qdisc:   qdisc,
		prog:    prog,
	}, nil
}

// clsactLink represents a traditional TC clsact qdisc attachment
// Note: This does not implement link.Link interface due to unexported methods,
// but provides cleanup functionality for traditional TC attachments
type clsactLink struct {
	ifName  string
	ifIndex int
	filter  *netlink.BpfFilter
	qdisc   *netlink.GenericQdisc
	prog    *ebpf.Program
}

// Close detaches and removes the TC clsact qdisc and filter
func (l *clsactLink) Close() error {
	var errs []error

	// Remove filter
	if l.filter != nil {
		if err := netlink.FilterDel(l.filter); err != nil {
			errs = append(errs, fmt.Errorf("failed to remove filter: %w", err))
		}
	}

	// Remove qdisc (this will also remove all filters)
	if l.qdisc != nil {
		if err := netlink.QdiscDel(l.qdisc); err != nil {
			errs = append(errs, fmt.Errorf("failed to remove qdisc: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during clsact link close: %v", errs)
	}

	return nil
}

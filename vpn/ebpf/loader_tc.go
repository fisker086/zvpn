//go:build ebpf
// +build ebpf

package ebpf

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

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

	// Try to load shared maps from XDP program (pinned maps) before loading TC objects
	// This allows us to use MapReplacements to replace maps during loading
	mapReplacements := make(map[string]*ebpf.Map)
	sharedMapNames := []string{"vpn_clients", "vpn_network_config", "server_egress_ip", "nat_conn_track"}

	for _, name := range sharedMapNames {
		pinPath := getSharedMapPinPath(name)
		pinnedMap, err := ebpf.LoadPinnedMap(pinPath, nil)
		if err != nil {
			if os.IsNotExist(err) {
				log.Printf("Shared map %s not found at %s, TC will create its own", name, pinPath)
				continue
			}
			log.Printf("Warning: Failed to load pinned map %s from %s: %v, TC will create its own", name, pinPath, err)
			continue
		}
		mapReplacements[name] = pinnedMap
		log.Printf("✅ Loaded shared map %s from %s for replacement", name, pinPath)
	}

	// Load pre-compiled eBPF objects with map replacements
	objs := &tc_natObjects{}
	var collOpts *ebpf.CollectionOptions
	if len(mapReplacements) > 0 {
		collOpts = &ebpf.CollectionOptions{
			MapReplacements: mapReplacements,
		}
		log.Printf("Using %d shared maps from XDP program", len(mapReplacements))
	}

	if err := loadTc_natObjects(objs, collOpts); err != nil {
		// Close loaded maps on error
		for _, m := range mapReplacements {
			m.Close()
		}
		return nil, fmt.Errorf("failed to load eBPF TC objects: %w", err)
	}

	if len(mapReplacements) > 0 {
		log.Printf("✅ TC program reused %d shared maps from XDP program", len(mapReplacements))

		// Verify that TC program can read the shared map values
		if serverEgressIPMap, ok := mapReplacements["server_egress_ip"]; ok {
			key := uint32(0)
			var value uint32
			if err := serverEgressIPMap.Lookup(key, &value); err == nil {
				ip := net.IPv4(
					byte(value>>24),
					byte(value>>16),
					byte(value>>8),
					byte(value),
				)
				log.Printf("✅ TC program verified shared server_egress_ip map: %s (0x%08X)", ip.String(), value)
			} else {
				log.Printf("⚠️  TC program failed to read from shared server_egress_ip map: %v", err)
			}
		}
	} else {
		log.Printf("⚠️  TC program using its own maps (XDP maps not found or not pinned)")
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
	tcxOpts := link.TCXOptions{
		Program:   objs.TcNatEgress,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	}
	tcLink, err = link.AttachTCX(tcxOpts)
	if err != nil {
		log.Printf("Warning: Failed to attach TC program using TCX: %v", err)
		log.Printf("TCX requires kernel 6.6+, falling back to traditional TC clsact qdisc...")

		// Fallback to traditional TC clsact qdisc using netlink (kernel 4.1+)
		clsactLink, err := attachTCClsact(ifName, iface.Index, objs.TcNatEgress)
		if err != nil {
			objs.Close()
			return nil, fmt.Errorf("failed to attach TC program: %w (tried TCX and traditional TC clsact)", err)
		}
		log.Printf("✅ TC egress NAT program attached using traditional TC clsact qdisc (compatible with kernel 4.1+)")
		tcProg := &TCProgram{
			objs:              objs,
			link:              nil, // No link.Link for traditional TC
			clsactLink:        clsactLink,
			ifName:            ifName,
			serverEgressIPMap: objs.ServerEgressIp,
			vpnClients:        objs.VpnClients,
			natStats:          objs.NatStats,
			vpnNetworkConfig:  objs.VpnNetworkConfig,
		}

		// Verify TC program can read from shared maps
		if objs.ServerEgressIp != nil {
			key := uint32(0)
			var value uint32
			if err := objs.ServerEgressIp.Lookup(key, &value); err == nil {
				ip := net.IPv4(
					byte(value>>24),
					byte(value>>16),
					byte(value>>8),
					byte(value),
				)
				log.Printf("✅ TC program verified it can read server_egress_ip: %s (0x%08X)", ip.String(), value)
			} else {
				log.Printf("⚠️  TC program cannot read server_egress_ip (may not be set yet): %v", err)
			}
		}

		return tcProg, nil
	}

	log.Printf("✅ TC egress NAT program attached using TCX (kernel 6.6+)")
	log.Printf("✅ TC egress NAT program attached to interface %s", ifName)

	tcProg := &TCProgram{
		objs:              objs,
		link:              tcLink,
		clsactLink:        nil, // Using TCX link
		ifName:            ifName,
		serverEgressIPMap: objs.ServerEgressIp,
		vpnClients:        objs.VpnClients,
		natStats:          objs.NatStats,
		vpnNetworkConfig:  objs.VpnNetworkConfig,
	}

	// Verify TC program can read from shared maps
	if objs.ServerEgressIp != nil {
		key := uint32(0)
		var value uint32
		if err := objs.ServerEgressIp.Lookup(key, &value); err == nil {
			ip := net.IPv4(
				byte(value>>24),
				byte(value>>16),
				byte(value>>8),
				byte(value),
			)
			log.Printf("✅ TC program verified it can read server_egress_ip: %s (0x%08X)", ip.String(), value)
		} else {
			log.Printf("⚠️  TC program cannot read server_egress_ip (may not be set yet): %v", err)
		}
	}

	return tcProg, nil
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
	// Use ipToUint32() for consistency
	ipUint32 := ipToUint32(publicIP)

	// Store in map with key 0
	key := uint32(0)
	if err := t.serverEgressIPMap.Put(key, ipUint32); err != nil {
		return fmt.Errorf("failed to set egress IP in TC eBPF map: %w", err)
	}

	// Verify the value was stored correctly
	var verifyValue uint32
	if err := t.serverEgressIPMap.Lookup(key, &verifyValue); err != nil {
		return fmt.Errorf("failed to verify egress IP in TC eBPF map: %w", err)
	}
	if verifyValue != ipUint32 {
		return fmt.Errorf("egress IP verification failed: expected 0x%08X, got 0x%08X", ipUint32, verifyValue)
	}

	log.Printf("✅ TC eBPF NAT: Server egress IP set to %s (0x%08X, verified: 0x%08X)", publicIP.String(), ipUint32, verifyValue)
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
	// Use binary.BigEndian.Uint32 for consistency
	networkUint32 := ipToUint32(ipNet.IP)
	if networkUint32 == 0 {
		return fmt.Errorf("VPN network must be IPv4")
	}

	// Convert mask to uint32 (mask is already in network byte order)
	maskBytes := ipNet.Mask
	if len(maskBytes) != 4 {
		return fmt.Errorf("invalid mask length")
	}
	maskUint32 := binary.BigEndian.Uint32(maskBytes)

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

	networkIP := net.IP([]byte{
		byte(networkUint32 >> 24),
		byte(networkUint32 >> 16),
		byte(networkUint32 >> 8),
		byte(networkUint32),
	})
	maskIP := net.IP([]byte{
		byte(maskUint32 >> 24),
		byte(maskUint32 >> 16),
		byte(maskUint32 >> 8),
		byte(maskUint32),
	})
	log.Printf("✅ TC eBPF NAT: VPN network configured: %s (network: %s/0x%08X, mask: %s/0x%08X)",
		vpnNetwork, networkIP.String(), networkUint32, maskIP.String(), maskUint32)
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
		// Ignore error if key does not exist (already deleted or never existed)
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "key does not exist") || strings.Contains(errStr, "not found") {
			return nil
		}
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
	for i := uint32(0); i < 30; i++ {
		var value uint64
		if err := t.natStats.Lookup(i, &value); err == nil {
			stats[i] = value
		}
	}

	return stats, nil
}

// GetDetailedNATStats returns formatted NAT statistics for debugging
func (t *TCProgram) GetDetailedNATStats() string {
	stats, err := t.GetNATStats()
	if err != nil {
		return fmt.Sprintf("Failed to get stats: %v", err)
	}

	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("TC NAT Stats (interface: %s): Total=%d, VPNCheck=%d, ClientFound=%d, EgressIP=%d, NAT=%d, NotConfigured=%d",
		t.ifName, stats[4], stats[1], stats[2], stats[3], stats[0], stats[5]))
	
	// Add debug statistics
	if stats[7] > 0 {
		buf.WriteString(fmt.Sprintf(", ShouldNotNAT=%d", stats[7]))
	}
	if stats[10] > 0 {
		buf.WriteString(fmt.Sprintf(", SrcIsVPN=%d", stats[10]))
	}
	if stats[11] > 0 {
		buf.WriteString(fmt.Sprintf(", DstIsVPN=%d", stats[11]))
	}
	if stats[12] > 0 {
		buf.WriteString(fmt.Sprintf(", SrcIsEgress=%d", stats[12]))
	}
	
	// Show debug information (first few packets)
	if stats[20] > 0 {
		srcIP := net.IP(make([]byte, 4))
		// Try big-endian first (network byte order)
		binary.BigEndian.PutUint32(srcIP, uint32(stats[20]))
		// If it looks wrong (first byte is 0-9, which is unusual), try little-endian
		if srcIP[0] <= 9 && srcIP[0] != 10 {
			binary.LittleEndian.PutUint32(srcIP, uint32(stats[20]))
		}
		buf.WriteString(fmt.Sprintf(", DebugSrcIP=%s/0x%08X", srcIP.String(), stats[20]))
	}
	if stats[21] > 0 {
		vpnNet := net.IP(make([]byte, 4))
		binary.BigEndian.PutUint32(vpnNet, uint32(stats[21]))
		buf.WriteString(fmt.Sprintf(", DebugVPNNet=%s/0x%08X", vpnNet.String(), stats[21]))
	}
	if stats[22] > 0 {
		vpnMask := net.IP(make([]byte, 4))
		binary.BigEndian.PutUint32(vpnMask, uint32(stats[22]))
		buf.WriteString(fmt.Sprintf(", DebugVPNMask=%s/0x%08X", vpnMask.String(), stats[22]))
	}
	// Show egress IP debug (key 23)
	if stats[23] > 0 {
		egressIP := net.IP(make([]byte, 4))
		binary.BigEndian.PutUint32(egressIP, uint32(stats[23]))
		buf.WriteString(fmt.Sprintf(", DebugEgressIP=%s/0x%08X", egressIP.String(), stats[23]))
	}
	// Show destination IP debug (key 26)
	if stats[26] > 0 {
		dstIP := net.IP(make([]byte, 4))
		binary.BigEndian.PutUint32(dstIP, uint32(stats[26]))
		buf.WriteString(fmt.Sprintf(", DebugDstIP=%s/0x%08X", dstIP.String(), stats[26]))
	}
	// Show comparison result debug (key 24)
	if stats[24] > 0 {
		buf.WriteString(fmt.Sprintf(", DebugCmpResult=%d", stats[24]))
	}

	// Show debug info if VPN check failed
	if stats[1] == 0 && stats[4] > 0 {
		if stats[18] != 0 || stats[19] != 0 {
			buf.WriteString(fmt.Sprintf(", src_is_vpn=%d, dst_is_vpn=%d", stats[18], stats[19]))
		}
		if stats[12] > 0 {
			vpnNet := net.IP(make([]byte, 4))
			// IP addresses in eBPF are stored in network byte order (big-endian)
			binary.BigEndian.PutUint32(vpnNet, uint32(stats[12]))
			buf.WriteString(fmt.Sprintf(" (VPNNet=%s/0x%08X", vpnNet.String(), stats[12]))
			if stats[13] > 0 {
				vpnMask := net.IP(make([]byte, 4))
				binary.BigEndian.PutUint32(vpnMask, uint32(stats[13]))
				buf.WriteString(fmt.Sprintf(", VPNMask=%s/0x%08X", vpnMask.String(), stats[13]))
			}
			if stats[20] > 0 {
				srcIP := net.IP(make([]byte, 4))
				// Try both byte orders to handle potential endianness issues
				// First try big-endian (network byte order)
				binary.BigEndian.PutUint32(srcIP, uint32(stats[20]))
				// If the result looks wrong (first byte is 0-9, which is unusual for IP addresses),
				// try little-endian (host byte order on x86)
				if srcIP[0] <= 9 {
					binary.LittleEndian.PutUint32(srcIP, uint32(stats[20]))
				}
				buf.WriteString(fmt.Sprintf(", SrcIP=%s/0x%08X", srcIP.String(), stats[20]))
			}
			if stats[14] > 0 {
				srcNet := net.IP(make([]byte, 4))
				binary.BigEndian.PutUint32(srcNet, uint32(stats[14]))
				// If the result looks wrong, try little-endian
				if srcNet[0] <= 9 {
					binary.LittleEndian.PutUint32(srcNet, uint32(stats[14]))
				}
				buf.WriteString(fmt.Sprintf(", SrcNet=%s/0x%08X", srcNet.String(), stats[14]))
			}
			if stats[7] > 0 {
				srcIPFirst := net.IP(make([]byte, 4))
				binary.BigEndian.PutUint32(srcIPFirst, uint32(stats[7]))
				// If the result looks wrong, try little-endian
				if srcIPFirst[0] <= 9 {
					binary.LittleEndian.PutUint32(srcIPFirst, uint32(stats[7]))
				}
				buf.WriteString(fmt.Sprintf(", FirstSrcIP=%s/0x%08X", srcIPFirst.String(), stats[7]))
			}
			// Show egress IP if available (key 21)
			if stats[21] > 0 {
				egressIP := net.IP(make([]byte, 4))
				binary.BigEndian.PutUint32(egressIP, uint32(stats[21]))
				// If the result looks wrong, try little-endian
				if egressIP[0] <= 9 {
					binary.LittleEndian.PutUint32(egressIP, uint32(stats[21]))
				}
				buf.WriteString(fmt.Sprintf(", EgressIP=%s/0x%08X", egressIP.String(), stats[21]))
			}
			// Show src_is_egress status (key 22)
			if stats[22] > 0 {
				buf.WriteString(fmt.Sprintf(", src_is_egress=%d", stats[22]))
			}
			// Show egress_ip pointer status (key 23)
			if stats[23] != 0 {
				buf.WriteString(fmt.Sprintf(", egress_ip_ptr=%d", stats[23]))
			}
			// Show egress_ip value directly (key 24)
			if stats[24] > 0 {
				egressIPVal := net.IP(make([]byte, 4))
				binary.BigEndian.PutUint32(egressIPVal, uint32(stats[24]))
				buf.WriteString(fmt.Sprintf(", egress_ip_val=%s/0x%08X", egressIPVal.String(), stats[24]))
			}
			buf.WriteString(")")
		}
	}
	buf.WriteString("\n")

	return buf.String()
}

// VerifyAttachment verifies that the TC program is correctly attached to the interface
func (t *TCProgram) VerifyAttachment() error {
	if t == nil {
		return fmt.Errorf("TC program not loaded")
	}

	// Check if we have a link (TCX) or clsactLink (traditional TC)
	if t.link != nil {
		log.Printf("TC NAT: Program attached using TCX link")
		return nil
	}

	if t.clsactLink != nil {
		log.Printf("TC NAT: Program attached using traditional TC clsact qdisc")
		// Verify clsact qdisc exists
		link, err := netlink.LinkByName(t.ifName)
		if err != nil {
			return fmt.Errorf("failed to find interface %s: %w", t.ifName, err)
		}

		qdiscs, err := netlink.QdiscList(link)
		if err != nil {
			return fmt.Errorf("failed to list qdiscs: %w", err)
		}

		clsactFound := false
		for _, qdisc := range qdiscs {
			if qdisc.Type() == "clsact" {
				clsactFound = true
				log.Printf("TC NAT: Verified clsact qdisc exists on interface %s", t.ifName)
				break
			}
		}

		if !clsactFound {
			return fmt.Errorf("clsact qdisc not found on interface %s", t.ifName)
		}

		// Verify filter exists
		filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
		if err != nil {
			return fmt.Errorf("failed to list filters: %w", err)
		}

		filterFound := false
		for _, filter := range filters {
			if bpfFilter, ok := filter.(*netlink.BpfFilter); ok {
				if bpfFilter.Name == "tc_nat_egress" {
					filterFound = true
					log.Printf("TC NAT: Verified eBPF filter 'tc_nat_egress' exists on interface %s egress", t.ifName)
					break
				}
			}
		}

		if !filterFound {
			return fmt.Errorf("eBPF filter 'tc_nat_egress' not found on interface %s egress", t.ifName)
		}

		return nil
	}

	return fmt.Errorf("TC program not attached (no link or clsactLink)")
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
			log.Printf("✅ Clsact qdisc already exists on interface %s", ifName)
		} else {
			log.Printf("ERROR: Failed to create clsact qdisc on interface %s: %v", ifName, err)
			log.Printf("ERROR: LinkIndex=%d, Handle=%d, Parent=%d", ifIndex, netlink.MakeHandle(0xffff, 0), netlink.HANDLE_CLSACT)
			return nil, fmt.Errorf("failed to create clsact qdisc: %w", err)
		}
	} else {
		log.Printf("✅ Created clsact qdisc on interface %s", ifName)
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
	log.Printf("Attempting to attach eBPF program to clsact qdisc on interface %s (FD=%d, LinkIndex=%d, Parent=%d)",
		ifName, progFD, ifIndex, netlink.HANDLE_MIN_EGRESS)
	if err := netlink.FilterAdd(filter); err != nil {
		log.Printf("ERROR: Failed to attach eBPF program to clsact qdisc on interface %s: %v", ifName, err)
		log.Printf("ERROR: Program FD: %d, LinkIndex: %d, Parent: %d", progFD, ifIndex, netlink.HANDLE_MIN_EGRESS)
		log.Printf("ERROR: Filter details: Handle=%d, Protocol=%d, Priority=%d, Name=%s",
			netlink.MakeHandle(0, 1), unix.ETH_P_ALL, 1, "tc_nat_egress")
		// Clean up qdisc if filter add fails
		if delErr := netlink.QdiscDel(qdisc); delErr != nil {
			log.Printf("WARNING: Failed to clean up qdisc after filter add failure: %v", delErr)
		}
		return nil, fmt.Errorf("failed to attach eBPF program to clsact qdisc: %w", err)
	}

	log.Printf("✅ Attached eBPF program to clsact qdisc egress hook on interface %s", ifName)

	// Verify attachment immediately
	if link, err := netlink.LinkByName(ifName); err == nil {
		filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
		if err == nil {
			found := false
			for _, f := range filters {
				if bpfFilter, ok := f.(*netlink.BpfFilter); ok && bpfFilter.Name == "tc_nat_egress" {
					found = true
					log.Printf("✅ Verified TC filter 'tc_nat_egress' is attached to %s egress", ifName)
					break
				}
			}
			if !found {
				log.Printf("⚠️  WARNING: TC filter 'tc_nat_egress' not found on %s egress after attach!", ifName)
				log.Printf("⚠️  Available filters on %s egress:", ifName)
				for _, f := range filters {
					log.Printf("    Filter: %+v", f)
				}
			}
		} else {
			log.Printf("⚠️  WARNING: Failed to verify TC filter attachment: %v", err)
		}
	} else {
		log.Printf("⚠️  WARNING: Failed to get link %s for verification: %v", ifName, err)
	}

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


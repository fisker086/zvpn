//go:build ebpf
// +build ebpf

package ebpf

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// XDPProgram represents an eBPF XDP program
type XDPProgram struct {
	objs              *xdpObjects
	link               link.Link
	ifName             string
	policiesMap        *ebpf.Map
	policyChains       *ebpf.Map // Hook point + index -> policy ID
	vpnClients         *ebpf.Map
	stats              *ebpf.Map
	policyStats        *ebpf.Map
	policyEvents       *ebpf.Map // Queue of policy events (allow/deny) for audit logging
	blockedIPs         *ebpf.Map // Blocked IPs for bruteforce protection
	rateLimitConfigMap *ebpf.Map // Rate limit and DDoS protection configuration
	serverEgressIPMap  *ebpf.Map // Server egress IP for NAT masquerading
	vpnNetworkConfig   *ebpf.Map // VPN network configuration
	policyChainStatus  *ebpf.Map // Policy chain status (optimization: check if chain is empty)
}

// LoadXDPProgram loads and attaches the XDP program to a network interface
func LoadXDPProgram(ifName string) (*XDPProgram, error) {
	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load pre-compiled eBPF objects
	objs := &xdpObjects{}
	if err := loadXdpObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
	}

	// Open network interface
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to find interface %s: %w", ifName, err)
	}

	// Attach XDP program to interface
	opts := link.XDPOptions{
		Program:   objs.XdpVpnForward,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // Use generic mode for compatibility
	}

	xdpLink, err := link.AttachXDP(opts)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to attach XDP program: %w", err)
	}

	// Initialize policy chains map
	// Now using a single hash map instead of array of maps
	// The key is a composite of hook_point and index
	policyChains := objs.PolicyChains

	// Initialize policy chain status map (optimization: track if chains are empty)
	policyChainStatus := objs.PolicyChainStatus

	// Initialize all hook points as empty (0 = no policies)
	// This ensures fast path works correctly when no policies are configured
	for hookPoint := uint32(0); hookPoint < 5; hookPoint++ {
		emptyStatus := uint8(0)
		if err := policyChainStatus.Put(hookPoint, emptyStatus); err != nil {
			objs.Close()
			return nil, fmt.Errorf("failed to initialize policy chain status: %w", err)
		}
	}

	return &XDPProgram{
		objs:              objs,
		link:               xdpLink,
		ifName:             ifName,
		policiesMap:        objs.Policies,
		policyChains:       policyChains,
		vpnClients:         objs.VpnClients,
		stats:              objs.Stats,
		policyStats:        objs.PolicyStats,
		policyEvents:       objs.PolicyEvents,
		blockedIPs:         objs.BlockedIpsMap,
		rateLimitConfigMap: objs.RateLimitConfigMap,
		serverEgressIPMap:  objs.ServerEgressIp,
		vpnNetworkConfig:   objs.VpnNetworkConfig,
		policyChainStatus:  policyChainStatus,
	}, nil
}

// AddVPNClient adds a VPN client IP mapping
func (x *XDPProgram) AddVPNClient(vpnIP, clientIP net.IP) error {
	if x == nil || x.vpnClients == nil {
		return fmt.Errorf("eBPF program not loaded")
	}

	vpnIPUint32 := ipToUint32(vpnIP)
	clientIPUint32 := ipToUint32(clientIP)

	if err := x.vpnClients.Put(vpnIPUint32, clientIPUint32); err != nil {
		return fmt.Errorf("failed to add VPN client mapping: %w", err)
	}

	return nil
}

// RemoveVPNClient removes a VPN client IP mapping
func (x *XDPProgram) RemoveVPNClient(vpnIP net.IP) error {
	if x == nil || x.vpnClients == nil {
		return fmt.Errorf("eBPF program not loaded")
	}

	vpnIPUint32 := ipToUint32(vpnIP)
	if err := x.vpnClients.Delete(vpnIPUint32); err != nil {
		return fmt.Errorf("failed to remove VPN client mapping: %w", err)
	}

	return nil
}

// AddRoute adds a routing rule with optional metric
// Note: Routes are now handled by the kernel, not eBPF
// This method is kept for compatibility but does nothing
func (x *XDPProgram) AddRoute(network *net.IPNet, gateway net.IP, metric int) error {
	// Routes are handled by kernel routing table, not eBPF
	// This is a no-op for compatibility
	return nil
}

// UpdateRoute updates an existing routing rule
// Note: Routes are now handled by the kernel, not eBPF
func (x *XDPProgram) UpdateRoute(network *net.IPNet, gateway net.IP, metric int) error {
	// Routes are handled by kernel routing table, not eBPF
	// This is a no-op for compatibility
	return nil
}

// DeleteRoute removes a routing rule
// Note: Routes are now handled by the kernel, not eBPF
func (x *XDPProgram) DeleteRoute(network *net.IPNet) error {
	// Routes are handled by kernel routing table, not eBPF
	// This is a no-op for compatibility
	return nil
}

// AddPolicy adds a policy to eBPF maps
func (x *XDPProgram) AddPolicy(policyID uint32, hookPoint uint32, action uint32,
	srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8) error {
	if x == nil || x.policiesMap == nil {
		return fmt.Errorf("eBPF program not loaded")
	}

	// Create policy entry (legacy format for backward compatibility)
	entry := struct {
		PolicyID     uint32
		Action       uint32
		HookPoint    uint32
		Priority     uint32
		SrcIP        uint32
		DstIP        uint32
		SrcIPMask    uint32
		DstIPMask    uint32
		SrcPort      uint16
		DstPort      uint16
		SrcPortEnd   uint16
		DstPortEnd   uint16
		Protocol     uint8
		ProtocolMask uint8
		Flags        uint8
	}{
		PolicyID:     policyID,
		Action:       action,
		HookPoint:    hookPoint,
		Priority:     policyID, // Use policy ID as priority for now (can be overridden)
		SrcIP:        ipToUint32(srcIP),
		DstIP:        ipToUint32(dstIP),
		SrcIPMask:    0xFFFFFFFF, // Exact match by default
		DstIPMask:    0xFFFFFFFF, // Exact match by default
		SrcPort:      srcPort,
		DstPort:      dstPort,
		SrcPortEnd:   0, // Single port
		DstPortEnd:   0, // Single port
		Protocol:     protocol,
		ProtocolMask: 0, // Single protocol
		Flags:        0, // Flags: bit 0=src_ip match type, bit 1=dst_ip match type, bit 2=src_port match type, bit 3=dst_port match type
	}

	// Add policy to policies map
	if err := x.policiesMap.Put(policyID, entry); err != nil {
		return fmt.Errorf("failed to add policy to map: %w", err)
	}

	// Add policy ID to policy chain for this hook point
	// Find next available slot in chain (sorted by priority)
	// First, collect all existing policies for this hook point
	type chainKey struct {
		HookPoint uint32
		Index     uint32
	}

	type policyEntry struct {
		ID       uint32
		Priority uint32
	}

	existingPolicies := make([]policyEntry, 0, 64)

	// Collect all existing policies for this hook point
	for i := uint32(0); i < 64; i++ {
		key := chainKey{
			HookPoint: hookPoint,
			Index:     i,
		}

		var existingID uint32
		if err := x.policyChains.Lookup(key, &existingID); err == nil && existingID != 0 {
			// Get policy priority
			var existingPolicy struct {
				PolicyID  uint32
				Action    uint32
				HookPoint uint32
				Priority  uint32
				SrcIP     uint32
				DstIP     uint32
				SrcPort   uint16
				DstPort   uint16
				Protocol  uint8
				Flags     uint8
			}
			if err := x.policiesMap.Lookup(existingID, &existingPolicy); err == nil {
				existingPolicies = append(existingPolicies, policyEntry{
					ID:       existingID,
					Priority: existingPolicy.Priority,
				})
			}
		}
	}

	// Get current policy priority
	var currentPolicy struct {
		PolicyID  uint32
		Action    uint32
		HookPoint uint32
		Priority  uint32
		SrcIP     uint32
		DstIP     uint32
		SrcPort   uint16
		DstPort   uint16
		Protocol  uint8
		Flags     uint8
	}
	if err := x.policiesMap.Lookup(policyID, &currentPolicy); err != nil {
		return fmt.Errorf("failed to lookup policy %d: %w", policyID, err)
	}

	// Check if policy already exists in chain
	for _, ep := range existingPolicies {
		if ep.ID == policyID {
			// Policy already in chain, update if priority changed
			return nil
		}
	}

	// Enforce chain depth limit (XDP 遍历 0..63)
	if len(existingPolicies) >= 64 {
		return fmt.Errorf("policy chain full (64) at hook point %d", hookPoint)
	}

	// Add current policy to list and sort by priority
	existingPolicies = append(existingPolicies, policyEntry{
		ID:       policyID,
		Priority: currentPolicy.Priority,
	})

	// Sort by priority (lower priority number = higher priority)
	for i := 0; i < len(existingPolicies)-1; i++ {
		for j := i + 1; j < len(existingPolicies); j++ {
			if existingPolicies[i].Priority > existingPolicies[j].Priority {
				existingPolicies[i], existingPolicies[j] = existingPolicies[j], existingPolicies[i]
			}
		}
	}

	// Clear all existing entries for this hook point
	for i := uint32(0); i < 64; i++ {
		key := chainKey{
			HookPoint: hookPoint,
			Index:     i,
		}
		x.policyChains.Delete(key)
	}

	// Re-add all policies in sorted order
	for i, ep := range existingPolicies {
		key := chainKey{
			HookPoint: hookPoint,
			Index:     uint32(i),
		}
		if err := x.policyChains.Put(key, ep.ID); err != nil {
			return fmt.Errorf("failed to add policy %d to chain at index %d: %w", ep.ID, i, err)
		}
	}

	// Update policy chain status (optimization: mark chain as non-empty if policies exist)
	hasPolicies := uint8(0)
	if len(existingPolicies) > 0 {
		hasPolicies = 1
	}
	if err := x.policyChainStatus.Put(hookPoint, hasPolicies); err != nil {
		return fmt.Errorf("failed to update policy chain status: %w", err)
	}

	return nil
}

// AddPolicyWithMask adds a policy to eBPF maps with support for CIDR masks, port ranges, and protocol masks
func (x *XDPProgram) AddPolicyWithMask(policyID uint32, hookPoint uint32, action uint32,
	srcIP, dstIP net.IP, srcIPMask, dstIPMask uint32,
	srcPort, srcPortEnd, dstPort, dstPortEnd uint16,
	protocolMask uint8) error {
	if x == nil || x.policiesMap == nil {
		return fmt.Errorf("eBPF program not loaded")
	}

	// Flags encoding (2 bits per field):
	// bits 0-1: src IP match type, 2-3: dst IP match type, 4-5: src port, 6-7: dst port
	// match type: 0=exact, 1=any (0), 2=mask/range

	const (
		flagSrcIPShift   = 0
		flagDstIPShift   = 2
		flagSrcPortShift = 4
		flagDstPortShift = 6
	)

	srcMatchType := uint8(0) // exact
	if srcIPMask != 0 && srcIPMask != 0xFFFFFFFF {
		srcMatchType = 2 // mask
	} else if ipToUint32(srcIP) == 0 {
		srcMatchType = 1 // any
	}

	dstMatchType := uint8(0)
	if dstIPMask != 0 && dstIPMask != 0xFFFFFFFF {
		dstMatchType = 2 // mask
	} else if ipToUint32(dstIP) == 0 {
		dstMatchType = 1 // any
	}

	srcPortMatchType := uint8(0)
	if srcPortEnd != 0 && srcPortEnd != srcPort {
		srcPortMatchType = 2 // range
	} else if srcPort == 0 {
		srcPortMatchType = 1 // any
	}

	dstPortMatchType := uint8(0)
	if dstPortEnd != 0 && dstPortEnd != dstPort {
		dstPortMatchType = 2 // range
	} else if dstPort == 0 {
		dstPortMatchType = 1 // any
	}

	// Create policy entry with extended fields
	entry := struct {
		PolicyID     uint32
		Action       uint32
		HookPoint    uint32
		Priority     uint32
		SrcIP        uint32
		DstIP        uint32
		SrcIPMask    uint32
		DstIPMask    uint32
		SrcPort      uint16
		DstPort      uint16
		SrcPortEnd   uint16
		DstPortEnd   uint16
		Protocol     uint8
		ProtocolMask uint8
		Flags        uint8
	}{
		PolicyID:     policyID,
		Action:       action,
		HookPoint:    hookPoint,
		Priority:     policyID, // Use policy ID as priority for now
		SrcIP:        ipToUint32(srcIP),
		DstIP:        ipToUint32(dstIP),
		SrcIPMask:    srcIPMask,
		DstIPMask:    dstIPMask,
		SrcPort:      srcPort,
		DstPort:      dstPort,
		SrcPortEnd:   srcPortEnd,
		DstPortEnd:   dstPortEnd,
		Protocol:     0, // Not used when protocolMask is set
		ProtocolMask: protocolMask,
		Flags:        0,
	}

	// Set flags based on match types (2 bits each)
	entry.Flags |= srcMatchType << flagSrcIPShift
	entry.Flags |= dstMatchType << flagDstIPShift
	entry.Flags |= srcPortMatchType << flagSrcPortShift
	entry.Flags |= dstPortMatchType << flagDstPortShift

	// Add policy to policies map
	if err := x.policiesMap.Put(policyID, entry); err != nil {
		return fmt.Errorf("failed to add policy to map: %w", err)
	}

	// Add policy ID to policy chain (reuse the same chain logic as AddPolicy)
	type chainKey struct {
		HookPoint uint32
		Index     uint32
	}

	type policyEntry struct {
		ID       uint32
		Priority uint32
	}

	existingPolicies := make([]policyEntry, 0, 64)

	// Collect all existing policies for this hook point
	for i := uint32(0); i < 64; i++ {
		key := chainKey{
			HookPoint: hookPoint,
			Index:     i,
		}

		var existingID uint32
		if err := x.policyChains.Lookup(key, &existingID); err == nil && existingID != 0 {
			var existingPolicy struct {
				PolicyID     uint32
				Action       uint32
				HookPoint    uint32
				Priority     uint32
				SrcIP        uint32
				DstIP        uint32
				SrcIPMask    uint32
				DstIPMask    uint32
				SrcPort      uint16
				DstPort      uint16
				SrcPortEnd   uint16
				DstPortEnd   uint16
				Protocol     uint8
				ProtocolMask uint8
				Flags        uint8
			}
			if err := x.policiesMap.Lookup(existingID, &existingPolicy); err == nil {
				existingPolicies = append(existingPolicies, policyEntry{
					ID:       existingID,
					Priority: existingPolicy.Priority,
				})
			}
		}
	}

	// Check if policy already exists in chain
	for _, ep := range existingPolicies {
		if ep.ID == policyID {
			return nil // Policy already in chain
		}
	}

	// Enforce chain depth limit (XDP 遍历 0..63)
	if len(existingPolicies) >= 64 {
		return fmt.Errorf("policy chain full (64) at hook point %d", hookPoint)
	}

	// Add current policy to list and sort by priority
	existingPolicies = append(existingPolicies, policyEntry{
		ID:       policyID,
		Priority: entry.Priority,
	})

	// Sort by priority (lower priority number = higher priority)
	for i := 0; i < len(existingPolicies)-1; i++ {
		for j := i + 1; j < len(existingPolicies); j++ {
			if existingPolicies[i].Priority > existingPolicies[j].Priority {
				existingPolicies[i], existingPolicies[j] = existingPolicies[j], existingPolicies[i]
			}
		}
	}

	// Update policy chain
	for i, ep := range existingPolicies {
		key := chainKey{
			HookPoint: hookPoint,
			Index:     uint32(i),
		}
		if err := x.policyChains.Put(key, ep.ID); err != nil {
			return fmt.Errorf("failed to add policy %d to chain at index %d: %w", ep.ID, i, err)
		}
	}

	// Clear remaining slots
	for i := len(existingPolicies); i < 64; i++ {
		key := chainKey{
			HookPoint: hookPoint,
			Index:     uint32(i),
		}
		x.policyChains.Delete(key)
	}

	// Update policy chain status (optimization: mark chain as non-empty if policies exist)
	hasPolicies := uint8(0)
	if len(existingPolicies) > 0 {
		hasPolicies = 1
	}
	if err := x.policyChainStatus.Put(hookPoint, hasPolicies); err != nil {
		return fmt.Errorf("failed to update policy chain status: %w", err)
	}

	return nil
}

// RemovePolicy removes a policy from eBPF maps
func (x *XDPProgram) RemovePolicy(policyID uint32) error {
	if x == nil || x.policiesMap == nil {
		return fmt.Errorf("eBPF program not loaded")
	}

	// Get policy hook point before removing
	var policy struct {
		PolicyID  uint32
		Action    uint32
		HookPoint uint32
		Priority  uint32
		SrcIP     uint32
		DstIP     uint32
		SrcPort   uint16
		DstPort   uint16
		Protocol  uint8
		Flags     uint8
	}

	hookPoint := uint32(0)
	if err := x.policiesMap.Lookup(policyID, &policy); err == nil {
		hookPoint = policy.HookPoint
	}

	// Remove from policies map
	if err := x.policiesMap.Delete(policyID); err != nil {
		return fmt.Errorf("failed to remove policy from map: %w", err)
	}

	// Remove from policy chain
	if hookPoint > 0 {
		type chainKey struct {
			HookPoint uint32
			Index     uint32
		}

		// Find and remove policy from chain, then compact
		for i := uint32(0); i < 64; i++ {
			key := chainKey{
				HookPoint: hookPoint,
				Index:     i,
			}

			var existingID uint32
			if err := x.policyChains.Lookup(key, &existingID); err == nil && existingID == policyID {
				// Found the policy, remove it
				x.policyChains.Delete(key)

				// Compact the chain by shifting remaining policies
				for j := i + 1; j < 64; j++ {
					nextKey := chainKey{
						HookPoint: hookPoint,
						Index:     j,
					}
					var nextID uint32
					if err := x.policyChains.Lookup(nextKey, &nextID); err == nil && nextID != 0 {
						// Move next policy to current position
						if err := x.policyChains.Put(key, nextID); err != nil {
							return fmt.Errorf("failed to compact policy chain: %w", err)
						}
						x.policyChains.Delete(nextKey)
						i = j - 1 // Continue from current position
					} else {
						break // End of chain
					}
				}
				break
			}
		}

		// Update policy chain status after removal
		// Check if chain is now empty
		hasPolicies := uint8(0)
		for i := uint32(0); i < 64; i++ {
			key := chainKey{
				HookPoint: hookPoint,
				Index:     i,
			}
			var existingID uint32
			if err := x.policyChains.Lookup(key, &existingID); err == nil && existingID != 0 {
				hasPolicies = 1
				break
			}
		}
		if err := x.policyChainStatus.Put(hookPoint, hasPolicies); err != nil {
			return fmt.Errorf("failed to update policy chain status: %w", err)
		}
	}

	// Remove from all policy chains
	for hookPoint := uint32(0); hookPoint < 5; hookPoint++ {
		for i := uint32(0); i < 64; i++ {
			// Create composite key for the hash map
			type chainKey struct {
				HookPoint uint32
				Index     uint32
			}

			key := chainKey{
				HookPoint: hookPoint,
				Index:     i,
			}

			var existingID uint32
			if err := x.policyChains.Lookup(key, &existingID); err == nil {
				if existingID == policyID {
					// Remove by setting to 0
					if err := x.policyChains.Put(key, uint32(0)); err != nil {
						return fmt.Errorf("failed to remove policy from chain: %w", err)
					}
					break
				}
			}
		}

		// Update policy chain status after removal (for each hook point)
		// Check if chain is now empty
		hasPolicies := uint8(0)
		for i := uint32(0); i < 64; i++ {
			type chainKey struct {
				HookPoint uint32
				Index     uint32
			}
			key := chainKey{
				HookPoint: hookPoint,
				Index:     i,
			}
			var existingID uint32
			if err := x.policyChains.Lookup(key, &existingID); err == nil && existingID != 0 {
				hasPolicies = 1
				break
			}
		}
		if err := x.policyChainStatus.Put(hookPoint, hasPolicies); err != nil {
			return fmt.Errorf("failed to update policy chain status: %w", err)
		}
	}

	return nil
}

// GetStats returns packet processing statistics
// Note: stats is a per-CPU map, so we need to read all CPU values and sum them
// Returns: (totalPackets, droppedPackets, error)
func (x *XDPProgram) GetStats() (uint64, error) {
	if x == nil || x.stats == nil {
		return 0, fmt.Errorf("eBPF program not loaded")
	}

	key := uint32(0)

	// For per-CPU maps, we need to use a slice to read all CPU values
	var values []uint64
	if err := x.stats.Lookup(key, &values); err != nil {
		return 0, fmt.Errorf("failed to get stats: %w", err)
	}

	// Sum all CPU values
	var total uint64
	for _, v := range values {
		total += v
	}

	return total, nil
}

// GetDetailedStats returns detailed packet processing statistics
// Returns: totalPackets, droppedPackets, error
func (x *XDPProgram) GetDetailedStats() (totalPackets uint64, droppedPackets uint64, err error) {
	if x == nil || x.stats == nil {
		return 0, 0, fmt.Errorf("eBPF program not loaded")
	}

	// Get total packets (key = 0)
	key0 := uint32(0)
	var values0 []uint64
	if err := x.stats.Lookup(key0, &values0); err != nil {
		return 0, 0, fmt.Errorf("failed to get total packets stats: %w", err)
	}
	for _, v := range values0 {
		totalPackets += v
	}

	// Get dropped packets (key = 1)
	key1 := uint32(1)
	var values1 []uint64
	if err := x.stats.Lookup(key1, &values1); err != nil {
		// Dropped packets might not be initialized, return 0 instead of error
		droppedPackets = 0
	} else {
		for _, v := range values1 {
			droppedPackets += v
		}
	}

	return totalPackets, droppedPackets, nil
}

// GetPolicyStats returns policy match statistics
// Note: policy_stats is a per-CPU hash map, so we need to read all CPU values and sum them
func (x *XDPProgram) GetPolicyStats(policyID uint32) (uint64, error) {
	if x == nil || x.policyStats == nil {
		return 0, fmt.Errorf("eBPF program not loaded")
	}

	// For per-CPU hash maps, we need to use a slice to read all CPU values
	var values []uint64
	if err := x.policyStats.Lookup(policyID, &values); err != nil {
		return 0, fmt.Errorf("failed to get policy stats: %w", err)
	}

	// Sum all CPU values
	var total uint64
	for _, v := range values {
		total += v
	}

	return total, nil
}

// SetPublicIP sets the public IP address for NAT masquerading in eBPF
func (x *XDPProgram) SetPublicIP(publicIP net.IP) error {
	if x == nil || x.serverEgressIPMap == nil {
		return fmt.Errorf("eBPF program not loaded or server_egress_ip map not found")
	}

	if publicIP == nil || publicIP.To4() == nil {
		return fmt.Errorf("invalid IPv4 address")
	}

	// Convert IP to network byte order (uint32)
	ipBytes := publicIP.To4()
	ipUint32 := uint32(ipBytes[0])<<24 | uint32(ipBytes[1])<<16 | uint32(ipBytes[2])<<8 | uint32(ipBytes[3])

	// Store in map with key 0
	key := uint32(0)
	if err := x.serverEgressIPMap.Put(key, ipUint32); err != nil {
		return fmt.Errorf("failed to set egress IP in eBPF map: %w", err)
	}

	log.Printf("✅ eBPF NAT: Server egress IP set to %s", publicIP.String())
	return nil
}

// GetPublicIP retrieves the currently configured public IP from the eBPF map
func (x *XDPProgram) GetPublicIP() (net.IP, error) {
	if x == nil || x.serverEgressIPMap == nil {
		return nil, fmt.Errorf("eBPF program not loaded or server_egress_ip map not found")
	}

	// Read from map with key 0
	key := uint32(0)
	var ipUint32 uint32
	if err := x.serverEgressIPMap.Lookup(key, &ipUint32); err != nil {
		return nil, fmt.Errorf("egress IP not configured in eBPF map: %w", err)
	}

	// Convert from network byte order to net.IP
	ip := net.IPv4(
		byte(ipUint32>>24),
		byte(ipUint32>>16),
		byte(ipUint32>>8),
		byte(ipUint32),
	)

	return ip, nil
}

// Close detaches and closes the XDP program
func (x *XDPProgram) Close() error {
	var errs []error

	if x.link != nil {
		if err := x.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close XDP link: %w", err))
		}
	}

	if x.objs != nil {
		if err := x.objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close eBPF objects: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during close: %v", errs)
	}

	return nil
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// SetVPNNetwork sets the VPN network configuration in XDP eBPF map
func (x *XDPProgram) SetVPNNetwork(vpnNetwork string) error {
	if x == nil || x.vpnNetworkConfig == nil {
		return fmt.Errorf("XDP program not loaded or vpn_network_config map not found")
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
	if err := x.vpnNetworkConfig.Put(key, networkUint32); err != nil {
		return fmt.Errorf("failed to set VPN network address in XDP eBPF map: %w", err)
	}

	// Store network mask (key 1)
	key = 1
	if err := x.vpnNetworkConfig.Put(key, maskUint32); err != nil {
		return fmt.Errorf("failed to set VPN network mask in XDP eBPF map: %w", err)
	}

	log.Printf("✅ XDP eBPF: VPN network configured: %s (network: 0x%08X, mask: 0x%08X)", vpnNetwork, networkUint32, maskUint32)
	return nil
}

// Helper function to convert IP to uint32 (used in stub)
func uint32ToIP(ip uint32) net.IP {
	return net.IP{
		byte(ip >> 24),
		byte(ip >> 16),
		byte(ip >> 8),
		byte(ip),
	}
}

// BlockIP blocks an IP address in eBPF (kernel-level blocking)
// blockedUntil: 0 = permanent block, otherwise timestamp in nanoseconds
func (x *XDPProgram) BlockIP(ip net.IP, blockedUntil uint64) error {
	if x == nil || x.blockedIPs == nil {
		return fmt.Errorf("eBPF program not loaded")
	}

	ipUint32 := ipToUint32(ip)
	if ipUint32 == 0 {
		return fmt.Errorf("invalid IP address: %s", ip.String())
	}

	if err := x.blockedIPs.Put(ipUint32, blockedUntil); err != nil {
		return fmt.Errorf("failed to block IP in eBPF: %w", err)
	}

	return nil
}

// UnblockIP unblocks an IP address in eBPF
func (x *XDPProgram) UnblockIP(ip net.IP) error {
	if x == nil || x.blockedIPs == nil {
		return fmt.Errorf("eBPF program not loaded")
	}

	ipUint32 := ipToUint32(ip)
	if ipUint32 == 0 {
		return fmt.Errorf("invalid IP address: %s", ip.String())
	}

	if err := x.blockedIPs.Delete(ipUint32); err != nil {
		return fmt.Errorf("failed to unblock IP in eBPF: %w", err)
	}

	return nil
}

// IsIPBlocked checks if an IP is blocked in eBPF
func (x *XDPProgram) IsIPBlocked(ip net.IP) (bool, uint64, error) {
	if x == nil || x.blockedIPs == nil {
		return false, 0, fmt.Errorf("eBPF program not loaded")
	}

	ipUint32 := ipToUint32(ip)
	if ipUint32 == 0 {
		return false, 0, fmt.Errorf("invalid IP address: %s", ip.String())
	}

	var blockedUntil uint64
	if err := x.blockedIPs.Lookup(ipUint32, &blockedUntil); err != nil {
		return false, 0, nil // Not blocked
	}

	return true, blockedUntil, nil
}

// RateLimitConfig represents the rate limit and DDoS protection configuration
type RateLimitConfig struct {
	EnableRateLimit      uint8  // 0 = disabled, 1 = enabled
	_                    [7]byte
	RateLimitPerIP       uint64 // Packets per second per IP
	EnableDDoSProtection uint8  // 0 = disabled, 1 = enabled
	_                    [7]byte
	DDoSThreshold        uint64 // Packets per second threshold
	DDoSBlockDuration    uint64 // Block duration in nanoseconds
}

// UpdateRateLimitConfig updates the rate limit and DDoS protection configuration in eBPF
func (x *XDPProgram) UpdateRateLimitConfig(config RateLimitConfig) error {
	if x == nil || x.rateLimitConfigMap == nil {
		return fmt.Errorf("eBPF program not loaded")
	}

	key := uint32(0)
	if err := x.rateLimitConfigMap.Put(key, config); err != nil {
		return fmt.Errorf("failed to update rate limit config in eBPF: %w", err)
	}

	return nil
}

// GetRateLimitConfig retrieves the current rate limit and DDoS protection configuration from eBPF
func (x *XDPProgram) GetRateLimitConfig() (RateLimitConfig, error) {
	var config RateLimitConfig
	if x == nil || x.rateLimitConfigMap == nil {
		return config, fmt.Errorf("eBPF program not loaded")
	}

	key := uint32(0)
	if err := x.rateLimitConfigMap.Lookup(key, &config); err != nil {
		return config, fmt.Errorf("failed to get rate limit config from eBPF: %w", err)
	}

	return config, nil
}

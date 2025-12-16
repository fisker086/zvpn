package policy

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/fisker/zvpn/vpn/ebpf"
)

// EBPFLoader wraps the eBPF loader and provides policy management
type EBPFLoader struct {
	xdpProgram   *ebpf.XDPProgram
	nextPolicyID uint32
	policyIDMap  map[string]uint32   // Hook name -> policy ID
	hookPolicies map[string][]uint32 // Hook name -> list of policy IDs
}

// NewEBPFLoader creates a new eBPF loader for policies
func NewEBPFLoader(xdpProgram *ebpf.XDPProgram) *EBPFLoader {
	return &EBPFLoader{
		xdpProgram:   xdpProgram,
		nextPolicyID: 1,
		policyIDMap:  make(map[string]uint32),
		hookPolicies: make(map[string][]uint32),
	}
}

// AddPolicy adds a policy to eBPF maps
func (e *EBPFLoader) AddPolicy(policyID uint, hook Hook, action Action) error {
	if e.xdpProgram == nil {
		return fmt.Errorf("XDP program not loaded")
	}

	// Convert hook to eBPF policy entry
	// This is a simplified example - you would need to implement
	// proper conversion based on hook type

	// For ACL hooks
	if aclHook, ok := hook.(*ACLHook); ok {
		return e.addACLPolicy(uint32(policyID), aclHook, action)
	}

	// For port filter hooks
	if portHook, ok := hook.(*PortFilterHook); ok {
		return e.addPortFilterPolicy(uint32(policyID), portHook, action)
	}

	// For user policy hooks
	if userHook, ok := hook.(*UserPolicyHook); ok {
		return e.addUserPolicy(uint32(policyID), userHook, action)
	}

	return fmt.Errorf("unsupported hook type: %T", hook)
}

// addACLPolicy adds an ACL policy to eBPF
func (e *EBPFLoader) addACLPolicy(policyID uint32, hook *ACLHook, action Action) error {
	// Convert action
	ebpfAction := uint32(action)

	// Convert hook point
	ebpfHookPoint := uint32(hook.HookPoint())

	var policyIDs []uint32

	// For ACL hooks, we need to create policies for each network/IP
	// Since eBPF policies are simple (single IP/network), we create multiple policies
	// if the hook has multiple networks

	// Convert protocols to protocol mask
	protocolMask := uint8(0)
	if len(hook.protocols) > 0 {
		for protocol := range hook.protocols {
			switch protocol {
			case "tcp":
				protocolMask |= 0x01
			case "udp":
				protocolMask |= 0x02
			case "icmp":
				protocolMask |= 0x04
			}
		}
	}

	// Source IPs
	if len(hook.srcMatcher.Networks) > 0 || len(hook.srcMatcher.IPs) > 0 {
		for _, network := range hook.srcMatcher.Networks {
			// Create policy for network with CIDR mask
			srcIP := network.IP
			srcMask := ipToUint32(net.IP(network.Mask))
			dstIP := net.IPv4(0, 0, 0, 0) // Any destination

			currentID := policyID + uint32(len(policyIDs))
			if err := e.xdpProgram.AddPolicyWithMask(
				currentID,
				ebpfHookPoint,
				ebpfAction,
				srcIP,
				dstIP,
				srcMask,
				0,          // No destination mask
				0, 0, 0, 0, // Any ports
				protocolMask,
			); err != nil {
				return fmt.Errorf("failed to add ACL source network policy: %w", err)
			}
			policyIDs = append(policyIDs, currentID)
		}

		for _, ip := range hook.srcMatcher.IPs {
			dstIP := net.IPv4(0, 0, 0, 0) // Any destination

			currentID := policyID + uint32(len(policyIDs))
			if err := e.xdpProgram.AddPolicyWithMask(
				currentID,
				ebpfHookPoint,
				ebpfAction,
				ip,
				dstIP,
				0xFFFFFFFF, // Exact match mask
				0,          // No destination mask
				0, 0, 0, 0, // Any ports
				protocolMask,
			); err != nil {
				return fmt.Errorf("failed to add ACL source IP policy: %w", err)
			}
			policyIDs = append(policyIDs, currentID)
		}
	}

	// Destination IPs
	if len(hook.dstMatcher.Networks) > 0 || len(hook.dstMatcher.IPs) > 0 {
		for _, network := range hook.dstMatcher.Networks {
			srcIP := net.IPv4(0, 0, 0, 0) // Any source
			dstIP := network.IP
			dstMask := ipToUint32(net.IP(network.Mask))

			currentID := policyID + uint32(len(policyIDs))
			if err := e.xdpProgram.AddPolicyWithMask(
				currentID,
				ebpfHookPoint,
				ebpfAction,
				srcIP,
				dstIP,
				0,          // No source mask
				dstMask,    // Destination network mask
				0, 0, 0, 0, // Any ports
				protocolMask,
			); err != nil {
				return fmt.Errorf("failed to add ACL destination network policy: %w", err)
			}
			policyIDs = append(policyIDs, currentID)
		}

		for _, ip := range hook.dstMatcher.IPs {
			srcIP := net.IPv4(0, 0, 0, 0) // Any source

			currentID := policyID + uint32(len(policyIDs))
			if err := e.xdpProgram.AddPolicyWithMask(
				currentID,
				ebpfHookPoint,
				ebpfAction,
				srcIP,
				ip,
				0,          // No source mask
				0xFFFFFFFF, // Exact match mask for destination
				0, 0, 0, 0, // Any ports
				protocolMask,
			); err != nil {
				return fmt.Errorf("failed to add ACL destination IP policy: %w", err)
			}
			policyIDs = append(policyIDs, currentID)
		}
	}

	// If no specific IPs/networks, create a catch-all policy
	if len(policyIDs) == 0 {
		if err := e.xdpProgram.AddPolicyWithMask(
			policyID,
			ebpfHookPoint,
			ebpfAction,
			net.IPv4(0, 0, 0, 0),
			net.IPv4(0, 0, 0, 0),
			0, 0, // No masks
			0, 0, 0, 0, // Any ports
			protocolMask,
		); err != nil {
			return fmt.Errorf("failed to add catch-all ACL policy: %w", err)
		}
		policyIDs = append(policyIDs, policyID)
	}

	// Store policy IDs for this hook
	e.hookPolicies[hook.Name()] = policyIDs

	log.Printf("eBPF: Added ACL policy for hook %s: %d policy entries created (policy IDs: %v)",
		hook.Name(), len(policyIDs), policyIDs)

	return nil
}

// addPortFilterPolicy adds a port filter policy to eBPF
func (e *EBPFLoader) addPortFilterPolicy(policyID uint32, hook *PortFilterHook, action Action) error {
	ebpfAction := uint32(action)
	ebpfHookPoint := uint32(hook.HookPoint())

	// Convert protocols to protocol mask
	protocolMask := uint8(0)
	if len(hook.protocols) > 0 {
		for protocol := range hook.protocols {
			switch protocol {
			case "tcp":
				protocolMask |= 0x01
			case "udp":
				protocolMask |= 0x02
			case "icmp":
				protocolMask |= 0x04
			}
		}
	}

	var policyIDs []uint32

	// Create policies for each port (single port, not range)
	for _, port := range hook.portMatcher.Ports {
		// Source port policy
		currentID := policyID + uint32(len(policyIDs))
		if err := e.xdpProgram.AddPolicyWithMask(
			currentID,
			ebpfHookPoint,
			ebpfAction,
			net.IPv4(0, 0, 0, 0),
			net.IPv4(0, 0, 0, 0),
			0, 0, // No IP masks
			port, 0, 0, 0, // Source port, no range, any dest port
			protocolMask,
		); err != nil {
			return fmt.Errorf("failed to add port filter policy: %w", err)
		}
		policyIDs = append(policyIDs, currentID)

		// Destination port policy
		currentID = policyID + uint32(len(policyIDs))
		if err := e.xdpProgram.AddPolicyWithMask(
			currentID,
			ebpfHookPoint,
			ebpfAction,
			net.IPv4(0, 0, 0, 0),
			net.IPv4(0, 0, 0, 0),
			0, 0, // No IP masks
			0, 0, port, 0, // Any source port, dest port, no range
			protocolMask,
		); err != nil {
			return fmt.Errorf("failed to add port filter policy: %w", err)
		}
		policyIDs = append(policyIDs, currentID)
	}

	// Handle port ranges (use range support in eBPF, not expansion)
	for _, portRange := range hook.portMatcher.PortRanges {
		// Source port range
		currentID := policyID + uint32(len(policyIDs))
		if err := e.xdpProgram.AddPolicyWithMask(
			currentID,
			ebpfHookPoint,
			ebpfAction,
			net.IPv4(0, 0, 0, 0),
			net.IPv4(0, 0, 0, 0),
			0, 0, // No IP masks
			portRange.Start, portRange.End, 0, 0, // Source port range
			protocolMask,
		); err != nil {
			return fmt.Errorf("failed to add port range policy: %w", err)
		}
		policyIDs = append(policyIDs, currentID)

		// Destination port range
		currentID = policyID + uint32(len(policyIDs))
		if err := e.xdpProgram.AddPolicyWithMask(
			currentID,
			ebpfHookPoint,
			ebpfAction,
			net.IPv4(0, 0, 0, 0),
			net.IPv4(0, 0, 0, 0),
			0, 0, // No IP masks
			0, 0, portRange.Start, portRange.End, // Dest port range
			protocolMask,
		); err != nil {
			return fmt.Errorf("failed to add port range policy: %w", err)
		}
		policyIDs = append(policyIDs, currentID)
	}

	// Store policy IDs for this hook
	e.hookPolicies[hook.Name()] = policyIDs

	log.Printf("eBPF: Added PortFilter policy for hook %s: %d policy entries created (policy IDs: %v)",
		hook.Name(), len(policyIDs), policyIDs)

	return nil
}

// addUserPolicy adds a user policy to eBPF
// Note: User policies are more complex and may need special handling
func (e *EBPFLoader) addUserPolicy(policyID uint32, hook *UserPolicyHook, action Action) error {
	// User policies are typically enforced at the control plane level
	// For eBPF, we might need to maintain a user->IP mapping
	// This is a simplified implementation

	ebpfAction := uint32(action)
	ebpfHookPoint := uint32(hook.HookPoint())

	// Create a catch-all policy for user-based rules
	// In production, you would maintain a user->IP mapping in eBPF
	if err := e.xdpProgram.AddPolicy(
		policyID,
		ebpfHookPoint,
		ebpfAction,
		net.IPv4(0, 0, 0, 0),
		net.IPv4(0, 0, 0, 0),
		0, 0, 0,
	); err != nil {
		return fmt.Errorf("failed to add user policy: %w", err)
	}

	return nil
}

// RemovePolicy removes a policy from eBPF maps
func (e *EBPFLoader) RemovePolicy(policyID uint) error {
	if e.xdpProgram == nil {
		return fmt.Errorf("XDP program not loaded")
	}

	return e.xdpProgram.RemovePolicy(uint32(policyID))
}

// RemoveHookPolicies removes all policies for a hook
func (e *EBPFLoader) RemoveHookPolicies(hookName string) error {
	if e.xdpProgram == nil {
		return fmt.Errorf("XDP program not loaded")
	}

	policyIDs, exists := e.hookPolicies[hookName]
	if !exists {
		return nil // No policies to remove
	}

	for _, policyID := range policyIDs {
		if err := e.xdpProgram.RemovePolicy(policyID); err != nil {
			return fmt.Errorf("failed to remove policy %d: %w", policyID, err)
		}
	}

	delete(e.hookPolicies, hookName)
	delete(e.policyIDMap, hookName)

	return nil
}

// GetOrAllocatePolicyID gets or allocates a policy ID for a hook
func (e *EBPFLoader) GetOrAllocatePolicyID(hookName string) uint32 {
	if id, exists := e.policyIDMap[hookName]; exists {
		return id
	}

	id := e.nextPolicyID
	e.policyIDMap[hookName] = id
	e.nextPolicyID++
	return id
}

// Helper functions for IP conversion
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(ip uint32) net.IP {
	return net.IP{
		byte(ip >> 24),
		byte(ip >> 16),
		byte(ip >> 8),
		byte(ip),
	}
}

// AddRoute adds a routing rule to eBPF
func (e *EBPFLoader) AddRoute(network *net.IPNet, gateway net.IP, metric int) error {
	if e.xdpProgram == nil {
		return fmt.Errorf("XDP program not loaded")
	}
	return e.xdpProgram.AddRoute(network, gateway, metric)
}

// UpdateRoute updates an existing routing rule in eBPF
func (e *EBPFLoader) UpdateRoute(network *net.IPNet, gateway net.IP, metric int) error {
	if e.xdpProgram == nil {
		return fmt.Errorf("XDP program not loaded")
	}
	return e.xdpProgram.UpdateRoute(network, gateway, metric)
}

// DeleteRoute removes a routing rule from eBPF
func (e *EBPFLoader) DeleteRoute(network *net.IPNet) error {
	if e.xdpProgram == nil {
		return fmt.Errorf("XDP program not loaded")
	}
	return e.xdpProgram.DeleteRoute(network)
}

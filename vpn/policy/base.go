package policy

import (
	"net"
)

// BaseHook provides a base implementation for policy hooks
type BaseHook struct {
	name      string
	hookPoint HookPoint
	priority  int
}

// NewBaseHook creates a new base hook
func NewBaseHook(name string, hookPoint HookPoint, priority int) *BaseHook {
	return &BaseHook{
		name:      name,
		hookPoint: hookPoint,
		priority:  priority,
	}
}

// Name returns the name of the hook
func (b *BaseHook) Name() string {
	return b.name
}

// HookPoint returns the hook point
func (b *BaseHook) HookPoint() HookPoint {
	return b.hookPoint
}

// Priority returns the priority
func (b *BaseHook) Priority() int {
	return b.priority
}

// Execute is a placeholder - should be overridden
func (b *BaseHook) Execute(ctx *Context) Action {
	return ActionAllow
}

// IPMatcher matches IP addresses using optimized Trie tree
type IPMatcher struct {
	Networks []*net.IPNet
	IPs      []net.IP
	trie     *IPTrie
	useTrie  bool // Use trie for matching when enabled
}

// NewIPMatcher creates a new IP matcher
func NewIPMatcher() *IPMatcher {
	return &IPMatcher{
		Networks: make([]*net.IPNet, 0),
		IPs:      make([]net.IP, 0),
		trie:     NewIPTrie(),
		useTrie:  true, // Enable trie by default for better performance
	}
}

// AddNetwork adds a network to match
func (m *IPMatcher) AddNetwork(network *net.IPNet) {
	m.Networks = append(m.Networks, network)
	if m.useTrie {
		m.trie.AddNetwork(network)
	}
}

// AddIP adds an IP to match
func (m *IPMatcher) AddIP(ip net.IP) {
	m.IPs = append(m.IPs, ip)
	if m.useTrie {
		m.trie.AddIP(ip)
	}
}

// Match checks if an IP matches
// Uses Trie tree for O(32) complexity instead of O(n)
func (m *IPMatcher) Match(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Use trie for better performance when enabled
	if m.useTrie && (len(m.IPs) > 0 || len(m.Networks) > 0) {
		return m.trie.Match(ip)
	}

	// Fallback to linear search (for backward compatibility or small sets)
	// Check exact IPs
	for _, matchIP := range m.IPs {
		if ip.Equal(matchIP) {
			return true
		}
	}

	// Check networks
	for _, network := range m.Networks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// EnableTrie enables or disables trie-based matching
func (m *IPMatcher) EnableTrie(enable bool) {
	if enable && !m.useTrie {
		// Rebuild trie
		m.trie.Clear()
		for _, ip := range m.IPs {
			m.trie.AddIP(ip)
		}
		for _, network := range m.Networks {
			m.trie.AddNetwork(network)
		}
	}
	m.useTrie = enable
}

// PortMatcher matches ports
type PortMatcher struct {
	Ports      []uint16
	PortRanges []PortRange
}

// PortRange represents a range of ports
type PortRange struct {
	Start uint16
	End   uint16
}

// NewPortMatcher creates a new port matcher
func NewPortMatcher() *PortMatcher {
	return &PortMatcher{
		Ports:      make([]uint16, 0),
		PortRanges: make([]PortRange, 0),
	}
}

// AddPort adds a port to match
func (m *PortMatcher) AddPort(port uint16) {
	m.Ports = append(m.Ports, port)
}

// AddRange adds a port range to match
func (m *PortMatcher) AddRange(start, end uint16) {
	m.PortRanges = append(m.PortRanges, PortRange{Start: start, End: end})
}

// Match checks if a port matches
func (m *PortMatcher) Match(port uint16) bool {
	// Check exact ports
	for _, p := range m.Ports {
		if port == p {
			return true
		}
	}

	// Check ranges
	for _, r := range m.PortRanges {
		if port >= r.Start && port <= r.End {
			return true
		}
	}

	return false
}

package policy

import (
	"net"
	"strings"
)

// Example: ACL (Access Control List) Hook
type ACLHook struct {
	*BaseHook
	srcMatcher    *IPMatcher
	dstMatcher    *IPMatcher
	protocols     map[string]bool // Supported protocols: "tcp", "udp", "icmp"
	action        Action
}

// NewACLHook creates a new ACL hook
func NewACLHook(name string, hookPoint HookPoint, priority int, action Action) *ACLHook {
	return &ACLHook{
		BaseHook:   NewBaseHook(name, hookPoint, priority),
		srcMatcher: NewIPMatcher(),
		dstMatcher: NewIPMatcher(),
		protocols:  make(map[string]bool),
		action:     action,
	}
}

// AddSourceNetwork adds a source network to match
func (h *ACLHook) AddSourceNetwork(network *net.IPNet) {
	h.srcMatcher.AddNetwork(network)
}

// AddDestinationNetwork adds a destination network to match
func (h *ACLHook) AddDestinationNetwork(network *net.IPNet) {
	h.dstMatcher.AddNetwork(network)
}

// AddSourceIP adds a source IP to match
func (h *ACLHook) AddSourceIP(ip net.IP) {
	h.srcMatcher.AddIP(ip)
}

// AddDestinationIP adds a destination IP to match
func (h *ACLHook) AddDestinationIP(ip net.IP) {
	h.dstMatcher.AddIP(ip)
}

// AddProtocol adds a protocol to filter (e.g., "tcp", "udp", "icmp")
func (h *ACLHook) AddProtocol(protocol string) {
	if protocol != "" {
		// Normalize protocol name to lowercase
		h.protocols[strings.ToLower(protocol)] = true
	}
}

// Execute executes the ACL hook
func (h *ACLHook) Execute(ctx *Context) Action {
	srcIP := net.ParseIP(ctx.SrcIP)
	dstIP := net.ParseIP(ctx.DstIP)

	if srcIP == nil || dstIP == nil {
		return ActionAllow
	}

	// Check protocol if specified
	if len(h.protocols) > 0 {
		protocol := strings.ToLower(ctx.Protocol)
		if !h.protocols[protocol] {
			return ActionAllow // Protocol doesn't match, continue
		}
	}

	// Check if source matches
	if len(h.srcMatcher.Networks) > 0 || len(h.srcMatcher.IPs) > 0 {
		if !h.srcMatcher.Match(srcIP) {
			return ActionAllow // No match, continue
		}
	}

	// Check if destination matches
	if len(h.dstMatcher.Networks) > 0 || len(h.dstMatcher.IPs) > 0 {
		if !h.dstMatcher.Match(dstIP) {
			return ActionAllow // No match, continue
		}
	}

	// Match found, return configured action
	return h.action
}

// Example: Port-based filtering hook
type PortFilterHook struct {
	*BaseHook
	portMatcher *PortMatcher
	protocols   map[string]bool // Supported protocols: "tcp", "udp", "icmp"
	action      Action
}

// NewPortFilterHook creates a new port filter hook
func NewPortFilterHook(name string, hookPoint HookPoint, priority int, action Action) *PortFilterHook {
	return &PortFilterHook{
		BaseHook:    NewBaseHook(name, hookPoint, priority),
		portMatcher: NewPortMatcher(),
		protocols:   make(map[string]bool),
		action:      action,
	}
}

// AddPort adds a port to filter
func (h *PortFilterHook) AddPort(port uint16) {
	h.portMatcher.AddPort(port)
}

// AddPortRange adds a port range to filter
func (h *PortFilterHook) AddPortRange(start, end uint16) {
	h.portMatcher.AddRange(start, end)
}

// AddProtocol adds a protocol to filter (e.g., "tcp", "udp", "icmp")
func (h *PortFilterHook) AddProtocol(protocol string) {
	if protocol != "" {
		// Normalize protocol name to lowercase
		h.protocols[strings.ToLower(protocol)] = true
	}
}

// Execute executes the port filter hook
func (h *PortFilterHook) Execute(ctx *Context) Action {
	// Check protocol if specified
	if len(h.protocols) > 0 {
		protocol := strings.ToLower(ctx.Protocol)
		if !h.protocols[protocol] {
			return ActionAllow // Protocol doesn't match, continue
		}
	}

	// Check source port
	if h.portMatcher.Match(ctx.SrcPort) {
		return h.action
	}

	// Check destination port
	if h.portMatcher.Match(ctx.DstPort) {
		return h.action
	}

	return ActionAllow
}

// Example: User-based policy hook
type UserPolicyHook struct {
	*BaseHook
	allowedUsers map[uint]bool
	deniedUsers  map[uint]bool
}

// NewUserPolicyHook creates a new user policy hook
func NewUserPolicyHook(name string, hookPoint HookPoint, priority int) *UserPolicyHook {
	return &UserPolicyHook{
		BaseHook:     NewBaseHook(name, hookPoint, priority),
		allowedUsers: make(map[uint]bool),
		deniedUsers:  make(map[uint]bool),
	}
}

// AllowUser allows a user
func (h *UserPolicyHook) AllowUser(userID uint) {
	h.allowedUsers[userID] = true
	delete(h.deniedUsers, userID)
}

// DenyUser denies a user
func (h *UserPolicyHook) DenyUser(userID uint) {
	h.deniedUsers[userID] = true
	delete(h.allowedUsers, userID)
}

// Execute executes the user policy hook
func (h *UserPolicyHook) Execute(ctx *Context) Action {
	// Check if user is denied
	if h.deniedUsers[ctx.UserID] {
		return ActionDeny
	}

	// Check if user is explicitly allowed
	if len(h.allowedUsers) > 0 {
		if !h.allowedUsers[ctx.UserID] {
			return ActionDeny // Not in allowed list
		}
	}

	return ActionAllow
}

// Example: Rate limiting hook (simplified)
type RateLimitHook struct {
	*BaseHook
	limitPerSecond int
	// In production, use a proper rate limiter with time windows
}

// NewRateLimitHook creates a new rate limit hook
func NewRateLimitHook(name string, hookPoint HookPoint, priority int, limitPerSecond int) *RateLimitHook {
	return &RateLimitHook{
		BaseHook:       NewBaseHook(name, hookPoint, priority),
		limitPerSecond: limitPerSecond,
	}
}

// Execute executes the rate limit hook
func (h *RateLimitHook) Execute(ctx *Context) Action {
	// In production, implement proper rate limiting
	// This is a simplified example
	// You would track packet counts per user/IP in a map with timestamps
	return ActionAllow
}

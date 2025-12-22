package policy

import (
	"sync"
)

// PolicyIndex provides indexed access to hooks for faster matching
type PolicyIndex struct {
	byProtocol map[string][]Hook // Group by protocol (tcp, udp, icmp, etc.)
	byPort     map[uint16][]Hook // Group by destination port
	byAction   map[Action][]Hook  // Group by action (for quick filtering)
	defaultHooks []Hook           // Hooks without specific filters
	allHooks   []Hook            // All hooks (fallback)
	lock       sync.RWMutex
}

// NewPolicyIndex creates a new policy index
func NewPolicyIndex() *PolicyIndex {
	return &PolicyIndex{
		byProtocol:  make(map[string][]Hook),
		byPort:      make(map[uint16][]Hook),
		byAction:    make(map[Action][]Hook),
		defaultHooks: make([]Hook, 0),
		allHooks:    make([]Hook, 0),
	}
}

// AddHook adds a hook to the index
func (pi *PolicyIndex) AddHook(hook Hook) {
	pi.lock.Lock()
	defer pi.lock.Unlock()

	pi.allHooks = append(pi.allHooks, hook)

	// Try to extract protocol and port from hook name/type
	// This is a simple heuristic - in practice, hooks should expose this info
	// For now, we'll index all hooks in defaultHooks and let Execute filter them
	pi.defaultHooks = append(pi.defaultHooks, hook)
}

// GetHooksForContext returns hooks that might match the given context
// This is an optimization to reduce the number of hooks to check
func (pi *PolicyIndex) GetHooksForContext(ctx *Context) []Hook {
	pi.lock.RLock()
	defer pi.lock.RUnlock()

	// For now, return all hooks (full optimization requires hook interface changes)
	// In the future, we can filter by:
	// - Protocol: if ctx.Protocol is "tcp", only check TCP hooks
	// - Port: if ctx.DstPort is 80, prioritize hooks that match port 80
	// - Action: if we're looking for DENY, only check DENY hooks

	// Simple optimization: if protocol is specified, try to get protocol-specific hooks
	if ctx.Protocol != "" {
		if protocolHooks, ok := pi.byProtocol[ctx.Protocol]; ok {
			// Return protocol-specific hooks first, then default hooks
			result := make([]Hook, 0, len(protocolHooks)+len(pi.defaultHooks))
			result = append(result, protocolHooks...)
			result = append(result, pi.defaultHooks...)
			return result
		}
	}

	// Return all hooks (fallback)
	return pi.allHooks
}

// Clear removes all hooks from the index
func (pi *PolicyIndex) Clear() {
	pi.lock.Lock()
	defer pi.lock.Unlock()

	pi.byProtocol = make(map[string][]Hook)
	pi.byPort = make(map[uint16][]Hook)
	pi.byAction = make(map[Action][]Hook)
	pi.defaultHooks = pi.defaultHooks[:0]
	pi.allHooks = pi.allHooks[:0]
}

// Count returns the total number of hooks in the index
func (pi *PolicyIndex) Count() int {
	pi.lock.RLock()
	defer pi.lock.RUnlock()
	return len(pi.allHooks)
}


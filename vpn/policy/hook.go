package policy

// HookPoint represents a point in the packet processing pipeline
// where policies can be applied
type HookPoint int

// MaxHookChainEntries limits how many policies are chained per hook point in eBPF.
// XDP 侧遍历 0..63，因此保持 64 的上限以避免链被截断。
const MaxHookChainEntries = 64

const (
	// HookPreRouting - Before routing decision
	HookPreRouting HookPoint = iota
	// HookPostRouting - After routing decision
	HookPostRouting
	// HookForward - During forwarding
	HookForward
	// HookInput - Input to local system
	HookInput
	// HookOutput - Output from local system
	HookOutput
)

// String returns the string representation of a hook point
func (h HookPoint) String() string {
	switch h {
	case HookPreRouting:
		return "PRE_ROUTING"
	case HookPostRouting:
		return "POST_ROUTING"
	case HookForward:
		return "FORWARD"
	case HookInput:
		return "INPUT"
	case HookOutput:
		return "OUTPUT"
	default:
		return "UNKNOWN"
	}
}

// Action represents the action to take when a policy matches
type Action int

const (
	// ActionAllow - Allow the packet to pass
	ActionAllow Action = iota
	// ActionDeny - Drop the packet
	ActionDeny
	// ActionRedirect - Redirect to another destination
	ActionRedirect
	// ActionLog - Log the packet and allow
	ActionLog
	// ActionNAT - Apply NAT to the packet (eBPF only)
	ActionNAT
	// ActionDirect - Forward directly without VPN (eBPF only)
	ActionDirect
)

// String returns the string representation of an action
func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "ALLOW"
	case ActionDeny:
		return "DENY"
	case ActionRedirect:
		return "REDIRECT"
	case ActionLog:
		return "LOG"
	case ActionNAT:
		return "NAT"
	case ActionDirect:
		return "DIRECT"
	default:
		return "UNKNOWN"
	}
}

// Hook represents a policy hook that can be registered
type Hook interface {
	// Name returns the name of the hook
	Name() string

	// HookPoint returns where this hook should be executed
	HookPoint() HookPoint

	// Priority returns the priority (lower = higher priority)
	Priority() int

	// Execute executes the hook and returns the action
	Execute(ctx *Context) Action
}

// Context provides packet information to policy hooks
type Context struct {
	// Packet information
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol string // "tcp", "udp", "icmp", etc.

	// VPN context
	UserID   uint
	VPNIP    string
	ClientIP string

	// Policy context
	PolicyID uint

	// Metadata (can be extended)
	Metadata map[string]interface{}
}

// NewContext creates a new policy context
func NewContext() *Context {
	return &Context{
		Metadata: make(map[string]interface{}),
	}
}

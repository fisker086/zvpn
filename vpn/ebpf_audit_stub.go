//go:build !ebpf
// +build !ebpf

package vpn

import (
	"github.com/fisker/zvpn/vpn/ebpf"
)

// startEBPFAuditLoggerIfEnabled starts eBPF audit logger if eBPF is enabled
// Stub implementation when eBPF is not compiled
func startEBPFAuditLoggerIfEnabled(ebpfProg *ebpf.XDPProgram) {
	// No-op when eBPF is not compiled
}


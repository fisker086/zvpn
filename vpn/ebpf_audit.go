//go:build ebpf
// +build ebpf

package vpn

import (
	"github.com/fisker/zvpn/vpn/ebpf"
)

// startEBPFAuditLoggerIfEnabled starts eBPF audit logger if eBPF is enabled
func startEBPFAuditLoggerIfEnabled(ebpfProg *ebpf.XDPProgram) {
	if ebpfProg != nil {
		ebpf.StartAuditLogger(ebpfProg)
	}
}


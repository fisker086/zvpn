//go:build !ebpf
// +build !ebpf

package ebpf

// ClearEBPFAuditLogProtocolCache clears the cache to force reload on next access
// Stub implementation when eBPF is not compiled
func ClearEBPFAuditLogProtocolCache() {
	// No-op when eBPF is not compiled
}

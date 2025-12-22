//go:build !linux

package vpn

// ============================================================================
// Platform Stubs (Non-Linux platforms)
// ============================================================================

// getBatchListener returns nil on non-Linux platforms
func getBatchListener() func(*VPNServer, *TUNDevice) {
	return nil
}

// getAFXDPListener returns nil for non-Linux platforms
func getAFXDPListener() func(*VPNServer, *XDPSocket) {
	return nil
}


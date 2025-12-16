//go:build !linux

package vpn

import (
	"fmt"
	"net"
)

// TUNDevice represents a TUN network device (stub for non-Linux systems)
type TUNDevice struct {
	name string
}

// NewTUNDevice creates a new TUN device (stub - returns error on non-Linux)
func NewTUNDevice(name, address string, mtu int) (*TUNDevice, error) {
	return nil, fmt.Errorf("TUN device is only supported on Linux")
}

// Read reads a packet from the TUN device (stub)
func (t *TUNDevice) Read(buf []byte) (int, error) {
	return 0, fmt.Errorf("TUN device not supported on this platform")
}

// Write writes a packet to the TUN device (stub)
func (t *TUNDevice) Write(buf []byte) (int, error) {
	return 0, fmt.Errorf("TUN device not supported on this platform")
}

// Name returns the interface name
func (t *TUNDevice) Name() string {
	if t != nil {
		return t.name
	}
	return ""
}

// Close closes the TUN device (stub)
func (t *TUNDevice) Close() error {
	return nil
}

// GetIP returns the actual IP address of the TUN device (stub)
func (t *TUNDevice) GetIP() (net.IP, error) {
	return nil, fmt.Errorf("TUN device not supported on this platform")
}

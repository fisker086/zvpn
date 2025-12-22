//go:build !linux

package vpn

import "fmt"

// XDPSocket stub for non-Linux platforms
type XDPSocket struct{}

// NewXDPSocket returns an error on non-Linux platforms
func NewXDPSocket(ifname string, queueID int) (*XDPSocket, error) {
	return nil, fmt.Errorf("AF_XDP is only supported on Linux")
}

func (x *XDPSocket) Read(buf []byte) (int, error) {
	return 0, fmt.Errorf("AF_XDP not supported on this platform")
}

func (x *XDPSocket) Write(buf []byte) (int, error) {
	return 0, fmt.Errorf("AF_XDP not supported on this platform")
}

func (x *XDPSocket) Close() error {
	return nil
}

func (x *XDPSocket) Enable() error {
	return fmt.Errorf("AF_XDP not supported on this platform")
}

func (x *XDPSocket) Disable() {}

func (x *XDPSocket) IsEnabled() bool {
	return false
}

func (x *XDPSocket) GetQueueID() int {
	return 0
}

func (x *XDPSocket) GetInterfaceIndex() int {
	return 0
}


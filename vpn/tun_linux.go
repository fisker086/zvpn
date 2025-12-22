//go:build linux

package vpn

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	TUNSETIFF = 0x400454ca
	IFF_TUN   = 0x0001
	IFF_NO_PI = 0x1000
)

// TUNDevice represents a TUN network device
type TUNDevice struct {
	file    *os.File
	name    string
	address string
	mtu     int
	link    netlink.Link
}

// GetIP returns the actual IP address of the TUN device
func (t *TUNDevice) GetIP() (net.IP, error) {
	if t.link == nil {
		// Try to get link by name
		link, err := netlink.LinkByName(t.name)
		if err != nil {
			return nil, fmt.Errorf("failed to find interface %s: %w", t.name, err)
		}
		t.link = link
	}

	// Get IPv4 addresses on the interface
	addrs, err := netlink.AddrList(t.link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("failed to list addresses on interface %s: %w", t.name, err)
	}

	// Return the first IPv4 address
	for _, addr := range addrs {
		if addr.IP != nil && addr.IP.To4() != nil {
			return addr.IP, nil
		}
	}

	// Fallback: parse from address string
	if t.address != "" {
		ip, _, err := net.ParseCIDR(t.address)
		if err == nil && ip != nil {
			return ip, nil
		}
	}

	return nil, fmt.Errorf("no IPv4 address found on TUN device %s", t.name)
}

// ifReq is used for ioctl calls
type ifReq struct {
	Name  [16]byte
	Flags uint16
	pad   [22]byte
}

// NewTUNDevice creates or opens an existing TUN device on Linux using netlink
func NewTUNDevice(name, address string, mtu int) (*TUNDevice, error) {
	// Open /dev/net/tun
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %w", err)
	}

	// Try to find the interface first to check if it already exists
	_, err = netlink.LinkByName(name)
	var actualName string
	var req ifReq

	if err == nil {
		// Interface already exists, just open it without creating new
		actualName = name
		log.Printf("Reusing existing TUN device: %s", actualName)
	} else {
		// Interface doesn't exist, create new TUN interface using ioctl
		copy(req.Name[:], name)
		req.Flags = IFF_TUN | IFF_NO_PI

		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), TUNSETIFF, uintptr(unsafe.Pointer(&req)))
		if errno != 0 {
			file.Close()
			return nil, fmt.Errorf("failed to create TUN device: %v", errno)
		}

		// Get the actual device name
		actualName = string(req.Name[:])
		for i, c := range actualName {
			if c == 0 {
				actualName = actualName[:i]
				break
			}
		}
	}

	tun := &TUNDevice{
		file:    file,
		name:    actualName,
		address: address,
		mtu:     mtu,
	}

	// Configure the interface using netlink (no exec commands)
	// This is safe even if the interface already exists
	if err := tun.configure(); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to configure TUN device: %w", err)
	}

	log.Printf("TUN device %s (address: %s) ready for use", actualName, address)
	return tun, nil
}

// configure sets up the TUN device using netlink (no exec commands)
func (t *TUNDevice) configure() error {
	// Get link by name
	link, err := netlink.LinkByName(t.name)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", t.name, err)
	}
	t.link = link

	// Parse CIDR address
	ip, ipNet, err := net.ParseCIDR(t.address)
	if err != nil {
		return fmt.Errorf("invalid address %s: %w", t.address, err)
	}

	// IPv6 is allowed by default, no need to disable it

	// Remove all existing IPv4 addresses first to ensure we use the new one
	existingAddrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to list existing addresses: %w", err)
	}

	// Track if any address removal failed
	addrRemovalFailed := false
	for _, addr := range existingAddrs {
		if err = netlink.AddrDel(link, &addr); err != nil {
			log.Printf("Warning: failed to remove existing address %s: %v", addr.IPNet.String(), err)
			addrRemovalFailed = true
		} else {
			log.Printf("Removed existing address: %s", addr.IPNet.String())
		}
	}

	// If address removal failed, check if we need to take additional action
	if addrRemovalFailed {
		// Re-list addresses to see what remains
		remainingAddrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err == nil && len(remainingAddrs) > 0 {
			log.Printf("TUN device %s still has %d addresses after cleanup attempt", t.name, len(remainingAddrs))
			// Continue anyway, but this might cause unexpected behavior
		}
	}

	// Add the new IP address to interface using netlink
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: ipNet.Mask,
		},
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add new address: %w", err)
	}
	ones, _ := ipNet.Mask.Size()
	log.Printf("TUN device %s: Successfully added IP address %s/%d", t.name, ip.String(), ones)

	// Verify the address was added correctly
	verifyAddrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err == nil {
		for _, verifyAddr := range verifyAddrs {
			log.Printf("TUN device %s: Current IP address: %s", t.name, verifyAddr.IPNet.String())
		}
	}

	// Set MTU using netlink
	if t.mtu > 0 {
		if err := netlink.LinkSetMTU(link, t.mtu); err != nil {
			return fmt.Errorf("failed to set MTU: %w", err)
		}
	}

	// Bring interface up using netlink
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up interface: %w", err)
	}

	// IPv6 is allowed by default, no need to remove auto-assigned addresses

	// Enable IP forwarding by writing to /proc
	if err := enableIPForwarding(); err != nil {
		log.Printf("Warning: failed to enable IP forwarding: %v", err)
	}

	log.Printf("TUN device %s configured successfully using netlink", t.name)
	return nil
}

// enableIPForwarding enables IPv4 forwarding via /proc
// Only writes to /proc if forwarding is not already enabled
func enableIPForwarding() error {
	// First read current state to avoid unnecessary writes
	file, err := os.OpenFile("/proc/sys/net/ipv4/ip_forward", os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to open ip_forward: %w", err)
	}
	defer file.Close()

	// Read current state
	buf := make([]byte, 2)
	n, err := file.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read ip_forward: %w", err)
	}

	// Check if forwarding is already enabled
	if n > 0 && buf[0] == '1' {
		// Forwarding already enabled, no need to write
		return nil
	}

	// Forwarding is not enabled, write '1'
	if _, err := file.WriteAt([]byte("1\n"), 0); err != nil {
		return fmt.Errorf("failed to write ip_forward: %w", err)
	}

	return nil
}

// IPv6 is now allowed by default, no need to disable it

// Read reads a packet from the TUN device
// Uses syscall.Read to avoid "not pollable" errors in Docker
func (t *TUNDevice) Read(buf []byte) (int, error) {
	// Use syscall.Read instead of file.Read to avoid "not pollable" errors
	// This is more reliable in Docker containers
	n, err := syscall.Read(int(t.file.Fd()), buf)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Write writes a packet to the TUN device
// Uses syscall.Write for consistency
func (t *TUNDevice) Write(buf []byte) (int, error) {
	// Use syscall.Write for consistency with Read
	n, err := syscall.Write(int(t.file.Fd()), buf)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Name returns the interface name
func (t *TUNDevice) Name() string {
	return t.name
}

// Close closes the TUN device and cleans up using netlink
func (t *TUNDevice) Close() error {
	// Bring interface down using netlink
	if t.link != nil {
		if err := netlink.LinkSetDown(t.link); err != nil {
			log.Printf("Warning: failed to bring down interface: %v", err)
		}
	}

	// Close file descriptor
	if t.file != nil {
		return t.file.Close()
	}
	return nil
}

// GetStats returns interface statistics using netlink
func (t *TUNDevice) GetStats() (*netlink.LinkStatistics, error) {
	if t.link == nil {
		return nil, fmt.Errorf("link not initialized")
	}

	// Refresh link info
	link, err := netlink.LinkByName(t.name)
	if err != nil {
		return nil, fmt.Errorf("failed to get link: %w", err)
	}

	attrs := link.Attrs()
	return attrs.Statistics, nil
}

// SetTxQueueLen sets the transmit queue length using netlink
func (t *TUNDevice) SetTxQueueLen(qlen int) error {
	if t.link == nil {
		return fmt.Errorf("link not initialized")
	}

	if err := netlink.LinkSetTxQLen(t.link, qlen); err != nil {
		return fmt.Errorf("failed to set tx queue length: %w", err)
	}

	return nil
}

// AddRoute adds a route to the TUN device using netlink
func (t *TUNDevice) AddRoute(dst *net.IPNet, gw net.IP) error {
	if t.link == nil {
		return fmt.Errorf("link not initialized")
	}

	route := &netlink.Route{
		LinkIndex: t.link.Attrs().Index,
		Dst:       dst,
		Gw:        gw,
	}

	if err := netlink.RouteAdd(route); err != nil {
		// If route already exists, it's not an error
		// netlink包会返回unix.EEXIST错误，os.IsExist不适用于netlink错误
		if err != unix.EEXIST {
			return fmt.Errorf("failed to add route: %w", err)
		}
		// 路由已存在，打印调试日志但不返回错误
		log.Printf("Route %s via %s already exists on interface %s", dst.String(), gw.String(), t.name)
	}

	return nil
}

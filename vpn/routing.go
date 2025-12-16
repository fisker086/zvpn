package vpn

import (
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type RouteManager struct {
	interfaceName string
}

func NewRouteManager(interfaceName string) *RouteManager {
	return &RouteManager{
		interfaceName: interfaceName,
	}
}

// AddRoute adds a route using netlink
func (rm *RouteManager) AddRoute(network *net.IPNet, gateway net.IP, metric int) error {
	// Get the network interface by name
	link, err := netlink.LinkByName(rm.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", rm.interfaceName, err)
	}

	// Create route
	route := &netlink.Route{
		Dst:       network,
		Gw:        gateway,
		LinkIndex: link.Attrs().Index,
		Priority:  metric,
	}

	// Add the route
	if err := netlink.RouteAdd(route); err != nil {
		// Check if route already exists (EEXIST)
		if errno, ok := err.(syscall.Errno); !ok || errno != syscall.EEXIST {
			return fmt.Errorf("failed to add route %s via %s: %w",
				network.String(), gateway.String(), err)
		}
		// Route already exists, which is fine
	}

	return nil
}

// DeleteRoute deletes a route using netlink
func (rm *RouteManager) DeleteRoute(network *net.IPNet) error {
	// Get the network interface by name
	link, err := netlink.LinkByName(rm.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", rm.interfaceName, err)
	}

	// Find the route
	routes, err := netlink.RouteList(link, unix.AF_INET)
	if err != nil {
		return fmt.Errorf("failed to list routes: %w", err)
	}

	// Find matching route and delete it
	for _, route := range routes {
		if route.Dst != nil && route.Dst.String() == network.String() {
			if err := netlink.RouteDel(&route); err != nil {
				return fmt.Errorf("failed to delete route %s: %w", network.String(), err)
			}
			return nil
		}
	}

	// Route not found, which is fine
	return nil
}

// ParseCIDR parses a CIDR string and returns an IPNet
func ParseCIDR(cidr string) (*net.IPNet, error) {
	if !strings.Contains(cidr, "/") {
		// Assume /32 for single IP
		cidr = cidr + "/32"
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	return ipNet, err
}

// CreateAndConfigureTUN is deprecated, TUN device is now managed by VPNServer
func (rm *RouteManager) CreateAndConfigureTUN() error {
	log.Printf("Note: CreateAndConfigureTUN is deprecated, TUN device management moved to VPNServer")
	return nil
}

// GetEgressInterfaceIP gets the IP address of the egress interface for default route
// This is used for NAT masquerading - returns the IP that will be used as the source IP
func GetEgressInterfaceIP() (net.IP, error) {
	// Get default route (0.0.0.0/0)
	routes, err := netlink.RouteList(nil, unix.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	var defaultRoute *netlink.Route
	for i := range routes {
		if routes[i].Dst == nil {
			// Default route (destination is nil)
			defaultRoute = &routes[i]
			break
		}
	}

	if defaultRoute == nil {
		return nil, fmt.Errorf("default route not found")
	}

	// Get the egress interface
	var link netlink.Link
	if defaultRoute.LinkIndex > 0 {
		link, err = netlink.LinkByIndex(defaultRoute.LinkIndex)
		if err != nil {
			return nil, fmt.Errorf("failed to get egress interface by index %d: %w", defaultRoute.LinkIndex, err)
		}
	} else if defaultRoute.Gw != nil {
		// If we have a gateway, find the interface that can reach it
		link, err = findInterfaceForGateway(defaultRoute.Gw)
		if err != nil {
			return nil, fmt.Errorf("failed to find interface for gateway %s: %w", defaultRoute.Gw.String(), err)
		}
	} else {
		return nil, fmt.Errorf("default route has no interface or gateway")
	}

	// Get IP addresses on the egress interface
	addrs, err := netlink.AddrList(link, 0) // 使用0表示所有地址族
	if err != nil {
		return nil, fmt.Errorf("failed to list addresses on interface %s: %w", link.Attrs().Name, err)
	}

	// Prefer non-loopback, non-link-local addresses
	for _, addr := range addrs {
		if addr.IP.IsLoopback() || addr.IP.IsLinkLocalUnicast() {
			continue
		}
		if addr.IP.To4() != nil {
			return addr.IP, nil
		}
	}

	// If no suitable address found, return the first IPv4 address
	if len(addrs) > 0 {
		for _, addr := range addrs {
			if addr.IP.To4() != nil {
				return addr.IP, nil
			}
		}
	}

	return nil, fmt.Errorf("no IPv4 address found on egress interface %s", link.Attrs().Name)
}

// findInterfaceForGateway finds the interface that can reach a given gateway
func findInterfaceForGateway(gateway net.IP) (netlink.Link, error) {
	routes, err := netlink.RouteList(nil, unix.AF_INET)
	if err != nil {
		return nil, err
	}

	// Find a route that matches the gateway
	for _, route := range routes {
		if route.Gw != nil && route.Gw.Equal(gateway) && route.LinkIndex > 0 {
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err == nil {
				return link, nil
			}
		}
	}

	// Fallback: try all interfaces and check if gateway is in their subnet
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	for _, link := range links {
		addrs, err := netlink.AddrList(link, 0) // 使用0表示所有地址族
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if addr.IPNet != nil && addr.IPNet.Contains(gateway) {
				return link, nil
			}
		}
	}

	return nil, fmt.Errorf("cannot find interface for gateway %s", gateway.String())
}

package policy

import (
	"net"
)

// IPTrie is a binary trie (prefix tree) for efficient IP matching
// Supports both IPv4 and IPv6 addresses
type IPTrie struct {
	children [2]*IPTrie // 0/1 bit
	networks []*net.IPNet
	ips      []net.IP
	isLeaf   bool
}

// NewIPTrie creates a new IP trie
func NewIPTrie() *IPTrie {
	return &IPTrie{
		networks: make([]*net.IPNet, 0),
		ips:      make([]net.IP, 0),
	}
}

// AddIP adds an IP address to the trie
func (t *IPTrie) AddIP(ip net.IP) {
	if ip == nil {
		return
	}

	// Convert to IPv4 if it's IPv4-mapped IPv6
	ip = ip.To4()
	if ip == nil {
		// IPv6 not supported yet, skip
		return
	}

	// Traverse the trie based on IP bits
	current := t
	for i := 0; i < 32; i++ {
		byteIndex := i / 8
		bitIndex := 7 - (i % 8)
		bit := (ip[byteIndex] >> bitIndex) & 1

		if current.children[bit] == nil {
			current.children[bit] = NewIPTrie()
		}
		current = current.children[bit]
	}

	// Add IP to leaf node
	current.ips = append(current.ips, ip)
	current.isLeaf = true
}

// AddNetwork adds a network (CIDR) to the trie
func (t *IPTrie) AddNetwork(network *net.IPNet) {
	if network == nil {
		return
	}

	ip := network.IP.To4()
	if ip == nil {
		// IPv6 not supported yet, skip
		return
	}

	mask, _ := network.Mask.Size()
	if mask > 32 {
		mask = 32
	}

	// Traverse the trie based on network prefix
	current := t
	for i := 0; i < mask; i++ {
		byteIndex := i / 8
		bitIndex := 7 - (i % 8)
		bit := (ip[byteIndex] >> bitIndex) & 1

		if current.children[bit] == nil {
			current.children[bit] = NewIPTrie()
		}
		current = current.children[bit]
	}

	// Add network to node at prefix depth
	current.networks = append(current.networks, network)
	current.isLeaf = true
}

// Match checks if an IP matches any entry in the trie
// Returns true if IP matches any IP or network in the trie
func (t *IPTrie) Match(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Convert to IPv4 if it's IPv4-mapped IPv6
	ip = ip.To4()
	if ip == nil {
		// IPv6 not supported yet
		return false
	}

	// Traverse the trie
	current := t

	// Check exact IPs at root
	for _, matchIP := range current.ips {
		if ip.Equal(matchIP) {
			return true
		}
	}

	// Check networks at root
	for _, network := range current.networks {
		if network.Contains(ip) {
			return true
		}
	}

	// Traverse based on IP bits
	for i := 0; i < 32; i++ {
		byteIndex := i / 8
		bitIndex := 7 - (i % 8)
		bit := (ip[byteIndex] >> bitIndex) & 1

		// Check networks at current node before descending
		for _, network := range current.networks {
			if network.Contains(ip) {
				return true
			}
		}

		// Move to child node
		if current.children[bit] == nil {
			return false
		}
		current = current.children[bit]

		// Check exact IPs at current node
		for _, matchIP := range current.ips {
			if ip.Equal(matchIP) {
				return true
			}
		}

		// Check networks at current node
		for _, network := range current.networks {
			if network.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// Clear removes all entries from the trie
func (t *IPTrie) Clear() {
	t.children[0] = nil
	t.children[1] = nil
	t.networks = t.networks[:0]
	t.ips = t.ips[:0]
	t.isLeaf = false
}

// Count returns the number of entries in the trie
func (t *IPTrie) Count() int {
	count := len(t.ips) + len(t.networks)
	if t.children[0] != nil {
		count += t.children[0].Count()
	}
	if t.children[1] != nil {
		count += t.children[1].Count()
	}
	return count
}


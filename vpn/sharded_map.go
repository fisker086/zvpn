package vpn

import (
	"sync"
)

// ShardedClientMap provides a sharded map for VPN clients to reduce lock contention
// This uses multiple locks (shards) instead of a single global lock
type ShardedClientMap struct {
	shards     []*ClientShard
	shardCount int
}

// ClientShard represents a single shard with its own lock
type ClientShard struct {
	clients map[uint]*VPNClient
	lock    sync.RWMutex
}

// NewShardedClientMap creates a new sharded client map
// shardCount should be a power of 2 for best performance (e.g., 16, 32, 64)
func NewShardedClientMap(shardCount int) *ShardedClientMap {
	if shardCount <= 0 {
		shardCount = 16 // Default to 16 shards
	}
	
	shards := make([]*ClientShard, shardCount)
	for i := range shards {
		shards[i] = &ClientShard{
			clients: make(map[uint]*VPNClient),
		}
	}
	
	return &ShardedClientMap{
		shards:     shards,
		shardCount: shardCount,
	}
}

// getShard returns the shard for a given user ID
func (m *ShardedClientMap) getShard(userID uint) *ClientShard {
	// Use modulo to distribute clients across shards
	return m.shards[userID%uint(m.shardCount)]
}

// Get retrieves a client by user ID
func (m *ShardedClientMap) Get(userID uint) (*VPNClient, bool) {
	shard := m.getShard(userID)
	shard.lock.RLock()
	defer shard.lock.RUnlock()
	client, exists := shard.clients[userID]
	return client, exists
}

// Set stores a client by user ID
func (m *ShardedClientMap) Set(userID uint, client *VPNClient) {
	shard := m.getShard(userID)
	shard.lock.Lock()
	defer shard.lock.Unlock()
	shard.clients[userID] = client
}

// Delete removes a client by user ID
func (m *ShardedClientMap) Delete(userID uint) {
	shard := m.getShard(userID)
	shard.lock.Lock()
	defer shard.lock.Unlock()
	delete(shard.clients, userID)
}

// Range iterates over all clients (requires locking all shards)
// This is expensive and should be used sparingly
func (m *ShardedClientMap) Range(fn func(userID uint, client *VPNClient) bool) {
	// Lock all shards in order to avoid deadlocks
	for _, shard := range m.shards {
		shard.lock.RLock()
	}
	
	// Unlock all shards when done
	defer func() {
		for _, shard := range m.shards {
			shard.lock.RUnlock()
		}
	}()
	
	// Iterate over all shards
	for _, shard := range m.shards {
		for userID, client := range shard.clients {
			if !fn(userID, client) {
				return
			}
		}
	}
}

// Len returns the total number of clients (requires locking all shards)
func (m *ShardedClientMap) Len() int {
	count := 0
	for _, shard := range m.shards {
		shard.lock.RLock()
		count += len(shard.clients)
		shard.lock.RUnlock()
	}
	return count
}

// ShardedVPNIPMap provides a sharded map for VPN IP to User ID mapping
type ShardedVPNIPMap struct {
	shards     []*VPNIPShard
	shardCount int
}

// VPNIPShard represents a single shard for VPN IP mapping
type VPNIPShard struct {
	ipToUser map[string]uint
	lock     sync.RWMutex
}

// NewShardedVPNIPMap creates a new sharded VPN IP map
func NewShardedVPNIPMap(shardCount int) *ShardedVPNIPMap {
	if shardCount <= 0 {
		shardCount = 16 // Default to 16 shards
	}
	
	shards := make([]*VPNIPShard, shardCount)
	for i := range shards {
		shards[i] = &VPNIPShard{
			ipToUser: make(map[string]uint),
		}
	}
	
	return &ShardedVPNIPMap{
		shards:     shards,
		shardCount: shardCount,
	}
}

// getShard returns the shard for a given IP string
func (m *ShardedVPNIPMap) getShard(ip string) *VPNIPShard {
	// Simple hash function to distribute IPs across shards
	hash := 0
	for _, c := range ip {
		hash = hash*31 + int(c)
	}
	if hash < 0 {
		hash = -hash
	}
	return m.shards[hash%m.shardCount]
}

// Get retrieves a user ID by VPN IP
func (m *ShardedVPNIPMap) Get(ip string) (uint, bool) {
	shard := m.getShard(ip)
	shard.lock.RLock()
	defer shard.lock.RUnlock()
	userID, exists := shard.ipToUser[ip]
	return userID, exists
}

// Set stores a VPN IP to user ID mapping
func (m *ShardedVPNIPMap) Set(ip string, userID uint) {
	shard := m.getShard(ip)
	shard.lock.Lock()
	defer shard.lock.Unlock()
	shard.ipToUser[ip] = userID
}

// Delete removes a VPN IP mapping
func (m *ShardedVPNIPMap) Delete(ip string) {
	shard := m.getShard(ip)
	shard.lock.Lock()
	defer shard.lock.Unlock()
	delete(shard.ipToUser, ip)
}


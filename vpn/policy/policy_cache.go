package policy

import (
	"hash/fnv"
	"sync"
)

// PolicyCacheEntry represents a cached policy execution result
type PolicyCacheEntry struct {
	Action Action
	// Add timestamp for cache expiration if needed
}

// PolicyCache provides LRU-like caching for policy execution results
type PolicyCache struct {
	cache   sync.Map // map[uint64]*PolicyCacheEntry
	maxSize int
	hitCount int64
	missCount int64
}

// NewPolicyCache creates a new policy cache
func NewPolicyCache(maxSize int) *PolicyCache {
	if maxSize <= 0 {
		maxSize = 1000 // Default cache size
	}
	return &PolicyCache{
		maxSize: maxSize,
	}
}

// hashContext creates a hash of the context for cache key
func hashContext(ctx *Context) uint64 {
	h := fnv.New64a()
	h.Write([]byte(ctx.SrcIP))
	h.Write([]byte(ctx.DstIP))
	h.Write([]byte{byte(ctx.SrcPort >> 8), byte(ctx.SrcPort)})
	h.Write([]byte{byte(ctx.DstPort >> 8), byte(ctx.DstPort)})
	h.Write([]byte(ctx.Protocol))
	h.Write([]byte{byte(ctx.UserID >> 24), byte(ctx.UserID >> 16), byte(ctx.UserID >> 8), byte(ctx.UserID)})
	return h.Sum64()
}

// Get retrieves a cached result for the given context
func (pc *PolicyCache) Get(ctx *Context) (Action, bool) {
	key := hashContext(ctx)
	if entry, ok := pc.cache.Load(key); ok {
		pc.hitCount++
		return entry.(*PolicyCacheEntry).Action, true
	}
	pc.missCount++
	return ActionAllow, false
}

// Set stores a result in the cache
func (pc *PolicyCache) Set(ctx *Context, action Action) {
	// Simple size limit: if cache is too large, clear it
	// In production, use a proper LRU cache implementation
	if pc.Count() >= pc.maxSize {
		pc.Clear()
	}

	key := hashContext(ctx)
	pc.cache.Store(key, &PolicyCacheEntry{
		Action: action,
	})
}

// Clear removes all entries from the cache
func (pc *PolicyCache) Clear() {
	pc.cache.Range(func(key, value interface{}) bool {
		pc.cache.Delete(key)
		return true
	})
}

// Count returns the number of entries in the cache
func (pc *PolicyCache) Count() int {
	count := 0
	pc.cache.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// GetStats returns cache statistics
func (pc *PolicyCache) GetStats() (hitCount, missCount int64, hitRate float64) {
	total := pc.hitCount + pc.missCount
	if total == 0 {
		return pc.hitCount, pc.missCount, 0.0
	}
	return pc.hitCount, pc.missCount, float64(pc.hitCount) / float64(total)
}

// SetMaxSize sets the maximum cache size
func (pc *PolicyCache) SetMaxSize(maxSize int) {
	if maxSize <= 0 {
		maxSize = 1000 // Default cache size
	}
	pc.maxSize = maxSize
	// If current cache exceeds new max size, clear it
	if pc.Count() >= maxSize {
		pc.Clear()
	}
}

// GetMaxSize returns the maximum cache size
func (pc *PolicyCache) GetMaxSize() int {
	return pc.maxSize
}


package policy

import (
	"fmt"
	"sort"
	"sync"
)

// Registry manages policy hooks with optimizations
type Registry struct {
	hooks       map[HookPoint][]Hook
	indexes     map[HookPoint]*PolicyIndex // Indexed hooks for faster lookup
	caches      map[HookPoint]*PolicyCache // Caches for policy execution results
	lock        sync.RWMutex
	enableCache bool // Enable caching (default: true for high-traffic scenarios)
}

// NewRegistry creates a new policy registry
func NewRegistry() *Registry {
	return &Registry{
		hooks:       make(map[HookPoint][]Hook),
		indexes:     make(map[HookPoint]*PolicyIndex),
		caches:      make(map[HookPoint]*PolicyCache),
		enableCache: true, // Enable cache by default
	}
}

// SetCacheEnabled enables or disables policy caching
func (r *Registry) SetCacheEnabled(enabled bool) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.enableCache = enabled
	if !enabled {
		// Clear all caches
		for _, cache := range r.caches {
			cache.Clear()
		}
	}
}

// IsCacheEnabled returns whether caching is enabled
func (r *Registry) IsCacheEnabled() bool {
	r.lock.RLock()
	defer r.lock.RUnlock()
	return r.enableCache
}

// SetCacheSize sets the cache size for all hook points
func (r *Registry) SetCacheSize(maxSize int) {
	r.lock.Lock()
	defer r.lock.Unlock()
	for _, cache := range r.caches {
		if cache != nil {
			cache.SetMaxSize(maxSize)
		}
	}
	// Also set default size for future caches
	// This is stored in the registry, but we'll use the cache's default
}

// GetCacheSize returns the cache size (from first cache found, or default)
func (r *Registry) GetCacheSize() int {
	r.lock.RLock()
	defer r.lock.RUnlock()
	for _, cache := range r.caches {
		if cache != nil {
			return cache.GetMaxSize()
		}
	}
	return 1000 // Default cache size
}

// Register registers a policy hook
func (r *Registry) Register(hook Hook) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	hookPoint := hook.HookPoint()

	// Enforce per-hook-point chain length (align with eBPF XDP 0..63 traversal)
	if len(r.hooks[hookPoint]) >= MaxHookChainEntries {
		return fmt.Errorf("hook point %s reached max entries (%d)", hookPoint.String(), MaxHookChainEntries)
	}

	// Check if hook with same name already exists
	for _, h := range r.hooks[hookPoint] {
		if h.Name() == hook.Name() {
			return fmt.Errorf("hook %s already registered at %s", hook.Name(), hookPoint.String())
		}
	}

	// Add hook and sort by priority
	r.hooks[hookPoint] = append(r.hooks[hookPoint], hook)
	sort.Slice(r.hooks[hookPoint], func(i, j int) bool {
		return r.hooks[hookPoint][i].Priority() < r.hooks[hookPoint][j].Priority()
	})

	// Update index
	if r.indexes[hookPoint] == nil {
		r.indexes[hookPoint] = NewPolicyIndex()
	}
	r.indexes[hookPoint].AddHook(hook)

	// Clear cache for this hook point (invalidate cache when hooks change)
	if cache := r.caches[hookPoint]; cache != nil {
		cache.Clear()
	}

	return nil
}

// HookCount returns number of hooks for a hook point.
func (r *Registry) HookCount(hookPoint HookPoint) int {
	r.lock.RLock()
	defer r.lock.RUnlock()
	return len(r.hooks[hookPoint])
}

// Unregister unregisters a policy hook
func (r *Registry) Unregister(name string, hookPoint HookPoint) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	hooks := r.hooks[hookPoint]
	for i, h := range hooks {
		if h.Name() == name {
			r.hooks[hookPoint] = append(hooks[:i], hooks[i+1:]...)

			// Rebuild index
			if r.indexes[hookPoint] != nil {
				r.indexes[hookPoint].Clear()
				for _, hook := range r.hooks[hookPoint] {
					r.indexes[hookPoint].AddHook(hook)
				}
			}

			// Clear cache
			if cache := r.caches[hookPoint]; cache != nil {
				cache.Clear()
			}

			return nil
		}
	}

	return fmt.Errorf("hook %s not found at %s", name, hookPoint.String())
}

// Execute executes all hooks for a given hook point
// Returns the first non-ALLOW action, or ALLOW if all hooks allow
func (r *Registry) Execute(hookPoint HookPoint, ctx *Context) Action {
	return r.ExecuteWithStats(hookPoint, ctx, nil)
}

// ExecuteWithStats executes all hooks for a given hook point with statistics collection
// Returns the first non-ALLOW action, or ALLOW if all hooks allow
func (r *Registry) ExecuteWithStats(hookPoint HookPoint, ctx *Context, statsCollector *StatsCollector) Action {
	// Check cache first (if enabled)
	if r.enableCache {
		r.lock.RLock()
		cache := r.caches[hookPoint]
		r.lock.RUnlock()

		if cache != nil {
			if cachedAction, ok := cache.Get(ctx); ok {
				// Cache hit - return cached result
				return cachedAction
			}
		}
	}

	// Get hooks list with minimal lock time
	r.lock.RLock()
	hooks := r.hooks[hookPoint]
	// Make a copy to release lock early
	hooksCopy := make([]Hook, len(hooks))
	copy(hooksCopy, hooks)
	r.lock.RUnlock()

	// Early return if no hooks
	if len(hooksCopy) == 0 {
		auditLogger := GetAuditLogger()
		if auditLogger.IsEnabled() {
			auditLogger.LogAccess(ctx, nil, ActionAllow, "allowed", "No policy matched, default allow")
		}
		return ActionAllow
	}

	auditLogger := GetAuditLogger()
	auditLogs := make([]func(), 0, len(hooksCopy)) // Batch audit logs

	// Execute hooks in priority order
	for _, hook := range hooksCopy {
		action := hook.Execute(ctx)
		matched := action != ActionAllow

		// Record statistics if collector is provided
		if statsCollector != nil && action != ActionAllow {
			statsCollector.RecordMatch(hook.Name(), action)
		}

		// Batch audit logging (defer execution to reduce overhead)
		if auditLogger.IsEnabled() {
			hookName := hook.Name()
			hookAction := action
			hookMatched := matched
			hookCtx := ctx // Context is read-only, safe to capture

			// Log ActionLog events immediately
			if action == ActionLog {
				logger := GetHookLogger()
				logger.LogPacket(hookName, hookCtx, hookAction)
				auditLogs = append(auditLogs, func() {
					auditLogger.LogHookExecution(hookCtx, hook, hookAction, true)
				})
				// ActionLog allows the packet to continue
				continue
			}

			// Batch other audit logs
			result := "allowed"
			reason := "Policy allowed"
			if action == ActionDeny {
				result = "blocked"
				reason = "Access denied by policy"
			} else if action == ActionRedirect {
				result = "redirected"
				reason = "Traffic redirected"
			} else if action == ActionAllow {
				result = "allowed"
				reason = "Access allowed by policy"
			}

			finalResult := result
			finalReason := reason
			auditLogs = append(auditLogs, func() {
				auditLogger.LogAccess(hookCtx, hook, hookAction, finalResult, finalReason)
				auditLogger.LogHookExecution(hookCtx, hook, hookAction, hookMatched)
			})
		}

		// Early termination: if action is not ALLOW, return immediately
		if action != ActionAllow {
			// Execute batched audit logs before returning
			for _, logFn := range auditLogs {
				logFn()
			}

			// Cache the result (if enabled)
			if r.enableCache {
				r.lock.RLock()
				cache := r.caches[hookPoint]
				if cache == nil {
					cache = NewPolicyCache(1000) // Default cache size
					r.caches[hookPoint] = cache
				}
				r.lock.RUnlock()
				cache.Set(ctx, action)
			}

			return action
		}
	}

	// Execute remaining audit logs
	for _, logFn := range auditLogs {
		logFn()
	}

	// If all hooks allowed, log successful access
	if auditLogger.IsEnabled() {
		auditLogger.LogAccess(ctx, nil, ActionAllow, "allowed", "No policy matched, default allow")
	}

	// Cache the result (if enabled)
	if r.enableCache {
		r.lock.RLock()
		cache := r.caches[hookPoint]
		if cache == nil {
			cache = NewPolicyCache(1000) // Default cache size
			r.caches[hookPoint] = cache
		}
		r.lock.RUnlock()
		cache.Set(ctx, ActionAllow)
	}

	return ActionAllow
}

// BatchExecute executes policies for multiple contexts in batch
// This is more efficient when processing multiple packets/requests
// Returns a slice of actions corresponding to each context
func (r *Registry) BatchExecute(hookPoint HookPoint, contexts []*Context, statsCollector *StatsCollector) []Action {
	// Get hooks list with minimal lock time
	r.lock.RLock()
	hooks := r.hooks[hookPoint]
	hooksCopy := make([]Hook, len(hooks))
	copy(hooksCopy, hooks)
	r.lock.RUnlock()

	// Early return if no hooks or no contexts
	if len(hooksCopy) == 0 || len(contexts) == 0 {
		actions := make([]Action, len(contexts))
		for i := range actions {
			actions[i] = ActionAllow
		}
		return actions
	}

	// Initialize results
	actions := make([]Action, len(contexts))
	for i := range actions {
		actions[i] = ActionAllow // Default to allow
	}

	auditLogger := GetAuditLogger()
	auditLogs := make([]func(), 0, len(hooksCopy)*len(contexts))

	// Execute hooks for each context
	// Optimize: process contexts in batch to improve cache locality
	for _, hook := range hooksCopy {
		// Process all contexts with this hook before moving to next hook
		// This improves cache locality and reduces function call overhead
		for i, ctx := range contexts {
			// Skip if already denied (early termination optimization)
			if actions[i] != ActionAllow {
				continue
			}

			action := hook.Execute(ctx)
			matched := action != ActionAllow

			// Record statistics
			if statsCollector != nil && action != ActionAllow {
				statsCollector.RecordMatch(hook.Name(), action)
			}

			// Batch audit logging
			if auditLogger.IsEnabled() {
				hookName := hook.Name()
				hookAction := action
				hookMatched := matched
				hookCtx := ctx

				if action == ActionLog {
					logger := GetHookLogger()
					logger.LogPacket(hookName, hookCtx, hookAction)
					auditLogs = append(auditLogs, func() {
						auditLogger.LogHookExecution(hookCtx, hook, hookAction, true)
					})
					continue
				}

				result := "allowed"
				reason := "Policy allowed"
				if action == ActionDeny {
					result = "blocked"
					reason = "Access denied by policy"
				} else if action == ActionRedirect {
					result = "redirected"
					reason = "Traffic redirected"
				}

				finalResult := result
				finalReason := reason
				auditLogs = append(auditLogs, func() {
					auditLogger.LogAccess(hookCtx, hook, hookAction, finalResult, finalReason)
					auditLogger.LogHookExecution(hookCtx, hook, hookAction, hookMatched)
				})
			}

			// Update action (only if not already set to non-ALLOW)
			if action != ActionAllow {
				actions[i] = action
			}
		}
	}

	// Execute batched audit logs
	for _, logFn := range auditLogs {
		logFn()
	}

	// Log default allow for contexts that passed all hooks
	if auditLogger.IsEnabled() {
		for i, ctx := range contexts {
			if actions[i] == ActionAllow {
				auditLogger.LogAccess(ctx, nil, ActionAllow, "allowed", "No policy matched, default allow")
			}
		}
	}

	return actions
}

// GetHooks returns all hooks for a given hook point
func (r *Registry) GetHooks(hookPoint HookPoint) []Hook {
	r.lock.RLock()
	defer r.lock.RUnlock()

	hooks := make([]Hook, len(r.hooks[hookPoint]))
	copy(hooks, r.hooks[hookPoint])
	return hooks
}

// GetAllHooks returns all registered hooks
func (r *Registry) GetAllHooks() map[HookPoint][]Hook {
	r.lock.RLock()
	defer r.lock.RUnlock()

	result := make(map[HookPoint][]Hook)
	for hookPoint, hooks := range r.hooks {
		result[hookPoint] = make([]Hook, len(hooks))
		copy(result[hookPoint], hooks)
	}
	return result
}

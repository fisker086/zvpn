package policy

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/fisker/zvpn/models"
)

// SyncManager interface for different sync implementations
type SyncManager interface {
	Start()
	Stop()
	ForceSync()
	GetLastSyncTime() time.Time
}

// Manager manages policy execution and eBPF integration
type Manager struct {
	registry      *Registry
	ebpfLoader    *EBPFLoader
	syncManager   SyncManager // Can be HookSyncManager or DistributedSyncManager
	statsCollector *StatsCollector
	lock          sync.RWMutex
}

// NewManager creates a new policy manager
func NewManager() *Manager {
	return &Manager{
		registry:       NewRegistry(),
		statsCollector: NewStatsCollector(),
	}
}

// SetEBPFLoader sets the eBPF loader for policy management
func (m *Manager) SetEBPFLoader(loader *EBPFLoader) {
	m.ebpfLoader = loader
}

// RegisterHook registers a policy hook
func (m *Manager) RegisterHook(hook Hook) error {
	if err := m.registry.Register(hook); err != nil {
		return err
	}

	// If eBPF is enabled, sync to eBPF
	if m.ebpfLoader != nil {
		if err := m.syncHookToEBPF(hook); err != nil {
			log.Printf("Warning: Failed to sync hook to eBPF: %v", err)
		}
	}

	return nil
}

// UnregisterHook unregisters a policy hook
func (m *Manager) UnregisterHook(name string, hookPoint HookPoint) error {
	return m.registry.Unregister(name, hookPoint)
}

// ExecutePolicies executes policies for a hook point
func (m *Manager) ExecutePolicies(hookPoint HookPoint, ctx *Context) Action {
	return m.registry.ExecuteWithStats(hookPoint, ctx, m.statsCollector)
}

// BatchExecutePolicies executes policies for multiple contexts in batch
// This is more efficient when processing multiple packets/requests
// Returns a slice of actions corresponding to each context
func (m *Manager) BatchExecutePolicies(hookPoint HookPoint, contexts []*Context) []Action {
	return m.registry.BatchExecute(hookPoint, contexts, m.statsCollector)
}

// GetHookStats returns statistics for a hook
func (m *Manager) GetHookStats(hookName string) *models.HookStats {
	return m.statsCollector.GetStats(hookName)
}

// GetAllHookStats returns statistics for all hooks
func (m *Manager) GetAllHookStats() map[string]*models.HookStats {
	return m.statsCollector.GetAllStats()
}

// LoadPolicyFromDB loads a policy from database and creates hooks
func (m *Manager) LoadPolicyFromDB(policy *models.Policy) error {
	// Create ACL hooks based on policy
	// This is a simplified example - you can extend this

	// Example: Create hooks for each allowed network
	for _, allowedNet := range policy.AllowedNetworks {
		_, ipNet, err := net.ParseCIDR(allowedNet.Network)
		if err != nil {
			continue
		}

		hook := NewACLHook(
			fmt.Sprintf("policy_%d_network_%s", policy.ID, allowedNet.Network),
			HookPreRouting,
			int(policy.ID)*100, // Priority based on policy ID
			ActionAllow,
		)
		hook.AddDestinationNetwork(ipNet)

		if err := m.RegisterHook(hook); err != nil {
			log.Printf("Failed to register hook for policy %d: %v", policy.ID, err)
		}
	}

	return nil
}

// syncHookToEBPF syncs a hook to eBPF maps
func (m *Manager) syncHookToEBPF(hook Hook) error {
	if m.ebpfLoader == nil {
		return fmt.Errorf("eBPF loader not set")
	}

	// Get or allocate policy ID for this hook
	policyID := m.ebpfLoader.GetOrAllocatePolicyID(hook.Name())

	// Determine action based on hook type
	// For now, execute hook with a test context to determine default action
	testCtx := NewContext()
	action := hook.Execute(testCtx)

	// Add policy to eBPF
	if err := m.ebpfLoader.AddPolicy(uint(policyID), hook, action); err != nil {
		return fmt.Errorf("failed to sync hook %s to eBPF: %w", hook.Name(), err)
	}

	log.Printf("eBPF: Synced hook %s to eBPF with policy ID %d (hook point: %s, action: %s, priority: %d)",
		hook.Name(), policyID, hook.HookPoint().String(), action.String(), hook.Priority())
	return nil
}

// GetRegistry returns the policy registry
func (m *Manager) GetRegistry() *Registry {
	return m.registry
}

// GetEBPFLoader returns the eBPF loader
func (m *Manager) GetEBPFLoader() *EBPFLoader {
	return m.ebpfLoader
}

// GetDistributedSyncManager returns the distributed sync manager
func (m *Manager) GetDistributedSyncManager() *DistributedSyncManager {
	if dsm, ok := m.syncManager.(*DistributedSyncManager); ok {
		return dsm
	}
	return nil
}

// StartDistributedSync starts the distributed synchronization manager
func (m *Manager) StartDistributedSync(nodeID string, syncInterval, changeInterval time.Duration) {
	if m.syncManager != nil {
		return // Already started
	}
	m.syncManager = NewDistributedSyncManager(m, nodeID, syncInterval, changeInterval)
	m.syncManager.Start()
}

// StopHookSync stops the hook synchronization manager
func (m *Manager) StopHookSync() {
	if m.syncManager != nil {
		m.syncManager.Stop()
		m.syncManager = nil
	}
}

// ForceSyncHooks forces an immediate hook synchronization
func (m *Manager) ForceSyncHooks() {
	if m.syncManager != nil {
		m.syncManager.ForceSync()
	}
}

// SetCacheEnabled enables or disables policy caching
func (m *Manager) SetCacheEnabled(enabled bool) {
	m.registry.SetCacheEnabled(enabled)
}

// IsCacheEnabled returns whether caching is enabled
func (m *Manager) IsCacheEnabled() bool {
	return m.registry.IsCacheEnabled()
}

// SetCacheSize sets the cache size for all hook points
func (m *Manager) SetCacheSize(maxSize int) {
	m.registry.SetCacheSize(maxSize)
}

// GetCacheSize returns the cache size
func (m *Manager) GetCacheSize() int {
	return m.registry.GetCacheSize()
}

package policy

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
)

// DistributedSyncManager manages distributed synchronization of hooks across multiple nodes
type DistributedSyncManager struct {
	manager        *Manager
	nodeID         string // Unique node identifier
	lastSyncTime   time.Time
	syncInterval   time.Duration
	changeInterval time.Duration // Interval to check for changes
	stopChan       chan struct{}
	running        bool
	lock           sync.RWMutex
	
	// Change detection
	lastHookVersion map[string]int64 // Hook ID -> version (UpdatedAt timestamp)
}

// NewDistributedSyncManager creates a new distributed sync manager
func NewDistributedSyncManager(manager *Manager, nodeID string, syncInterval, changeInterval time.Duration) *DistributedSyncManager {
	if nodeID == "" {
		nodeID = fmt.Sprintf("node-%d", time.Now().UnixNano())
	}
	
	return &DistributedSyncManager{
		manager:        manager,
		nodeID:         nodeID,
		syncInterval:   syncInterval,
		changeInterval: changeInterval,
		stopChan:       make(chan struct{}),
		lastHookVersion: make(map[string]int64),
	}
}

// Start starts the distributed sync manager
func (d *DistributedSyncManager) Start() {
	d.lock.Lock()
	if d.running {
		d.lock.Unlock()
		return
	}
	d.running = true
	d.lock.Unlock()

	log.Printf("Distributed sync manager started (node: %s, sync interval: %v, change check: %v)", 
		d.nodeID, d.syncInterval, d.changeInterval)

	go d.syncLoop()
}

// Stop stops the distributed sync manager
func (d *DistributedSyncManager) Stop() {
	d.lock.Lock()
	defer d.lock.Unlock()

	if !d.running {
		return
	}

	d.running = false
	close(d.stopChan)
	log.Println("Distributed sync manager stopped")
}

// syncLoop runs the sync loop with change detection
func (d *DistributedSyncManager) syncLoop() {
	changeTicker := time.NewTicker(d.changeInterval)
	fullSyncTicker := time.NewTicker(d.syncInterval)
	defer changeTicker.Stop()
	defer fullSyncTicker.Stop()

	// Initial full sync
	d.fullSync()

	for {
		select {
		case <-changeTicker.C:
			// Check for changes and sync only changed hooks
			d.incrementalSync()
		case <-fullSyncTicker.C:
			// Full sync to ensure consistency
			d.fullSync()
		case <-d.stopChan:
			return
		}
	}
}

// fullSync performs a full synchronization of all hooks
func (d *DistributedSyncManager) fullSync() {
	log.Printf("Distributed sync: Starting full sync (node: %s)", d.nodeID)
	
	var hooks []models.Hook
	if err := database.DB.Order("updated_at DESC").Find(&hooks).Error; err != nil {
		log.Printf("Distributed sync: Failed to load hooks: %v", err)
		return
	}

	// Get currently registered hooks
	registeredHooks := make(map[string]bool)
	allHooks := d.manager.GetRegistry().GetAllHooks()
	for _, hookList := range allHooks {
		for _, hook := range hookList {
			registeredHooks[hook.Name()] = true
		}
	}

	// Track hooks that should exist
	shouldExist := make(map[string]bool)
	syncedCount := 0
	updatedCount := 0

	// Register or update hooks
	for _, hookModel := range hooks {
		hookID := hookModel.ID
		shouldExist[hookID] = true

		hookPoint := HookPoint(hookModel.HookPoint)
		isRegistered := registeredHooks[hookID]
		
		// Get version (UpdatedAt timestamp)
		version := hookModel.UpdatedAt.UnixNano()
		lastVersion, exists := d.lastHookVersion[hookID]
		
		// Check if hook needs update
		needsUpdate := !exists || version > lastVersion

		if hookModel.Enabled {
			if !isRegistered || needsUpdate {
				// Unregister old hook if exists
				if isRegistered {
					d.manager.UnregisterHook(hookID, hookPoint)
				}

				// Register or re-register hook
				hook := convertModelHookToPolicyHook(&hookModel)
				if hook != nil {
					if err := d.manager.RegisterHook(hook); err != nil {
						log.Printf("Distributed sync: Failed to register hook %s: %v", hookID, err)
					} else {
						d.lastHookVersion[hookID] = version
						if !isRegistered {
							syncedCount++
							log.Printf("Distributed sync: Registered hook %s (node: %s)", hookModel.Name, d.nodeID)
						} else {
							updatedCount++
							log.Printf("Distributed sync: Updated hook %s (node: %s)", hookModel.Name, d.nodeID)
						}
					}
				}
			}
		} else {
			// Hook should not be registered (disabled)
			if isRegistered {
				if err := d.manager.UnregisterHook(hookID, hookPoint); err != nil {
					log.Printf("Distributed sync: Failed to unregister disabled hook %s: %v", hookID, err)
				} else {
					delete(d.lastHookVersion, hookID)
					log.Printf("Distributed sync: Unregistered disabled hook %s (node: %s)", hookModel.Name, d.nodeID)
				}
			}
		}
	}

	// Remove hooks that no longer exist in database
	for hookID := range registeredHooks {
		if !shouldExist[hookID] {
			// Find the hook point for this hook
			for hookPoint, hookList := range allHooks {
				for _, hook := range hookList {
					if hook.Name() == hookID {
						if err := d.manager.UnregisterHook(hookID, hookPoint); err != nil {
							log.Printf("Distributed sync: Failed to unregister deleted hook %s: %v", hookID, err)
						} else {
							delete(d.lastHookVersion, hookID)
							log.Printf("Distributed sync: Unregistered deleted hook %s (node: %s)", hookID, d.nodeID)
						}
						break
					}
				}
			}
		}
	}

	d.lastSyncTime = time.Now()
	
	if syncedCount > 0 || updatedCount > 0 {
		log.Printf("Distributed sync: Full sync completed (node: %s, synced: %d, updated: %d)", 
			d.nodeID, syncedCount, updatedCount)
	}
}

// incrementalSync performs incremental synchronization of changed hooks only
func (d *DistributedSyncManager) incrementalSync() {
	// Get hooks that have been updated since last sync
	var hooks []models.Hook
	cutoffTime := d.lastSyncTime.Add(-time.Second) // Small buffer to avoid missing updates
	
	if err := database.DB.Where("updated_at > ?", cutoffTime).
		Order("updated_at DESC").Find(&hooks).Error; err != nil {
		log.Printf("Distributed sync: Failed to load changed hooks: %v", err)
		return
	}

	if len(hooks) == 0 {
		return // No changes
	}

	log.Printf("Distributed sync: Detected %d changed hooks (node: %s)", len(hooks), d.nodeID)

	// Get currently registered hooks
	registeredHooks := make(map[string]bool)
	allHooks := d.manager.GetRegistry().GetAllHooks()
	for _, hookList := range allHooks {
		for _, hook := range hookList {
			registeredHooks[hook.Name()] = true
		}
	}

	updatedCount := 0

	// Update changed hooks
	for _, hookModel := range hooks {
		hookID := hookModel.ID
		hookPoint := HookPoint(hookModel.HookPoint)
		isRegistered := registeredHooks[hookID]
		version := hookModel.UpdatedAt.UnixNano()

		if hookModel.Enabled {
			// Unregister old hook if exists
			if isRegistered {
				d.manager.UnregisterHook(hookID, hookPoint)
			}

			// Register or re-register hook
			hook := convertModelHookToPolicyHook(&hookModel)
			if hook != nil {
				if err := d.manager.RegisterHook(hook); err != nil {
					log.Printf("Distributed sync: Failed to update hook %s: %v", hookID, err)
				} else {
					d.lastHookVersion[hookID] = version
					updatedCount++
					log.Printf("Distributed sync: Incrementally updated hook %s (node: %s)", hookModel.Name, d.nodeID)
				}
			}
		} else {
			// Hook disabled
			if isRegistered {
				if err := d.manager.UnregisterHook(hookID, hookPoint); err != nil {
					log.Printf("Distributed sync: Failed to unregister disabled hook %s: %v", hookID, err)
				} else {
					delete(d.lastHookVersion, hookID)
					log.Printf("Distributed sync: Unregistered disabled hook %s (node: %s)", hookModel.Name, d.nodeID)
				}
			}
		}
	}

	if updatedCount > 0 {
		d.lastSyncTime = time.Now()
		log.Printf("Distributed sync: Incremental sync completed (node: %s, updated: %d)", d.nodeID, updatedCount)
	}
}

// ForceSync forces an immediate full sync
func (d *DistributedSyncManager) ForceSync() {
	log.Printf("Distributed sync: Force sync requested (node: %s)", d.nodeID)
	d.fullSync()
}

// GetLastSyncTime returns the last sync time
func (d *DistributedSyncManager) GetLastSyncTime() time.Time {
	d.lock.RLock()
	defer d.lock.RUnlock()
	return d.lastSyncTime
}

// GetNodeID returns the node ID
func (d *DistributedSyncManager) GetNodeID() string {
	return d.nodeID
}

// SyncHook syncs a specific hook immediately (called from API handlers)
func (d *DistributedSyncManager) SyncHook(hookID string) error {
	var hookModel models.Hook
	if err := database.DB.First(&hookModel, "id = ?", hookID).Error; err != nil {
		return fmt.Errorf("hook not found: %w", err)
	}

	hookPoint := HookPoint(hookModel.HookPoint)
	version := hookModel.UpdatedAt.UnixNano()

	// Unregister old hook if exists
	d.manager.UnregisterHook(hookID, hookPoint)

	if hookModel.Enabled {
		// Register hook
		hook := convertModelHookToPolicyHook(&hookModel)
		if hook != nil {
			if err := d.manager.RegisterHook(hook); err != nil {
				return fmt.Errorf("failed to register hook: %w", err)
			}
			d.lastHookVersion[hookID] = version
			log.Printf("Distributed sync: Manually synced hook %s (node: %s)", hookModel.Name, d.nodeID)
		}
	} else {
		delete(d.lastHookVersion, hookID)
		log.Printf("Distributed sync: Manually unregistered disabled hook %s (node: %s)", hookModel.Name, d.nodeID)
	}

	return nil
}

// GetSyncStatus returns the current sync status
func (d *DistributedSyncManager) GetSyncStatus() map[string]interface{} {
	d.lock.RLock()
	defer d.lock.RUnlock()

	return map[string]interface{}{
		"node_id":       d.nodeID,
		"running":       d.running,
		"last_sync":     d.lastSyncTime,
		"sync_interval": d.syncInterval.String(),
		"hook_count":    len(d.lastHookVersion),
	}
}



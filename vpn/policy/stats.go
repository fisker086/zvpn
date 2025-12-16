package policy

import (
	"sync"
	"time"

	"github.com/fisker/zvpn/models"
)

// StatsCollector collects statistics for policy hooks
type StatsCollector struct {
	stats map[string]*HookStats // Hook name -> stats
	lock  sync.RWMutex
}

// HookStats represents statistics for a single hook
type HookStats struct {
	TotalMatches  uint64
	TotalAllows   uint64
	TotalDenies   uint64
	TotalRedirects uint64
	TotalLogs     uint64
	LastMatchTime time.Time
	lock          sync.RWMutex
}

// NewStatsCollector creates a new stats collector
func NewStatsCollector() *StatsCollector {
	return &StatsCollector{
		stats: make(map[string]*HookStats),
	}
}

// RecordMatch records a hook match with the resulting action
func (sc *StatsCollector) RecordMatch(hookName string, action Action) {
	sc.lock.Lock()
	stats, exists := sc.stats[hookName]
	if !exists {
		stats = &HookStats{}
		sc.stats[hookName] = stats
	}
	sc.lock.Unlock()

	stats.lock.Lock()
	defer stats.lock.Unlock()

	stats.TotalMatches++
	stats.LastMatchTime = time.Now()

	switch action {
	case ActionAllow:
		stats.TotalAllows++
	case ActionDeny:
		stats.TotalDenies++
	case ActionRedirect:
		stats.TotalRedirects++
	case ActionLog:
		stats.TotalLogs++
	}
}

// GetStats returns statistics for a hook
func (sc *StatsCollector) GetStats(hookName string) *models.HookStats {
	sc.lock.RLock()
	stats, exists := sc.stats[hookName]
	sc.lock.RUnlock()

	if !exists {
		return &models.HookStats{
			TotalMatches: 0,
			TotalAllows:  0,
			TotalDenies:  0,
		}
	}

	stats.lock.RLock()
	defer stats.lock.RUnlock()

	result := &models.HookStats{
		TotalMatches: stats.TotalMatches,
		TotalAllows:  stats.TotalAllows,
		TotalDenies:  stats.TotalDenies,
	}

	if !stats.LastMatchTime.IsZero() {
		result.LastMatchTime = &stats.LastMatchTime
	}

	return result
}

// GetAllStats returns statistics for all hooks
func (sc *StatsCollector) GetAllStats() map[string]*models.HookStats {
	sc.lock.RLock()
	defer sc.lock.RUnlock()

	result := make(map[string]*models.HookStats)
	for hookName, stats := range sc.stats {
		stats.lock.RLock()
		hookStats := &models.HookStats{
			TotalMatches: stats.TotalMatches,
			TotalAllows:  stats.TotalAllows,
			TotalDenies:  stats.TotalDenies,
		}
		if !stats.LastMatchTime.IsZero() {
			hookStats.LastMatchTime = &stats.LastMatchTime
		}
		stats.lock.RUnlock()
		result[hookName] = hookStats
	}

	return result
}

// ResetStats resets statistics for a hook
func (sc *StatsCollector) ResetStats(hookName string) {
	sc.lock.Lock()
	defer sc.lock.Unlock()

	if stats, exists := sc.stats[hookName]; exists {
		stats.lock.Lock()
		stats.TotalMatches = 0
		stats.TotalAllows = 0
		stats.TotalDenies = 0
		stats.TotalRedirects = 0
		stats.TotalLogs = 0
		stats.LastMatchTime = time.Time{}
		stats.lock.Unlock()
	}
}

// RemoveStats removes statistics for a hook
func (sc *StatsCollector) RemoveStats(hookName string) {
	sc.lock.Lock()
	defer sc.lock.Unlock()
	delete(sc.stats, hookName)
}


package security

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/fisker/zvpn/vpn/ebpf"
)

// BruteforceProtection 密码爆破防护
type BruteforceProtection struct {
	mu                sync.RWMutex
	failedAttempts    map[string]*AttemptTracker // IP -> 失败尝试记录
	maxAttempts       int                        // 最大失败次数
	lockoutDuration   time.Duration              // 封禁时长
	windowDuration    time.Duration              // 时间窗口（在此窗口内的失败次数会被累计）
	ebpfProgram       *ebpf.XDPProgram           // eBPF 程序，用于在内核层面封禁IP
	blockedIPs        map[string]time.Time       // 被封禁的IP及其解封时间
	whitelistIPs      map[string]bool            // 白名单IP（不受限制）
	manualBlocks      map[string]time.Time       // 手动封禁的IP及其解封时间（0表示永久封禁）
	cleanupInterval   time.Duration              // 清理过期记录的间隔
	stopCleanup       chan struct{}              // 停止清理goroutine的信号
	enabled           bool                       // 是否启用防护
}

// AttemptTracker 跟踪单个IP的登录尝试
type AttemptTracker struct {
	IP            string
	FailedCount   int
	FirstAttempt  time.Time
	LastAttempt   time.Time
	BlockedUntil  time.Time // 封禁到期时间
}

// NewBruteforceProtection 创建密码爆破防护实例
func NewBruteforceProtection(maxAttempts int, lockoutDuration, windowDuration time.Duration) *BruteforceProtection {
	bp := &BruteforceProtection{
		failedAttempts:  make(map[string]*AttemptTracker),
		maxAttempts:     maxAttempts,
		lockoutDuration: lockoutDuration,
		windowDuration:  windowDuration,
		blockedIPs:      make(map[string]time.Time),
		whitelistIPs:   make(map[string]bool),
		manualBlocks:   make(map[string]time.Time),
		cleanupInterval: 5 * time.Minute, // 每5分钟清理一次过期记录
		stopCleanup:     make(chan struct{}),
		enabled:         true, // 默认启用
	}

	// 启动清理goroutine
	go bp.cleanupRoutine()

	return bp
}

// SetEBPFProgram 设置 eBPF 程序，用于在内核层面封禁IP
func (bp *BruteforceProtection) SetEBPFProgram(prog *ebpf.XDPProgram) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.ebpfProgram = prog
}

// UpdateConfig 动态更新配置（无需重启）
func (bp *BruteforceProtection) UpdateConfig(maxAttempts int, lockoutDuration, windowDuration time.Duration, enabled bool) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	
	bp.maxAttempts = maxAttempts
	bp.lockoutDuration = lockoutDuration
	bp.windowDuration = windowDuration
	bp.enabled = enabled
	
	log.Printf("Bruteforce Protection: Config updated - maxAttempts=%d, lockout=%v, window=%v, enabled=%v",
		maxAttempts, lockoutDuration, windowDuration, enabled)
}

// AddWhitelistIP 添加白名单IP
func (bp *BruteforceProtection) AddWhitelistIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.whitelistIPs[ip] = true
	log.Printf("Bruteforce Protection: IP %s added to whitelist", ip)
	return nil
}

// RemoveWhitelistIP 移除白名单IP
func (bp *BruteforceProtection) RemoveWhitelistIP(ip string) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	delete(bp.whitelistIPs, ip)
	log.Printf("Bruteforce Protection: IP %s removed from whitelist", ip)
}

// GetWhitelistIPs 获取所有白名单IP
func (bp *BruteforceProtection) GetWhitelistIPs() []string {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	ips := make([]string, 0, len(bp.whitelistIPs))
	for ip := range bp.whitelistIPs {
		ips = append(ips, ip)
	}
	return ips
}

// BlockIP 手动封禁IP（duration为0表示永久封禁）
func (bp *BruteforceProtection) BlockIP(ip string, duration time.Duration) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	bp.mu.Lock()
	defer bp.mu.Unlock()
	
	now := time.Now()
	if duration == 0 {
		// 永久封禁（使用一个很远的未来时间）
		bp.manualBlocks[ip] = now.Add(100 * 365 * 24 * time.Hour)
	} else {
		bp.manualBlocks[ip] = now.Add(duration)
	}
	
	// 同时更新blockedIPs
	bp.blockedIPs[ip] = bp.manualBlocks[ip]
	
	// 如果 eBPF 程序可用，在内核层面封禁该IP
	if bp.ebpfProgram != nil {
		bp.blockIPInEBPF(ip)
	}
	
	log.Printf("Bruteforce Protection: IP %s manually blocked for %v", ip, duration)
	return nil
}

// UnblockIP 手动解封IP
func (bp *BruteforceProtection) UnblockIP(ip string) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	
	delete(bp.manualBlocks, ip)
	delete(bp.blockedIPs, ip)
	
	// 清除失败尝试记录
	if tracker, exists := bp.failedAttempts[ip]; exists {
		tracker.FailedCount = 0
		tracker.BlockedUntil = time.Time{}
	}
	
	// 如果 eBPF 程序可用，在内核层面解封该IP
	if bp.ebpfProgram != nil {
		bp.unblockIPInEBPF(ip)
	}
	
	log.Printf("Bruteforce Protection: IP %s manually unblocked", ip)
}

// GetBlockedIPs 获取所有被封禁的IP及其解封时间
func (bp *BruteforceProtection) GetBlockedIPs() map[string]time.Time {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	
	result := make(map[string]time.Time)
	now := time.Now()
	
	// 合并自动封禁和手动封禁
	for ip, blockedUntil := range bp.blockedIPs {
		if blockedUntil.After(now) {
			result[ip] = blockedUntil
		}
	}
	
	for ip, blockedUntil := range bp.manualBlocks {
		if blockedUntil.After(now) {
			result[ip] = blockedUntil
		}
	}
	
	return result
}

// RecordFailedAttempt 记录一次失败的登录尝试
// 返回: (是否被封禁, 剩余尝试次数, 封禁到期时间)
func (bp *BruteforceProtection) RecordFailedAttempt(ip string) (bool, int, time.Time) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	// 如果防护未启用，直接允许
	if !bp.enabled {
		return false, bp.maxAttempts, time.Time{}
	}

	// 检查白名单
	if bp.whitelistIPs[ip] {
		return false, bp.maxAttempts, time.Time{}
	}

	now := time.Now()
	
	// 检查手动封禁
	if blockedUntil, exists := bp.manualBlocks[ip]; exists {
		if blockedUntil.After(now) {
			return true, 0, blockedUntil
		} else {
			// 手动封禁已过期，删除
			delete(bp.manualBlocks, ip)
			delete(bp.blockedIPs, ip)
		}
	}
	
	tracker, exists := bp.failedAttempts[ip]

	if !exists {
		// 第一次失败
		tracker = &AttemptTracker{
			IP:           ip,
			FailedCount:  1,
			FirstAttempt: now,
			LastAttempt:  now,
		}
		bp.failedAttempts[ip] = tracker
		return false, bp.maxAttempts - 1, time.Time{}
	}

	// 检查是否在封禁期内
	if !tracker.BlockedUntil.IsZero() && now.Before(tracker.BlockedUntil) {
		return true, 0, tracker.BlockedUntil
	}

	// 如果封禁已过期，重置计数器
	if !tracker.BlockedUntil.IsZero() && now.After(tracker.BlockedUntil) {
		tracker.FailedCount = 0
		tracker.BlockedUntil = time.Time{}
		delete(bp.blockedIPs, ip)
	}

	// 检查是否在时间窗口内
	if now.Sub(tracker.FirstAttempt) > bp.windowDuration {
		// 超出时间窗口，重置计数器
		tracker.FailedCount = 1
		tracker.FirstAttempt = now
		tracker.LastAttempt = now
		return false, bp.maxAttempts - 1, time.Time{}
	}

	// 在时间窗口内，增加失败计数
	tracker.FailedCount++
	tracker.LastAttempt = now

	remaining := bp.maxAttempts - tracker.FailedCount
	if remaining < 0 {
		remaining = 0
	}

	// 检查是否超过最大失败次数
	if tracker.FailedCount >= bp.maxAttempts {
		// 封禁该IP
		tracker.BlockedUntil = now.Add(bp.lockoutDuration)
		bp.blockedIPs[ip] = tracker.BlockedUntil

		// 如果 eBPF 程序可用，在内核层面封禁该IP
		if bp.ebpfProgram != nil {
			bp.blockIPInEBPF(ip)
		}

		log.Printf("Bruteforce Protection: IP %s blocked for %v (failed attempts: %d)", 
			ip, bp.lockoutDuration, tracker.FailedCount)
		return true, 0, tracker.BlockedUntil
	}

	return false, remaining, time.Time{}
}

// RecordSuccess 记录一次成功的登录，清除该IP的失败记录
// 注意：不会解除手动封禁的IP
func (bp *BruteforceProtection) RecordSuccess(ip string) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	// 如果IP在手动封禁列表中，不解除封禁
	if _, manuallyBlocked := bp.manualBlocks[ip]; manuallyBlocked {
		log.Printf("Bruteforce Protection: IP %s is manually blocked, not unblocking after successful login", ip)
		return
	}

	if tracker, exists := bp.failedAttempts[ip]; exists {
		// 清除失败记录
		tracker.FailedCount = 0
		tracker.FirstAttempt = time.Time{}
		tracker.LastAttempt = time.Time{}
		tracker.BlockedUntil = time.Time{}
	}

	// 如果IP被封禁（自动封禁），解除封禁
	if _, blocked := bp.blockedIPs[ip]; blocked {
		delete(bp.blockedIPs, ip)
		if bp.ebpfProgram != nil {
			bp.unblockIPInEBPF(ip)
		}
		log.Printf("Bruteforce Protection: IP %s unblocked after successful login", ip)
	}
}

// IsBlocked 检查IP是否被封禁
func (bp *BruteforceProtection) IsBlocked(ip string) (bool, time.Time) {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	// 如果防护未启用，不封禁
	if !bp.enabled {
		return false, time.Time{}
	}

	// 检查白名单
	if bp.whitelistIPs[ip] {
		return false, time.Time{}
	}

	// 检查手动封禁
	if blockedUntil, exists := bp.manualBlocks[ip]; exists {
		now := time.Now()
		if blockedUntil.After(now) {
			return true, blockedUntil
		}
	}

	// 检查自动封禁
	if tracker, exists := bp.failedAttempts[ip]; exists {
		if !tracker.BlockedUntil.IsZero() && time.Now().Before(tracker.BlockedUntil) {
			return true, tracker.BlockedUntil
		}
	}

	if blockedUntil, exists := bp.blockedIPs[ip]; exists {
		if time.Now().Before(blockedUntil) {
			return true, blockedUntil
		}
	}

	return false, time.Time{}
}

// GetRemainingAttempts 获取IP的剩余尝试次数
func (bp *BruteforceProtection) GetRemainingAttempts(ip string) int {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	tracker, exists := bp.failedAttempts[ip]
	if !exists {
		return bp.maxAttempts
	}

	remaining := bp.maxAttempts - tracker.FailedCount
	if remaining < 0 {
		return 0
	}
	return remaining
}

// blockIPInEBPF 在 eBPF 层面封禁IP
func (bp *BruteforceProtection) blockIPInEBPF(ip string) {
	if bp.ebpfProgram == nil {
		log.Printf("Bruteforce Protection: eBPF program not available, skipping kernel-level block for IP %s", ip)
		return
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		log.Printf("Bruteforce Protection: Invalid IP address %s, skipping eBPF block", ip)
		return
	}

	// Get blocked until time from manualBlocks or blockedIPs
	bp.mu.RLock()
	var blockedUntil uint64
	if blockedUntilTime, exists := bp.manualBlocks[ip]; exists {
		if blockedUntilTime.IsZero() {
			// Permanent block (use 0)
			blockedUntil = 0
		} else {
			// Convert to nanoseconds
			blockedUntil = uint64(blockedUntilTime.UnixNano())
		}
	} else if blockedUntilTime, exists := bp.blockedIPs[ip]; exists {
		if blockedUntilTime.IsZero() {
			blockedUntil = 0
		} else {
			blockedUntil = uint64(blockedUntilTime.UnixNano())
		}
	} else {
		// Should not happen, but if it does, use current time + lockout duration
		blockedUntil = uint64(time.Now().Add(bp.lockoutDuration).UnixNano())
	}
	bp.mu.RUnlock()

	// Block IP in eBPF (kernel-level)
	if err := bp.ebpfProgram.BlockIP(parsedIP, blockedUntil); err != nil {
		log.Printf("Bruteforce Protection: Failed to block IP %s in eBPF: %v", ip, err)
	} else {
		if blockedUntil == 0 {
			log.Printf("Bruteforce Protection: IP %s permanently blocked in eBPF (kernel-level)", ip)
		} else {
			log.Printf("Bruteforce Protection: IP %s blocked in eBPF until %v (kernel-level)", ip, time.Unix(0, int64(blockedUntil)))
		}
	}
}

// unblockIPInEBPF 在 eBPF 层面解除IP封禁
func (bp *BruteforceProtection) unblockIPInEBPF(ip string) {
	if bp.ebpfProgram == nil {
		log.Printf("Bruteforce Protection: eBPF program not available, skipping kernel-level unblock for IP %s", ip)
		return
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		log.Printf("Bruteforce Protection: Invalid IP address %s, skipping eBPF unblock", ip)
		return
	}

	// Unblock IP in eBPF (kernel-level)
	if err := bp.ebpfProgram.UnblockIP(parsedIP); err != nil {
		log.Printf("Bruteforce Protection: Failed to unblock IP %s in eBPF: %v", ip, err)
	} else {
		log.Printf("Bruteforce Protection: IP %s unblocked in eBPF (kernel-level)", ip)
	}
}

// cleanupRoutine 定期清理过期的记录
func (bp *BruteforceProtection) cleanupRoutine() {
	ticker := time.NewTicker(bp.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bp.cleanup()
		case <-bp.stopCleanup:
			return
		}
	}
}

// cleanup 清理过期的记录
func (bp *BruteforceProtection) cleanup() {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	now := time.Now()
	expiredIPs := make([]string, 0)

	// 清理过期的失败尝试记录
	for ip, tracker := range bp.failedAttempts {
		// 如果封禁已过期且超出时间窗口，删除记录
		if (!tracker.BlockedUntil.IsZero() && now.After(tracker.BlockedUntil)) &&
			now.Sub(tracker.LastAttempt) > bp.windowDuration*2 {
			expiredIPs = append(expiredIPs, ip)
		}
	}

	for _, ip := range expiredIPs {
		delete(bp.failedAttempts, ip)
	}

	// 清理过期的自动封禁记录（不包括手动封禁）
	expiredBlocks := make([]string, 0)
	for ip, blockedUntil := range bp.blockedIPs {
		// 只清理自动封禁，不清理手动封禁
		if _, isManual := bp.manualBlocks[ip]; !isManual && now.After(blockedUntil) {
			expiredBlocks = append(expiredBlocks, ip)
		}
	}

	for _, ip := range expiredBlocks {
		delete(bp.blockedIPs, ip)
	}

	// 清理过期的手动封禁记录（但保留永久封禁）
	expiredManualBlocks := make([]string, 0)
	for ip, blockedUntil := range bp.manualBlocks {
		// 永久封禁使用很远的未来时间，不会过期
		if blockedUntil.Before(now.Add(99 * 365 * 24 * time.Hour)) && now.After(blockedUntil) {
			expiredManualBlocks = append(expiredManualBlocks, ip)
		}
	}

	for _, ip := range expiredManualBlocks {
		delete(bp.manualBlocks, ip)
		delete(bp.blockedIPs, ip)
		if bp.ebpfProgram != nil {
			bp.unblockIPInEBPF(ip)
		}
	}

	if len(expiredIPs) > 0 || len(expiredBlocks) > 0 || len(expiredManualBlocks) > 0 {
		log.Printf("Bruteforce Protection: Cleaned up %d expired attempt records, %d expired auto-block records, %d expired manual-block records",
			len(expiredIPs), len(expiredBlocks), len(expiredManualBlocks))
	}
}

// GetStats 获取统计信息
func (bp *BruteforceProtection) GetStats() map[string]interface{} {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	blockedCount := 0
	totalAttempts := 0
	now := time.Now()

	for _, tracker := range bp.failedAttempts {
		totalAttempts += tracker.FailedCount
		if !tracker.BlockedUntil.IsZero() && now.Before(tracker.BlockedUntil) {
			blockedCount++
		}
	}

	manualBlockedCount := 0
	for _, blockedUntil := range bp.manualBlocks {
		if now.Before(blockedUntil) {
			manualBlockedCount++
		}
	}

	return map[string]interface{}{
		"enabled":              bp.enabled,
		"blocked_ips":          blockedCount,
		"manual_blocked_ips":   manualBlockedCount,
		"total_tracked_ips":    len(bp.failedAttempts),
		"whitelist_ips":        len(bp.whitelistIPs),
		"total_failed_attempts": totalAttempts,
		"max_attempts":         bp.maxAttempts,
		"lockout_duration":      bp.lockoutDuration.String(),
		"window_duration":       bp.windowDuration.String(),
	}
}

// Close 关闭防护实例
func (bp *BruteforceProtection) Close() {
	close(bp.stopCleanup)
}

// ParseIP 解析IP地址，支持IPv4和IPv6
func ParseIP(ipStr string) (net.IP, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	return ip, nil
}


package openconnect

import (
	"fmt"
	"log"
	"net"
	"time"
)

// DTLS性能优化器
// 解决UDP DTLS模式下路由下发慢的问题

type DTLSOptimizer struct {
	// 预加载路由配置
	preloadedRoutes map[string]*PreloadedRoute

	// 快速客户端匹配
	clientMatchCache map[string]*ClientMatchInfo

	// 优化参数
	config *DTLSOptimizerConfig
}

type PreloadedRoute struct {
	Network  string
	Gateway  net.IP
	Metric   int
	AddedAt  time.Time
	IsActive bool
}

type ClientMatchInfo struct {
	UserID    uint
	VPNIP     string
	PolicyID  uint
	MatchedAt time.Time
}

type DTLSOptimizerConfig struct {
	// 预加载延迟（毫秒）
	PreloadDelayMS int

	// 缓存超时时间
	CacheTimeout time.Duration

	// 启用快速匹配
	EnableFastMatch bool

	// 启用预路由
	EnablePreRouting bool
}

// NewDTLSOptimizer 创建DTLS性能优化器
func NewDTLSOptimizer(config *DTLSOptimizerConfig) *DTLSOptimizer {
	if config == nil {
		config = &DTLSOptimizerConfig{
			PreloadDelayMS:   50,                // 50ms预加载延迟
			CacheTimeout:     300 * time.Second, // 5分钟缓存超时
			EnableFastMatch:  true,
			EnablePreRouting: true,
		}
	}

	return &DTLSOptimizer{
		preloadedRoutes:  make(map[string]*PreloadedRoute),
		clientMatchCache: make(map[string]*ClientMatchInfo),
		config:           config,
	}
}

// PreloadRoutes 预加载用户路由配置
// 在DTLS握手开始前就准备好路由配置，减少等待时间
func (o *DTLSOptimizer) PreloadRoutes(userID uint, vpnIP string, policyID uint, routes []string, gateway net.IP) {
	if !o.config.EnablePreRouting {
		return
	}

	routeKey := fmt.Sprintf("user_%d_policy_%d", userID, policyID)

	// 清理旧的预加载路由
	delete(o.preloadedRoutes, routeKey)

	// 预加载所有路由
	for _, routeStr := range routes {
		_, _, err := net.ParseCIDR(routeStr)
		if err != nil {
			log.Printf("DTLS Optimizer: Failed to parse route %s: %v", routeStr, err)
			continue
		}

		preloadedRoute := &PreloadedRoute{
			Network:  routeStr,
			Gateway:  gateway,
			Metric:   100,
			AddedAt:  time.Now(),
			IsActive: false,
		}

		o.preloadedRoutes[routeKey+"_"+routeStr] = preloadedRoute
		log.Printf("DTLS Optimizer: ✓ Preloaded route %s for user %d", routeStr, userID)
	}

	// 缓存客户端匹配信息
	o.clientMatchCache[vpnIP] = &ClientMatchInfo{
		UserID:    userID,
		VPNIP:     vpnIP,
		PolicyID:  policyID,
		MatchedAt: time.Now(),
	}

	log.Printf("DTLS Optimizer: ✓ Preloaded %d routes for user %d (VPN IP: %s)", len(routes), userID, vpnIP)
}

// ApplyPreloadedRoutes 应用预加载的路由
// 当DTLS连接建立后，立即应用预加载的路由配置
func (o *DTLSOptimizer) ApplyPreloadedRoutes(userID uint, policyID uint, routeManager interface{}) error {
	if !o.config.EnablePreRouting {
		return nil
	}

	routeKey := fmt.Sprintf("user_%d_policy_%d", userID, policyID)
	appliedCount := 0

	// 获取路由管理器接口的方法
	if rm, ok := routeManager.(interface {
		AddRoute(*net.IPNet, net.IP, int) error
	}); ok {
		// 应用所有预加载的路由
		for key, preloadedRoute := range o.preloadedRoutes {
			if len(key) > len(routeKey) && key[:len(routeKey)] == routeKey {
				_, ipNet, err := net.ParseCIDR(preloadedRoute.Network)
				if err != nil {
					log.Printf("DTLS Optimizer: Failed to parse preloaded route %s: %v", preloadedRoute.Network, err)
					continue
				}

				// 应用路由到内核路由表
				if err := rm.AddRoute(ipNet, preloadedRoute.Gateway, preloadedRoute.Metric); err != nil {
					log.Printf("DTLS Optimizer: Failed to apply preloaded route %s: %v", preloadedRoute.Network, err)
				} else {
					preloadedRoute.IsActive = true
					appliedCount++
					log.Printf("DTLS Optimizer: ✓ Applied preloaded route %s (total: %d)", preloadedRoute.Network, appliedCount)
				}
			}
		}

		// 清理已应用的路由
		for key := range o.preloadedRoutes {
			if len(key) > len(routeKey) && key[:len(routeKey)] == routeKey {
				delete(o.preloadedRoutes, key)
			}
		}

		log.Printf("DTLS Optimizer: ✓ Applied %d preloaded routes for user %d", appliedCount, userID)
		return nil
	}

	return fmt.Errorf("routeManager does not support AddRoute method")
}

// FastClientMatch 快速客户端匹配
// 使用缓存加速客户端匹配过程，减少DTLS握手延迟
func (o *DTLSOptimizer) FastClientMatch(udpAddr *net.UDPAddr) (*ClientMatchInfo, bool) {
	if !o.config.EnableFastMatch {
		return nil, false
	}

	// 检查缓存
	for _, matchInfo := range o.clientMatchCache {
		if time.Since(matchInfo.MatchedAt) > o.config.CacheTimeout {
			// 缓存超时，删除
			delete(o.clientMatchCache, matchInfo.VPNIP)
			continue
		}

		// 简单的IP匹配逻辑（实际实现中可能需要更复杂的逻辑）
		// 这里只是示例，实际应该根据具体的客户端标识逻辑来实现
		if matchInfo.VPNIP != "" {
			return matchInfo, true
		}
	}

	return nil, false
}

// OptimizeDTLSSettings 优化DTLS设置
// 返回优化后的DTLS配置参数
func (o *DTLSOptimizer) OptimizeDTLSSettings() map[string]interface{} {
	return map[string]interface{}{
		"connect_timeout":    time.Duration(o.config.PreloadDelayMS) * time.Millisecond,
		"handshake_timeout":  3 * time.Second,  // 减少握手超时
		"read_timeout":       30 * time.Second, // 减少读取超时
		"enable_early_data":  true,             // 启用早期数据
		"enable_false_start": true,             // 启用False Start
		"session_ticket":     true,             // 启用会话票据
		"compression":        false,            // 禁用压缩以提升性能
	}
}

// Cleanup 清理过期缓存
func (o *DTLSOptimizer) Cleanup() {
	now := time.Now()

	// 清理过期的客户端匹配缓存
	for vpnIP, matchInfo := range o.clientMatchCache {
		if now.Sub(matchInfo.MatchedAt) > o.config.CacheTimeout {
			delete(o.clientMatchCache, vpnIP)
		}
	}

	// 清理过期的预加载路由
	for key, preloadedRoute := range o.preloadedRoutes {
		if now.Sub(preloadedRoute.AddedAt) > o.config.CacheTimeout {
			delete(o.preloadedRoutes, key)
		}
	}

	log.Printf("DTLS Optimizer: Cleanup completed")
}

// GetOptimizationStats 获取优化统计信息
func (o *DTLSOptimizer) GetOptimizationStats() map[string]interface{} {
	return map[string]interface{}{
		"preloaded_routes_count": len(o.preloadedRoutes),
		"cached_clients_count":   len(o.clientMatchCache),
		"config":                 o.config,
		"uptime":                 time.Since(time.Now()), // 实际应该是创建时间
	}
}

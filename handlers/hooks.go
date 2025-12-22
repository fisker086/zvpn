package handlers

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/vpn"
	"github.com/fisker/zvpn/vpn/policy"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type HookHandler struct {
	config    *config.Config
	vpnServer *vpn.VPNServer
}

func NewHookHandler(cfg *config.Config) *HookHandler {
	return &HookHandler{config: cfg}
}

// SetVPNServer sets the VPN server instance
func (h *HookHandler) SetVPNServer(vpnServer *vpn.VPNServer) {
	h.vpnServer = vpnServer
}

type CreateHookRequest struct {
	Name        string            `json:"name" binding:"required"`
	HookPoint   models.HookPoint  `json:"hook_point"`
	Priority    int               `json:"priority" binding:"required,min=1,max=100"`
	Type        models.HookType   `json:"type" binding:"required"`
	Description string            `json:"description"`
	Rules       []models.HookRule `json:"rules"`
	Enabled     bool              `json:"enabled"`
}

type UpdateHookRequest struct {
	Name        *string            `json:"name"`
	Priority    *int               `json:"priority"`
	Description *string            `json:"description"`
	Rules       *[]models.HookRule `json:"rules"`
	Enabled     *bool              `json:"enabled"`
}

type ToggleHookRequest struct {
	Enabled bool `json:"enabled"`
}

// ListHooks 获取 Hook 列表
func (h *HookHandler) ListHooks(c *gin.Context) {
	var hooks []models.Hook
	if err := database.DB.Find(&hooks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 添加统计信息
	if h.vpnServer != nil {
		policyMgr := h.vpnServer.GetPolicyManager()
		if policyMgr != nil {
			allStats := policyMgr.GetAllHookStats()
			for i := range hooks {
				if stats, exists := allStats[hooks[i].ID]; exists {
					hooks[i].Stats = stats
				}
			}
		}
	}

	c.JSON(http.StatusOK, hooks)
}

// GetHook 获取 Hook 详情
func (h *HookHandler) GetHook(c *gin.Context) {
	id := c.Param("id")

	var hook models.Hook
	if err := database.DB.First(&hook, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Hook not found"})
		return
	}

	// 添加统计信息
	if h.vpnServer != nil {
		policyMgr := h.vpnServer.GetPolicyManager()
		if policyMgr != nil {
			hook.Stats = policyMgr.GetHookStats(hook.ID)
		}
	}

	c.JSON(http.StatusOK, hook)
}

// CreateHook 创建 Hook
func (h *HookHandler) CreateHook(c *gin.Context) {
	var req CreateHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hook := models.Hook{
		ID:          uuid.New().String(),
		Name:        req.Name,
		HookPoint:   req.HookPoint,
		Priority:    req.Priority,
		Type:        req.Type,
		Description: req.Description,
		Rules:       req.Rules,
		Enabled:     req.Enabled,
	}

	// 保存到数据库
	if err := database.DB.Create(&hook).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 如果启用，则注册到策略管理器
	if hook.Enabled && h.vpnServer != nil {
		policyMgr := h.vpnServer.GetPolicyManager()
		if policyMgr != nil {
			// 容量预检查：避免超过 eBPF 链表 64 限制
			count := policyMgr.GetRegistry().HookCount(policy.HookPoint(hook.HookPoint))
			if count >= policy.MaxHookChainEntries {
				database.DB.Delete(&hook)
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Hook 点已达上限 %d 条，请删除后再添加", policy.MaxHookChainEntries)})
				return
			}

			// Try to use distributed sync manager for immediate sync
			if dsm := policyMgr.GetDistributedSyncManager(); dsm != nil {
				if err := dsm.SyncHook(hook.ID); err != nil {
					log.Printf("Failed to sync hook %s via distributed sync: %v", hook.ID, err)
					// Fallback to direct registration
					policyHook := convertModelHookToPolicyHook(&hook)
					if policyHook != nil {
						if err := policyMgr.RegisterHook(policyHook); err != nil {
							log.Printf("Failed to register hook %s: %v", hook.ID, err)
							database.DB.Delete(&hook)
							c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
							return
						}
					}
				} else {
					log.Printf("Hook %s synced via distributed sync manager", hook.ID)
				}
			} else {
				// Fallback to direct registration
				policyHook := convertModelHookToPolicyHook(&hook)
				if policyHook != nil {
					if err := policyMgr.RegisterHook(policyHook); err != nil {
						log.Printf("Failed to register hook %s: %v", hook.ID, err)
						database.DB.Delete(&hook)
						c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
						return
					} else {
						log.Printf("Hook %s registered successfully", hook.ID)
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, hook)
}

// UpdateHook 更新 Hook
func (h *HookHandler) UpdateHook(c *gin.Context) {
	id := c.Param("id")

	var hook models.Hook
	if err := database.DB.First(&hook, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Hook not found"})
		return
	}

	var req UpdateHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 更新字段
	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Priority != nil {
		if *req.Priority < 1 || *req.Priority > 100 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Priority must be between 1 and 100"})
			return
		}
		updates["priority"] = *req.Priority
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.Rules != nil {
		updates["rules"] = models.HookRules(*req.Rules)
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}

	if err := database.DB.Model(&hook).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 重新加载 Hook
	database.DB.First(&hook, "id = ?", id)

	// 重新注册到策略管理器
	if h.vpnServer != nil {
		policyMgr := h.vpnServer.GetPolicyManager()
		if policyMgr != nil {
			// 容量预检查：仅当启用时检查
			if hook.Enabled {
				count := policyMgr.GetRegistry().HookCount(policy.HookPoint(hook.HookPoint))
				// 如果当前已注册且将重新注册，放行；如果未注册且已满，则拒绝
				isRegistered := false
				all := policyMgr.GetRegistry().GetAllHooks()
				for _, hooks := range all {
					for _, h := range hooks {
						if h.Name() == hook.ID {
							isRegistered = true
							break
						}
					}
				}
				if !isRegistered && count >= policy.MaxHookChainEntries {
					hook.Enabled = false
					database.DB.Save(&hook)
					c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Hook 点已达上限 %d 条，请删除后再启用", policy.MaxHookChainEntries)})
					return
				}
			}

			// Try to use distributed sync manager for immediate sync
			if dsm := policyMgr.GetDistributedSyncManager(); dsm != nil {
				if err := dsm.SyncHook(hook.ID); err != nil {
					log.Printf("Failed to sync hook %s via distributed sync: %v", hook.ID, err)
					// Fallback to direct registration
					hookPoint := policy.HookPoint(hook.HookPoint)
					if err := policyMgr.UnregisterHook(hook.ID, hookPoint); err != nil {
						log.Printf("Warning: Failed to unregister hook %s: %v", hook.ID, err)
					}
					if hook.Enabled {
						policyHook := convertModelHookToPolicyHook(&hook)
						if policyHook != nil {
							if err := policyMgr.RegisterHook(policyHook); err != nil {
								log.Printf("Failed to register hook %s: %v", hook.ID, err)
								hook.Enabled = false
								database.DB.Save(&hook)
								c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
								return
							}
						}
					}
				} else {
					log.Printf("Hook %s updated via distributed sync manager", hook.ID)
				}
			} else {
				// Fallback to direct registration
				hookPoint := policy.HookPoint(hook.HookPoint)
				if err := policyMgr.UnregisterHook(hook.ID, hookPoint); err != nil {
					log.Printf("Warning: Failed to unregister hook %s: %v", hook.ID, err)
				}
				if hook.Enabled {
					policyHook := convertModelHookToPolicyHook(&hook)
					if policyHook != nil {
						if err := policyMgr.RegisterHook(policyHook); err != nil {
							log.Printf("Failed to register hook %s: %v", hook.ID, err)
							hook.Enabled = false
							database.DB.Save(&hook)
							c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
							return
						} else {
							log.Printf("Hook %s re-registered successfully", hook.ID)
						}
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, hook)
}

// DeleteHook 删除 Hook
func (h *HookHandler) DeleteHook(c *gin.Context) {
	id := c.Param("id")

	var hook models.Hook
	if err := database.DB.First(&hook, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Hook not found"})
		return
	}

	// 从策略管理器注销
	if h.vpnServer != nil {
		policyMgr := h.vpnServer.GetPolicyManager()
		if policyMgr != nil {
			hookPoint := policy.HookPoint(hook.HookPoint)
			if err := policyMgr.UnregisterHook(hook.ID, hookPoint); err != nil {
				log.Printf("Warning: Failed to unregister hook %s: %v", hook.ID, err)
			}
		}
	}

	// 从数据库删除
	if err := database.DB.Delete(&hook).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Hook deleted"})
}

// ToggleHook 启用/禁用 Hook
func (h *HookHandler) ToggleHook(c *gin.Context) {
	id := c.Param("id")

	var hook models.Hook
	if err := database.DB.First(&hook, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Hook not found"})
		return
	}

	var req ToggleHookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hook.Enabled = req.Enabled
	if err := database.DB.Save(&hook).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 更新策略管理器
	if h.vpnServer != nil {
		policyMgr := h.vpnServer.GetPolicyManager()
		if policyMgr != nil {
			hookPoint := policy.HookPoint(hook.HookPoint)
			// 先注销
			if err := policyMgr.UnregisterHook(hook.ID, hookPoint); err != nil {
				log.Printf("Warning: Failed to unregister hook %s: %v", hook.ID, err)
			}
			// 如果启用，重新注册
			if hook.Enabled {
				// 容量预检查
				count := policyMgr.GetRegistry().HookCount(hookPoint)
				if count >= policy.MaxHookChainEntries {
					hook.Enabled = false
					database.DB.Save(&hook)
					c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Hook 点已达上限 %d 条，请删除后再启用", policy.MaxHookChainEntries)})
					return
				}

				policyHook := convertModelHookToPolicyHook(&hook)
				if policyHook != nil {
					if err := policyMgr.RegisterHook(policyHook); err != nil {
						log.Printf("Failed to register hook %s: %v", hook.ID, err)
						hook.Enabled = false
						database.DB.Save(&hook)
						c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
						return
					} else {
						log.Printf("Hook %s toggled successfully", hook.ID)
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, hook)
}

// GetHookStats 获取 Hook 统计
func (h *HookHandler) GetHookStats(c *gin.Context) {
	id := c.Param("id")

	if h.vpnServer == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "VPN server not initialized"})
		return
	}

	policyMgr := h.vpnServer.GetPolicyManager()
	if policyMgr == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Policy manager not initialized"})
		return
	}

	stats := policyMgr.GetHookStats(id)
	c.JSON(http.StatusOK, stats)
}

// convertModelHookToPolicyHook uses the shared converter from policy package
func convertModelHookToPolicyHook(hookModel *models.Hook) policy.Hook {
	return policy.ConvertModelHookToPolicyHook(hookModel)
}

// convertToACLHook converts a models.Hook to an ACLHook
func convertToACLHook(hookModel *models.Hook, hookPoint policy.HookPoint) policy.Hook {
	action := convertAction(hookModel.Rules)
	hook := policy.NewACLHook(hookModel.ID, hookPoint, hookModel.Priority, action)

	// Process rules
	for _, rule := range hookModel.Rules {
		// Add source IPs/networks
		for _, ipStr := range rule.SourceIPs {
			if ip := net.ParseIP(ipStr); ip != nil {
				hook.AddSourceIP(ip)
			}
		}
		for _, netStr := range rule.SourceNetworks {
			if _, ipNet, err := net.ParseCIDR(netStr); err == nil {
				hook.AddSourceNetwork(ipNet)
			}
		}

		// Add destination IPs/networks
		for _, ipStr := range rule.DestinationIPs {
			if ip := net.ParseIP(ipStr); ip != nil {
				hook.AddDestinationIP(ip)
			}
		}
		for _, netStr := range rule.DestinationNetworks {
			if _, ipNet, err := net.ParseCIDR(netStr); err == nil {
				hook.AddDestinationNetwork(ipNet)
			}
		}
	}

	return hook
}

// convertToPortFilterHook converts a models.Hook to a PortFilterHook
func convertToPortFilterHook(hookModel *models.Hook, hookPoint policy.HookPoint) policy.Hook {
	action := convertAction(hookModel.Rules)
	hook := policy.NewPortFilterHook(hookModel.ID, hookPoint, hookModel.Priority, action)

	// Process rules
	for _, rule := range hookModel.Rules {
		// Add ports
		for _, port := range rule.DestinationPorts {
			hook.AddPort(uint16(port))
		}
		for _, port := range rule.SourcePorts {
			hook.AddPort(uint16(port))
		}

		// Add port ranges
		for _, portRange := range rule.PortRanges {
			hook.AddPortRange(uint16(portRange.Start), uint16(portRange.End))
		}
	}

	return hook
}

// convertToUserPolicyHook converts a models.Hook to a UserPolicyHook
func convertToUserPolicyHook(hookModel *models.Hook, hookPoint policy.HookPoint) policy.Hook {
	hook := policy.NewUserPolicyHook(hookModel.ID, hookPoint, hookModel.Priority)

	// Process rules
	for _, rule := range hookModel.Rules {
		action := convertAction([]models.HookRule{rule})
		for _, userID := range rule.UserIDs {
			if action == policy.ActionAllow {
				hook.AllowUser(userID)
			} else {
				hook.DenyUser(userID)
			}
		}
	}

	return hook
}

// convertAction converts models.PolicyAction to policy.Action
func convertAction(rules []models.HookRule) policy.Action {
	if len(rules) == 0 {
		return policy.ActionAllow
	}

	switch rules[0].Action {
	case models.Allow:
		return policy.ActionAllow
	case models.Deny:
		return policy.ActionDeny
	case models.Redirect:
		return policy.ActionRedirect
	case models.Log:
		return policy.ActionLog
	default:
		return policy.ActionAllow
	}
}

// TestHook 测试 Hook
func (h *HookHandler) TestHook(c *gin.Context) {
	id := c.Param("id")

	var hook models.Hook
	if err := database.DB.First(&hook, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Hook not found"})
		return
	}

	var testData struct {
		SourceIP      string `json:"source_ip"`
		DestinationIP string `json:"destination_ip"`
		SourcePort    int    `json:"source_port"`
		DestPort      int    `json:"dest_port"`
		Protocol      string `json:"protocol"`
	}

	if err := c.ShouldBindJSON(&testData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: 执行测试逻辑
	// result := policy.TestHookRule(&hook, testData.SourceIP, testData.DestinationIP,
	//     testData.SourcePort, testData.DestPort, testData.Protocol)
	// c.JSON(http.StatusOK, gin.H{
	//     "matched": result.Matched,
	//     "action":  result.Action,
	//     "rule":    result.RuleIndex,
	// })

	// 临时返回测试结果
	c.JSON(http.StatusOK, gin.H{
		"matched": true,
		"action":  models.Allow,
		"rule":    0,
	})
}

// SyncHook 手动同步特定 Hook
func (h *HookHandler) SyncHook(c *gin.Context) {
	id := c.Param("id")

	if h.vpnServer == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "VPN server not initialized"})
		return
	}

	policyMgr := h.vpnServer.GetPolicyManager()
	if policyMgr == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Policy manager not initialized"})
		return
	}

	// Distributed sync must be enabled
	dsm := policyMgr.GetDistributedSyncManager()
	if dsm == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Distributed sync disabled"})
		return
	}

	if err := dsm.SyncHook(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Hook synced successfully",
		"hook_id": id,
		"node_id": dsm.GetNodeID(),
	})
}

// GetSyncStatus 获取同步状态
func (h *HookHandler) GetSyncStatus(c *gin.Context) {
	if h.vpnServer == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "VPN server not initialized"})
		return
	}

	policyMgr := h.vpnServer.GetPolicyManager()
	if policyMgr == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Policy manager not initialized"})
		return
	}

	// Use distributed sync manager when available
	if dsm := policyMgr.GetDistributedSyncManager(); dsm != nil {
		status := dsm.GetSyncStatus()
		c.JSON(http.StatusOK, status)
		return
	}

	// Distributed sync disabled
	c.JSON(http.StatusOK, gin.H{
		"node_id":   "disabled",
		"running":   false,
		"sync_type": "disabled",
		"last_sync": time.Now(),
	})
}

// ForceSync 强制全量同步
func (h *HookHandler) ForceSync(c *gin.Context) {
	if h.vpnServer == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "VPN server not initialized"})
		return
	}

	policyMgr := h.vpnServer.GetPolicyManager()
	if policyMgr == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Policy manager not initialized"})
		return
	}

	// Distributed sync must be enabled
	if dsm := policyMgr.GetDistributedSyncManager(); dsm != nil {
		policyMgr.ForceSyncHooks()
		c.JSON(http.StatusOK, gin.H{
			"message": "Full sync triggered",
			"node_id": dsm.GetNodeID(),
		})
		return
	}

	c.JSON(http.StatusBadRequest, gin.H{"error": "Distributed sync disabled"})
}

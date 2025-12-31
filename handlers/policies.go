package handlers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/gin-gonic/gin"
)

type PolicyHandler struct {
	config *config.Config
}

func NewPolicyHandler(cfg *config.Config) *PolicyHandler {
	return &PolicyHandler{config: cfg}
}

type CreatePolicyRequest struct {
	Name         string   `json:"name" binding:"required"`
	Description  string   `json:"description"`
	Routes       []string `json:"routes"` // CIDR format
	MaxBandwidth int64    `json:"max_bandwidth"`
	DNSServers   []string `json:"dns_servers"` // DNS server IPs
	GroupIDs     []uint   `json:"group_ids" binding:"required"` // 必须绑定至少一个用户组
}

// PolicyResponse 用于API响应的Policy结构，DNS字段为数组
type PolicyResponse struct {
	ID             uint                      `json:"id"`
	CreatedAt      time.Time                 `json:"created_at"`
	UpdatedAt      time.Time                 `json:"updated_at"`
	Name           string                    `json:"name"`
	Description    string                    `json:"description"`
	Routes         []models.Route            `json:"routes"`
	ExcludeRoutes  []models.ExcludeRoute     `json:"exclude_routes"`
	AllowedNetworks []models.AllowedNetwork  `json:"allowed_networks"`
	MaxBandwidth   int64                     `json:"max_bandwidth"`
	DNSServers     []string                  `json:"dns_servers"`
	TimeRestrictions []models.TimeRestriction `json:"time_restrictions"`
	Groups         []models.UserGroup        `json:"groups,omitempty"`
}

// convertPolicyToResponse 将数据库Policy转换为API响应格式
func convertPolicyToResponse(policy models.Policy) PolicyResponse {
	var dnsServers []string
	if policy.DNSServers != "" {
		if err := json.Unmarshal([]byte(policy.DNSServers), &dnsServers); err != nil {
			// 如果解析失败，返回空数组
			dnsServers = []string{}
		}
	}
	
	return PolicyResponse{
		ID:              policy.ID,
		CreatedAt:       policy.CreatedAt,
		UpdatedAt:       policy.UpdatedAt,
		Name:            policy.Name,
		Description:     policy.Description,
		Routes:          policy.Routes,
		ExcludeRoutes:   policy.ExcludeRoutes,
		AllowedNetworks: policy.AllowedNetworks,
		MaxBandwidth:    policy.MaxBandwidth,
		DNSServers:      dnsServers,
		TimeRestrictions: policy.TimeRestrictions,
		Groups:          policy.Groups,
	}
}

func (h *PolicyHandler) ListPolicies(c *gin.Context) {
	var policies []models.Policy
	if err := database.DB.Preload("Routes").Preload("ExcludeRoutes").Preload("AllowedNetworks").Preload("Groups").Find(&policies).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 转换为响应格式
	responses := make([]PolicyResponse, len(policies))
	for i, policy := range policies {
		responses[i] = convertPolicyToResponse(policy)
	}

	c.JSON(http.StatusOK, responses)
}

func (h *PolicyHandler) GetPolicy(c *gin.Context) {
	id := c.Param("id")
	var policy models.Policy
	if err := database.DB.Preload("Routes").Preload("ExcludeRoutes").Preload("AllowedNetworks").Preload("TimeRestrictions").Preload("Groups").First(&policy, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	c.JSON(http.StatusOK, convertPolicyToResponse(policy))
}

func (h *PolicyHandler) CreatePolicy(c *gin.Context) {
	var req CreatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证用户组是否存在（必填）
	if len(req.GroupIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "策略必须绑定至少一个用户组"})
		return
	}

	var groups []models.UserGroup
	if err := database.DB.Find(&groups, req.GroupIDs).Error; err != nil || len(groups) != len(req.GroupIDs) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "部分用户组不存在"})
		return
	}

	// 序列化DNS服务器数组为JSON字符串
	var dnsServersJSON string
	if len(req.DNSServers) > 0 {
		dnsBytes, err := json.Marshal(req.DNSServers)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "DNS服务器格式错误"})
			return
		}
		dnsServersJSON = string(dnsBytes)
	}

	policy := &models.Policy{
		Name:         req.Name,
		Description:  req.Description,
		MaxBandwidth: req.MaxBandwidth,
		DNSServers:   dnsServersJSON,
		Groups:       groups, // 创建时即绑定用户组
	}

	if err := database.DB.Create(policy).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Add routes
	for _, routeStr := range req.Routes {
		route := &models.Route{
			PolicyID: policy.ID,
			Network:  routeStr,
			Metric:   100,
		}
		database.DB.Create(route)
	}

	// 预加载用户组和路由
	database.DB.Preload("Routes").Preload("Groups").First(policy, policy.ID)
	c.JSON(http.StatusCreated, convertPolicyToResponse(*policy))
}

func (h *PolicyHandler) UpdatePolicy(c *gin.Context) {
	id := c.Param("id")
	var policy models.Policy
	if err := database.DB.Preload("Routes").First(&policy, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	var req struct {
		Name         string   `json:"name"`
		Description  string   `json:"description"`
		MaxBandwidth int64    `json:"max_bandwidth"`
		DNSServers   []string `json:"dns_servers"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Name != "" {
		policy.Name = req.Name
	}
	if req.Description != "" {
		policy.Description = req.Description
	}
	policy.MaxBandwidth = req.MaxBandwidth
	
	// 更新DNS服务器
	if req.DNSServers != nil {
		if len(req.DNSServers) > 0 {
			dnsBytes, err := json.Marshal(req.DNSServers)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "DNS服务器格式错误"})
				return
			}
			policy.DNSServers = string(dnsBytes)
		} else {
			policy.DNSServers = "" // 清空DNS配置，使用系统默认
		}
	}

	if err := database.DB.Save(&policy).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	database.DB.Preload("Routes").Preload("AllowedNetworks").Preload("Groups").First(&policy, policy.ID)
	c.JSON(http.StatusOK, convertPolicyToResponse(policy))
}

func (h *PolicyHandler) DeletePolicy(c *gin.Context) {
	id := c.Param("id")
	
	// 先获取策略信息
	var policy models.Policy
	if err := database.DB.First(&policy, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	// 开始事务，确保所有删除操作原子性
	tx := database.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 1. 删除策略与用户组的关联关系（user_group_policies 中间表）
	if err := tx.Model(&policy).Association("Groups").Clear(); err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to remove groups from policy: %v", err)})
		return
	}

	// 2. 删除策略的路由（Routes 表，PolicyID 外键）
	if err := tx.Where("policy_id = ?", policy.ID).Unscoped().Delete(&models.Route{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete policy routes: %v", err)})
		return
	}

	// 2.5. 删除策略的排除路由（ExcludeRoutes 表，PolicyID 外键）
	if err := tx.Where("policy_id = ?", policy.ID).Unscoped().Delete(&models.ExcludeRoute{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete policy exclude routes: %v", err)})
		return
	}

	// 3. 删除策略的允许网络（AllowedNetworks 表，PolicyID 外键）
	if err := tx.Where("policy_id = ?", policy.ID).Unscoped().Delete(&models.AllowedNetwork{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete policy allowed networks: %v", err)})
		return
	}

	// 4. 删除策略的时间限制（TimeRestrictions 表，PolicyID 外键）
	if err := tx.Where("policy_id = ?", policy.ID).Unscoped().Delete(&models.TimeRestriction{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete policy time restrictions: %v", err)})
		return
	}

	// 5. 删除策略本身
	if err := tx.Unscoped().Delete(&policy).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete policy: %v", err)})
		return
	}

	// 提交事务
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to commit transaction: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted successfully"})
}

func (h *PolicyHandler) AddRoute(c *gin.Context) {
	id := c.Param("id")
	var policy models.Policy
	if err := database.DB.First(&policy, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	var req struct {
		Network string `json:"network" binding:"required"`
		Gateway string `json:"gateway"`
		Metric  int    `json:"metric"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Metric == 0 {
		req.Metric = 100
	}

	route := &models.Route{
		PolicyID: policy.ID,
		Network:  req.Network,
		Gateway:  req.Gateway,
		Metric:   req.Metric,
	}

	if err := database.DB.Create(route).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, route)
}

func (h *PolicyHandler) UpdateRoute(c *gin.Context) {
	policyID := c.Param("id")
	routeID := c.Param("route_id")

	// 验证策略是否存在
	var policy models.Policy
	if err := database.DB.First(&policy, policyID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	// 验证路由是否存在且属于该策略
	var route models.Route
	if err := database.DB.Where("id = ? AND policy_id = ?", routeID, policyID).First(&route).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Route not found"})
		return
	}

	// 绑定请求参数
	var req struct {
		Network string `json:"network"`
		Gateway string `json:"gateway"`
		Metric  int    `json:"metric"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 更新路由字段
	if req.Network != "" {
		route.Network = req.Network
	}
	route.Gateway = req.Gateway // 允许清空网关
	if req.Metric > 0 {
		route.Metric = req.Metric
	}

	// 保存更新
	if err := database.DB.Save(&route).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, route)
}

func (h *PolicyHandler) DeleteRoute(c *gin.Context) {
	id := c.Param("route_id")
	if err := database.DB.Delete(&models.Route{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Route deleted"})
}

// AddExcludeRoute 添加排除路由
func (h *PolicyHandler) AddExcludeRoute(c *gin.Context) {
	id := c.Param("id")
	var policy models.Policy
	if err := database.DB.First(&policy, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	var req struct {
		Network string `json:"network" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证CIDR格式
	if _, _, err := net.ParseCIDR(req.Network); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid CIDR format"})
		return
	}

	excludeRoute := &models.ExcludeRoute{
		PolicyID: policy.ID,
		Network:  req.Network,
	}

	if err := database.DB.Create(excludeRoute).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, excludeRoute)
}

// UpdateExcludeRoute 更新排除路由
func (h *PolicyHandler) UpdateExcludeRoute(c *gin.Context) {
	policyID := c.Param("id")
	excludeRouteID := c.Param("exclude_route_id")

	// 验证策略是否存在
	var policy models.Policy
	if err := database.DB.First(&policy, policyID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	// 验证排除路由是否存在且属于该策略
	var excludeRoute models.ExcludeRoute
	if err := database.DB.Where("id = ? AND policy_id = ?", excludeRouteID, policyID).First(&excludeRoute).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Exclude route not found"})
		return
	}

	// 绑定请求参数
	var req struct {
		Network string `json:"network"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 更新排除路由字段
	if req.Network != "" {
		// 验证CIDR格式
		if _, _, err := net.ParseCIDR(req.Network); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid CIDR format"})
			return
		}
		excludeRoute.Network = req.Network
	}

	// 保存更新
	if err := database.DB.Save(&excludeRoute).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, excludeRoute)
}

// DeleteExcludeRoute 删除排除路由
func (h *PolicyHandler) DeleteExcludeRoute(c *gin.Context) {
	policyID := c.Param("id")
	excludeRouteID := c.Param("exclude_route_id")

	// 验证策略是否存在
	var policy models.Policy
	if err := database.DB.First(&policy, policyID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	// 验证排除路由是否存在且属于该策略
	var excludeRoute models.ExcludeRoute
	if err := database.DB.Where("id = ? AND policy_id = ?", excludeRouteID, policyID).First(&excludeRoute).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Exclude route not found"})
		return
	}

	if err := database.DB.Delete(&excludeRoute).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Exclude route deleted"})
}

// AssignGroups 给策略分配用户组
func (h *PolicyHandler) AssignGroups(c *gin.Context) {
	id := c.Param("id")
	var policy models.Policy
	if err := database.DB.First(&policy, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	var req struct {
		GroupIDs []uint `json:"group_ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var groups []models.UserGroup
	if err := database.DB.Find(&groups, req.GroupIDs).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Some groups not found"})
		return
	}

	// 更新关联关系
	if err := database.DB.Model(&policy).Association("Groups").Replace(groups); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 注意：不再直接更新用户的 PolicyID，策略通过用户组动态获取

	database.DB.Preload("Routes").Preload("Groups").First(&policy, policy.ID)
	c.JSON(http.StatusOK, convertPolicyToResponse(policy))
}

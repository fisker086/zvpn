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
	DNSServers   []string `json:"dns_servers"`                  // DNS server IPs
	SplitDNS     []string `json:"split_dns"`                    // Split-DNS domains, e.g. ["example.com", "*.example.com"]
	GroupIDs     []uint   `json:"group_ids" binding:"required"` // 必须绑定至少一个用户组
}

type PolicyResponse struct {
	ID               uint                     `json:"id"`
	CreatedAt        time.Time                `json:"created_at"`
	UpdatedAt        time.Time                `json:"updated_at"`
	Name             string                   `json:"name"`
	Description      string                   `json:"description"`
	Routes           []models.Route           `json:"routes"`
	ExcludeRoutes    []models.ExcludeRoute    `json:"exclude_routes"`
	AllowedNetworks  []models.AllowedNetwork  `json:"allowed_networks"`
	MaxBandwidth     int64                    `json:"max_bandwidth"`
	DNSServers       []string                 `json:"dns_servers"`
	SplitDNS         []string                 `json:"split_dns"` // Split-DNS domains
	TimeRestrictions []models.TimeRestriction `json:"time_restrictions"`
	Groups           []models.UserGroup       `json:"groups,omitempty"`
}

func convertPolicyToResponse(policy models.Policy) PolicyResponse {
	var dnsServers []string
	if policy.DNSServers != "" {
		if err := json.Unmarshal([]byte(policy.DNSServers), &dnsServers); err != nil {
			dnsServers = []string{}
		}
	}

	var splitDNS []string
	if policy.SplitDNS != "" {
		if err := json.Unmarshal([]byte(policy.SplitDNS), &splitDNS); err != nil {
			splitDNS = []string{}
		}
	}

	return PolicyResponse{
		ID:               policy.ID,
		CreatedAt:        policy.CreatedAt,
		UpdatedAt:        policy.UpdatedAt,
		Name:             policy.Name,
		Description:      policy.Description,
		Routes:           policy.Routes,
		ExcludeRoutes:    policy.ExcludeRoutes,
		AllowedNetworks:  policy.AllowedNetworks,
		MaxBandwidth:     policy.MaxBandwidth,
		DNSServers:       dnsServers,
		SplitDNS:         splitDNS,
		TimeRestrictions: policy.TimeRestrictions,
		Groups:           policy.Groups,
	}
}

func (h *PolicyHandler) ListPolicies(c *gin.Context) {
	var policies []models.Policy
	if err := database.DB.Preload("Routes").Preload("ExcludeRoutes").Preload("AllowedNetworks").Preload("Groups").Find(&policies).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

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

	if len(req.GroupIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "策略必须绑定至少一个用户组"})
		return
	}

	var groups []models.UserGroup
	if err := database.DB.Find(&groups, req.GroupIDs).Error; err != nil || len(groups) != len(req.GroupIDs) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "部分用户组不存在"})
		return
	}

	var dnsServersJSON string
	if len(req.DNSServers) > 0 {
		dnsBytes, err := json.Marshal(req.DNSServers)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "DNS服务器格式错误"})
			return
		}
		dnsServersJSON = string(dnsBytes)
	}

	var splitDNSJSON string
	if len(req.SplitDNS) > 0 {
		splitDNSBytes, err := json.Marshal(req.SplitDNS)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Split-DNS域名格式错误"})
			return
		}
		splitDNSJSON = string(splitDNSBytes)
	}

	policy := &models.Policy{
		Name:         req.Name,
		Description:  req.Description,
		SplitDNS:     splitDNSJSON,
		MaxBandwidth: req.MaxBandwidth,
		DNSServers:   dnsServersJSON,
		Groups:       groups, // 创建时即绑定用户组
	}

	if err := database.DB.Create(policy).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	for _, routeStr := range req.Routes {
		route := &models.Route{
			PolicyID: policy.ID,
			Network:  routeStr,
			Metric:   100,
		}
		database.DB.Create(route)
	}

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
		SplitDNS     []string `json:"split_dns"`
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

	if req.SplitDNS != nil {
		if len(req.SplitDNS) > 0 {
			splitDNSBytes, err := json.Marshal(req.SplitDNS)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Split-DNS域名格式错误"})
				return
			}
			policy.SplitDNS = string(splitDNSBytes)
		} else {
			policy.SplitDNS = "" // 清空Split-DNS配置
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

	var policy models.Policy
	if err := database.DB.First(&policy, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	tx := database.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	if err := tx.Model(&policy).Association("Groups").Clear(); err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to remove groups from policy: %v", err)})
		return
	}

	if err := tx.Where("policy_id = ?", policy.ID).Unscoped().Delete(&models.Route{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete policy routes: %v", err)})
		return
	}

	if err := tx.Where("policy_id = ?", policy.ID).Unscoped().Delete(&models.ExcludeRoute{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete policy exclude routes: %v", err)})
		return
	}

	if err := tx.Where("policy_id = ?", policy.ID).Unscoped().Delete(&models.AllowedNetwork{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete policy allowed networks: %v", err)})
		return
	}

	if err := tx.Where("policy_id = ?", policy.ID).Unscoped().Delete(&models.TimeRestriction{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete policy time restrictions: %v", err)})
		return
	}

	if err := tx.Unscoped().Delete(&policy).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete policy: %v", err)})
		return
	}

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

	var policy models.Policy
	if err := database.DB.First(&policy, policyID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	var route models.Route
	if err := database.DB.Where("id = ? AND policy_id = ?", routeID, policyID).First(&route).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Route not found"})
		return
	}

	var req struct {
		Network string `json:"network"`
		Gateway string `json:"gateway"`
		Metric  int    `json:"metric"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Network != "" {
		route.Network = req.Network
	}
	route.Gateway = req.Gateway // 允许清空网关
	if req.Metric > 0 {
		route.Metric = req.Metric
	}

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

func (h *PolicyHandler) UpdateExcludeRoute(c *gin.Context) {
	policyID := c.Param("id")
	excludeRouteID := c.Param("exclude_route_id")

	var policy models.Policy
	if err := database.DB.First(&policy, policyID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	var excludeRoute models.ExcludeRoute
	if err := database.DB.Where("id = ? AND policy_id = ?", excludeRouteID, policyID).First(&excludeRoute).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Exclude route not found"})
		return
	}

	var req struct {
		Network string `json:"network"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Network != "" {
		if _, _, err := net.ParseCIDR(req.Network); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid CIDR format"})
			return
		}
		excludeRoute.Network = req.Network
	}

	if err := database.DB.Save(&excludeRoute).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, excludeRoute)
}

func (h *PolicyHandler) DeleteExcludeRoute(c *gin.Context) {
	policyID := c.Param("id")
	excludeRouteID := c.Param("exclude_route_id")

	var policy models.Policy
	if err := database.DB.First(&policy, policyID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

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

	if err := database.DB.Model(&policy).Association("Groups").Replace(groups); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	database.DB.Preload("Routes").Preload("Groups").First(&policy, policy.ID)
	c.JSON(http.StatusOK, convertPolicyToResponse(policy))
}


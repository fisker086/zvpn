package handlers

import (
	"net/http"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/gin-gonic/gin"
)

type GroupHandler struct {
	config *config.Config
}

func NewGroupHandler(cfg *config.Config) *GroupHandler {
	return &GroupHandler{config: cfg}
}

type CreateGroupRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

type UpdateGroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type AssignUsersRequest struct {
	UserIDs []uint `json:"user_ids" binding:"required"`
}

type AssignPoliciesRequest struct {
	PolicyIDs []uint `json:"policy_ids" binding:"required"`
}

// ListGroups 获取所有用户组
func (h *GroupHandler) ListGroups(c *gin.Context) {
	var groups []models.UserGroup
	if err := database.DB.Preload("Users").Preload("Policies").Find(&groups).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, groups)
}

// GetGroup 获取单个用户组
func (h *GroupHandler) GetGroup(c *gin.Context) {
	id := c.Param("id")
	var group models.UserGroup
	if err := database.DB.Preload("Users").Preload("Policies").First(&group, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	c.JSON(http.StatusOK, group)
}

// CreateGroup 创建用户组
func (h *GroupHandler) CreateGroup(c *gin.Context) {
	var req CreateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	group := &models.UserGroup{
		Name:        req.Name,
		Description: req.Description,
	}

	if err := database.DB.Create(group).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	database.DB.Preload("Users").Preload("Policies").First(group, group.ID)
	c.JSON(http.StatusCreated, group)
}

// UpdateGroup 更新用户组
func (h *GroupHandler) UpdateGroup(c *gin.Context) {
	id := c.Param("id")
	var group models.UserGroup
	if err := database.DB.First(&group, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	var req UpdateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Name != "" {
		group.Name = req.Name
	}
	if req.Description != "" {
		group.Description = req.Description
	}

	if err := database.DB.Save(&group).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	database.DB.Preload("Users").Preload("Policies").First(&group, group.ID)
	c.JSON(http.StatusOK, group)
}

// DeleteGroup 删除用户组
func (h *GroupHandler) DeleteGroup(c *gin.Context) {
	id := c.Param("id")
	if err := database.DB.Delete(&models.UserGroup{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Group deleted"})
}

// AssignUsers 给用户组分配用户
func (h *GroupHandler) AssignUsers(c *gin.Context) {
	id := c.Param("id")
	var group models.UserGroup
	if err := database.DB.First(&group, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	var req AssignUsersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var users []models.User
	if err := database.DB.Find(&users, req.UserIDs).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Some users not found"})
		return
	}

	// 更新关联关系
	if err := database.DB.Model(&group).Association("Users").Replace(users); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 重新加载组以获取策略
	database.DB.Preload("Policies").First(&group, group.ID)

	// 注意：不再直接更新用户的 PolicyID，策略通过用户组动态获取

	database.DB.Preload("Users").Preload("Policies").First(&group, group.ID)
	c.JSON(http.StatusOK, group)
}

// AssignPolicies 给用户组分配策略
func (h *GroupHandler) AssignPolicies(c *gin.Context) {
	id := c.Param("id")
	var group models.UserGroup
	if err := database.DB.First(&group, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	var req AssignPoliciesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var policies []models.Policy
	if err := database.DB.Find(&policies, req.PolicyIDs).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Some policies not found"})
		return
	}

	// 更新关联关系
	if err := database.DB.Model(&group).Association("Policies").Replace(policies); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 注意：不再直接更新用户的 PolicyID，策略通过用户组动态获取

	database.DB.Preload("Users").Preload("Policies").First(&group, group.ID)
	c.JSON(http.StatusOK, group)
}

// GetGroupUsers 获取用户组的用户列表
func (h *GroupHandler) GetGroupUsers(c *gin.Context) {
	id := c.Param("id")
	var group models.UserGroup
	if err := database.DB.First(&group, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	var users []models.User
	database.DB.Model(&group).Association("Users").Find(&users)

	// Clear password hashes
	for i := range users {
		users[i].PasswordHash = ""
	}

	c.JSON(http.StatusOK, users)
}

// GetGroupPolicies 获取用户组的策略列表
func (h *GroupHandler) GetGroupPolicies(c *gin.Context) {
	id := c.Param("id")
	var group models.UserGroup
	if err := database.DB.First(&group, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	var policies []models.Policy
	database.DB.Model(&group).Association("Policies").Find(&policies)

	c.JSON(http.StatusOK, policies)
}

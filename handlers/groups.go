package handlers

import (
	"fmt"
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
	AllowLan    *bool  `json:"allow_lan"` // 允许本地网络访问（类似  的 allow_lan 配置）
}

type UpdateGroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	AllowLan    *bool  `json:"allow_lan"` // 允许本地网络访问（类似  的 allow_lan 配置）
}

type AssignUsersRequest struct {
	UserIDs []uint `json:"user_ids" binding:"required"`
}

type AssignPoliciesRequest struct {
	PolicyIDs []uint `json:"policy_ids" binding:"required"`
}

func (h *GroupHandler) ListGroups(c *gin.Context) {
	var groups []models.UserGroup
	if err := database.DB.Preload("Users").Preload("Policies").Find(&groups).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, groups)
}

func (h *GroupHandler) GetGroup(c *gin.Context) {
	id := c.Param("id")
	var group models.UserGroup
	if err := database.DB.Preload("Users").Preload("Policies").First(&group, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	c.JSON(http.StatusOK, group)
}

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
	if req.AllowLan != nil {
		group.AllowLan = *req.AllowLan
	}

	if err := database.DB.Create(group).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	database.DB.Preload("Users").Preload("Policies").First(group, group.ID)
	c.JSON(http.StatusCreated, group)
}

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
	if req.AllowLan != nil {
		group.AllowLan = *req.AllowLan
	}

	if err := database.DB.Save(&group).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	database.DB.Preload("Users").Preload("Policies").First(&group, group.ID)
	c.JSON(http.StatusOK, group)
}

func (h *GroupHandler) DeleteGroup(c *gin.Context) {
	id := c.Param("id")
	
	var group models.UserGroup
	if err := database.DB.First(&group, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	tx := database.DB.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	if err := tx.Model(&group).Association("Users").Clear(); err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to remove users from group: %v", err)})
		return
	}

	if err := tx.Model(&group).Association("Policies").Clear(); err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to remove policies from group: %v", err)})
		return
	}

	if err := tx.Unscoped().Delete(&group).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete group: %v", err)})
		return
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to commit transaction: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Group deleted successfully"})
}

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

	if err := database.DB.Model(&group).Association("Users").Replace(users); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	database.DB.Preload("Policies").First(&group, group.ID)


	database.DB.Preload("Users").Preload("Policies").First(&group, group.ID)
	c.JSON(http.StatusOK, group)
}

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

	if err := database.DB.Model(&group).Association("Policies").Replace(policies); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}


	database.DB.Preload("Users").Preload("Policies").First(&group, group.ID)
	c.JSON(http.StatusOK, group)
}

func (h *GroupHandler) GetGroupUsers(c *gin.Context) {
	id := c.Param("id")
	var group models.UserGroup
	if err := database.DB.First(&group, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	var users []models.User
	database.DB.Model(&group).Association("Users").Find(&users)

	for i := range users {
		users[i].PasswordHash = ""
	}

	c.JSON(http.StatusOK, users)
}

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

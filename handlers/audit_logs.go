package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/gin-gonic/gin"
)

type AuditLogHandler struct{}

func NewAuditLogHandler() *AuditLogHandler {
	return &AuditLogHandler{}
}

// ListAuditLogs 获取审计日志列表
func (h *AuditLogHandler) ListAuditLogs(c *gin.Context) {
	var logs []models.AuditLog
	query := database.DB.Model(&models.AuditLog{})

	// 查询参数
	userID := c.Query("user_id")
	username := c.Query("username")
	logType := c.Query("type")
	action := c.Query("action")
	sourceIP := c.Query("source_ip")
	destinationIP := c.Query("destination_ip")
	startTime := c.Query("start_time")
	endTime := c.Query("end_time")
	result := c.Query("result")

	// 应用过滤条件
	if userID != "" {
		if id, err := strconv.ParseUint(userID, 10, 32); err == nil {
			query = query.Where("user_id = ?", uint(id))
		}
	}
	if username != "" {
		query = query.Where("username LIKE ?", "%"+username+"%")
	}
	if logType != "" {
		query = query.Where("type = ?", logType)
	}
	if action != "" {
		query = query.Where("action = ?", action)
	}
	if sourceIP != "" {
		query = query.Where("source_ip = ?", sourceIP)
	}
	if destinationIP != "" {
		query = query.Where("destination_ip = ?", destinationIP)
	}
	if result != "" {
		query = query.Where("result = ?", result)
	}
	if startTime != "" {
		if t, err := time.Parse("2006-01-02T15:04:05Z07:00", startTime); err == nil {
			query = query.Where("created_at >= ?", t)
		}
	}
	if endTime != "" {
		if t, err := time.Parse("2006-01-02T15:04:05Z07:00", endTime); err == nil {
			query = query.Where("created_at <= ?", t)
		}
	}

	// 默认排除系统自动生成的日志，只审计用户的实际操作
	// 1. 排除DNS解析记录（DNS解析太频繁）
	//    DNS解析记录的特征：protocol = 'dns' 或 resource_type = 'dns_query'
	// 2. 排除eBPF自动允许的事件（系统级别的网络包处理，太频繁）
	//    eBPF事件的特征：hook_id LIKE 'ebpf-policy-%' 且 result = 'allowed'
	//    但保留eBPF拒绝的事件（blocked），因为这是重要的安全事件
	//    注意：认证类型的日志（如登录、断开连接）不应该被过滤，所以只对access类型应用eBPF过滤
	query = query.Where("NOT (protocol = ? OR resource_type = ?)", "dns", "dns_query").
		Where("(type != ? OR NOT (COALESCE(hook_id, '') LIKE ? AND result = ?))", 
			models.AuditLogTypeAccess, "ebpf-policy-%", "allowed")

	// 分页
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 50
	}

	offset := (page - 1) * pageSize

	// 获取总数
	var total int64
	query.Count(&total)

	// 获取数据
	if err := query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&logs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":        logs,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
	})
}

// GetAuditLog 获取审计日志详情
func (h *AuditLogHandler) GetAuditLog(c *gin.Context) {
	id := c.Param("id")

	var log models.AuditLog
	if err := database.DB.First(&log, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Audit log not found"})
		return
	}

	c.JSON(http.StatusOK, log)
}

// GetAuditLogStats 获取审计日志统计
func (h *AuditLogHandler) GetAuditLogStats(c *gin.Context) {
	startTime := c.Query("start_time")
	endTime := c.Query("end_time")

	query := database.DB.Model(&models.AuditLog{})

	if startTime != "" {
		if t, err := time.Parse("2006-01-02T15:04:05Z07:00", startTime); err == nil {
			query = query.Where("created_at >= ?", t)
		}
	}
	if endTime != "" {
		if t, err := time.Parse("2006-01-02T15:04:05Z07:00", endTime); err == nil {
			query = query.Where("created_at <= ?", t)
		}
	}

	// 默认排除系统自动生成的日志，只审计用户的实际操作
	// 1. 排除DNS解析记录（DNS解析太频繁）
	// 2. 排除eBPF自动允许的事件（系统级别的网络包处理，太频繁）
	//    但保留eBPF拒绝的事件（blocked），因为这是重要的安全事件
	//    注意：认证类型的日志（如登录、断开连接）不应该被过滤，所以只对access类型应用eBPF过滤
	query = query.Where("NOT (protocol = ? OR resource_type = ?)", "dns", "dns_query").
		Where("(type != ? OR NOT (COALESCE(hook_id, '') LIKE ? AND result = ?))", 
			models.AuditLogTypeAccess, "ebpf-policy-%", "allowed")

	var stats struct {
		TotalLogs     int64            `json:"total_logs"`
		TotalAccess   int64            `json:"total_access"`
		TotalBlocked  int64            `json:"total_blocked"`
		TotalAllowed  int64            `json:"total_allowed"`
		TotalByType   map[string]int64 `json:"total_by_type"`
		TotalByAction map[string]int64 `json:"total_by_action"`
		TopUsers      []struct {
			UserID   uint   `json:"user_id"`
			Username string `json:"username"`
			Count    int64  `json:"count"`
		} `json:"top_users"`
		TopDestinations []struct {
			DestinationIP string `json:"destination_ip"`
			Count         int64  `json:"count"`
		} `json:"top_destinations"`
	}

	// 总数
	query.Count(&stats.TotalLogs)

	// 按类型统计
	stats.TotalByType = make(map[string]int64)
	var typeStats []struct {
		Type  string
		Count int64
	}
	query.Select("type, COUNT(*) as count").Group("type").Scan(&typeStats)
	for _, ts := range typeStats {
		stats.TotalByType[ts.Type] = ts.Count
	}

	// 按动作统计
	stats.TotalByAction = make(map[string]int64)
	var actionStats []struct {
		Action string
		Count  int64
	}
	query.Select("action, COUNT(*) as count").Group("action").Scan(&actionStats)
	for _, as := range actionStats {
		stats.TotalByAction[as.Action] = as.Count
	}

	// 访问统计（使用已过滤的query，已排除DNS记录）
	query.Where("type = ?", models.AuditLogTypeAccess).Count(&stats.TotalAccess)
	query.Where("result = ?", "blocked").Count(&stats.TotalBlocked)
	query.Where("result = ?", "allowed").Count(&stats.TotalAllowed)

	// Top users
	var topUsers []struct {
		UserID   uint   `json:"user_id"`
		Username string `json:"username"`
		Count    int64  `json:"count"`
	}
	query.Select("user_id, username, COUNT(*) as count").
		Where("user_id > 0").
		Group("user_id, username").
		Order("count DESC").
		Limit(10).
		Scan(&topUsers)
	stats.TopUsers = topUsers

	// Top destinations
	var topDests []struct {
		DestinationIP string `json:"destination_ip"`
		Count         int64  `json:"count"`
	}
	query.Select("destination_ip, COUNT(*) as count").
		Where("destination_ip != ''").
		Group("destination_ip").
		Order("count DESC").
		Limit(10).
		Scan(&topDests)
	stats.TopDestinations = topDests

	c.JSON(http.StatusOK, stats)
}

// DeleteAuditLogs 删除审计日志（按条件）
func (h *AuditLogHandler) DeleteAuditLogs(c *gin.Context) {
	var req struct {
		BeforeDate string `json:"before_date"` // 删除此日期之前的日志
		Type       string `json:"type"`        // 只删除指定类型的日志
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := database.DB.Model(&models.AuditLog{})

	if req.BeforeDate != "" {
		if t, err := time.Parse("2006-01-02", req.BeforeDate); err == nil {
			query = query.Where("created_at < ?", t)
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid date format"})
			return
		}
	}

	if req.Type != "" {
		query = query.Where("type = ?", req.Type)
	}

	var count int64
	if err := query.Count(&count).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := query.Delete(&models.AuditLog{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Audit logs deleted",
		"count":   count,
	})
}

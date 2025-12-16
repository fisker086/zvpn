package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/vpn"
	"github.com/gin-gonic/gin"
)

type DomainHandler struct {
	config    *config.Config
	vpnServer *vpn.VPNServer
}

func NewDomainHandler(cfg *config.Config) *DomainHandler {
	return &DomainHandler{config: cfg}
}

// SetVPNServer sets the VPN server instance
func (h *DomainHandler) SetVPNServer(server *vpn.VPNServer) {
	h.vpnServer = server
}

type CreateDomainRequest struct {
	Domain      string   `json:"domain" binding:"required"`
	PolicyID    *uint    `json:"policy_id"`
	AutoResolve bool     `json:"auto_resolve"`
	ManualIPs   []string `json:"manual_ips"` // 手动配置的IP地址列表（用于内网域名等场景）
}

// DomainResponse 用于API响应的Domain结构，IPs字段为数组
type DomainResponse struct {
	ID          uint       `json:"id"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Domain      string     `json:"domain"`
	PolicyID    *uint      `json:"policy_id"`
	PolicyName  *string    `json:"policy_name,omitempty"`
	AutoResolve bool       `json:"auto_resolve"`
	Resolved    bool       `json:"resolved"`
	ResolvedAt  *time.Time `json:"resolved_at"`
	IPs         []string   `json:"ips"`        // 合并后的所有IP（手动IP + 自动解析IP）
	ManualIPs   []string   `json:"manual_ips"` // 手动配置的IP
	Routes      []struct {
		CIDR    string `json:"cidr"`
		Gateway string `json:"gateway,omitempty"`
	} `json:"routes,omitempty"`
	AccessCount uint64     `json:"access_count"`
	LastUsed    *time.Time `json:"last_used"`
}

// convertDomainToResponse 将数据库Domain转换为API响应格式
func convertDomainToResponse(domain models.Domain) DomainResponse {
	// 合并手动配置的IP和自动解析的IP
	var allIPs []string
	manualIPs := make([]string, 0) // 初始化为空数组，确保JSON序列化为 [] 而不是 null

	// 先添加手动配置的IP（优先级更高）
	if domain.ManualIPs != "" {
		if err := json.Unmarshal([]byte(domain.ManualIPs), &manualIPs); err == nil {
			allIPs = append(allIPs, manualIPs...)
		}
	}

	// 再添加自动解析的IP
	if domain.IPs != "" {
		var autoIPs []string
		if err := json.Unmarshal([]byte(domain.IPs), &autoIPs); err == nil {
			allIPs = append(allIPs, autoIPs...)
		}
	}

	var policyName *string
	if domain.Policy != nil {
		policyName = &domain.Policy.Name
	}

	// 构建路由信息（从所有IP生成）
	var routes []struct {
		CIDR    string `json:"cidr"`
		Gateway string `json:"gateway,omitempty"`
	}
	for _, ip := range allIPs {
		routes = append(routes, struct {
			CIDR    string `json:"cidr"`
			Gateway string `json:"gateway,omitempty"`
		}{
			CIDR: ip + "/32",
		})
	}

	return DomainResponse{
		ID:          domain.ID,
		CreatedAt:   domain.CreatedAt,
		UpdatedAt:   domain.UpdatedAt,
		Domain:      domain.Domain,
		PolicyID:    domain.PolicyID,
		PolicyName:  policyName,
		AutoResolve: domain.AutoResolve,
		Resolved:    domain.Resolved,
		ResolvedAt:  domain.ResolvedAt,
		IPs:         allIPs,    // 返回合并后的IP列表
		ManualIPs:   manualIPs, // 返回手动配置的IP列表
		Routes:      routes,
		AccessCount: domain.AccessCount,
		LastUsed:    domain.LastUsed,
	}
}

// ListDomains 获取域名列表（支持分页）
func (h *DomainHandler) ListDomains(c *gin.Context) {
	// 分页参数
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "10"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	offset := (page - 1) * pageSize

	// 构建查询
	query := database.DB.Model(&models.Domain{})

	// 获取总数
	var total int64
	query.Count(&total)

	// 获取数据
	var domains []models.Domain
	if err := query.Preload("Policy").Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&domains).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 转换为响应格式
	responses := make([]DomainResponse, len(domains))
	for i, domain := range domains {
		responses[i] = convertDomainToResponse(domain)
	}

	c.JSON(http.StatusOK, gin.H{
		"domains":     responses,
		"total":       total,
		"page":        page,
		"page_size":   pageSize,
		"total_pages": (total + int64(pageSize) - 1) / int64(pageSize),
	})
}

// CreateDomain 创建域名
func (h *DomainHandler) CreateDomain(c *gin.Context) {
	var req CreateDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证策略是否存在（如果提供了）
	if req.PolicyID != nil {
		var policy models.Policy
		if err := database.DB.First(&policy, *req.PolicyID).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "策略不存在"})
			return
		}
	}

	// 检查域名是否已存在（包括软删除的记录）
	var existingDomain models.Domain
	// 先检查未删除的记录
	if err := database.DB.Where("domain = ?", req.Domain).First(&existingDomain).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "域名已存在"})
		return
	}
	// 再检查软删除的记录（使用 Unscoped 查询）
	var deletedDomain models.Domain
	if err := database.DB.Unscoped().Where("domain = ?", req.Domain).First(&deletedDomain).Error; err == nil {
		// 找到软删除的记录，恢复它并更新信息
		// 先清除 DeletedAt 字段以恢复记录
		if err := database.DB.Unscoped().Model(&deletedDomain).Update("deleted_at", nil).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "恢复域名失败: " + err.Error()})
			return
		}
		// 更新其他字段
		deletedDomain.PolicyID = req.PolicyID
		deletedDomain.AutoResolve = req.AutoResolve
		if len(req.ManualIPs) > 0 {
			ipsBytes, _ := json.Marshal(req.ManualIPs)
			deletedDomain.ManualIPs = string(ipsBytes)
			deletedDomain.Resolved = true
		} else {
			deletedDomain.ManualIPs = ""
			deletedDomain.Resolved = false
		}
		if err := database.DB.Save(&deletedDomain).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新域名失败: " + err.Error()})
			return
		}
		// 恢复后继续处理路由等逻辑
		domain := &deletedDomain
		// 如果配置了手动IP，立即添加路由
		if len(req.ManualIPs) > 0 {
			now := time.Now()
			domain.ResolvedAt = &now
			database.DB.Save(domain)
			if h.vpnServer != nil {
				go h.addDomainRoutes(domain, req.ManualIPs)
			}
		} else if req.AutoResolve {
			go h.resolveDomain(domain.ID)
		}
		// 预加载策略
		database.DB.Preload("Policy").First(domain, domain.ID)
		c.JSON(http.StatusOK, gin.H{
			"message": "域名已恢复（之前被删除）",
			"domain":  convertDomainToResponse(*domain),
		})
		return
	}

	// 处理手动配置的IP
	var manualIPsJSON string
	if len(req.ManualIPs) > 0 {
		// 验证IP地址格式
		for _, ipStr := range req.ManualIPs {
			if net.ParseIP(ipStr) == nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("无效的IP地址: %s", ipStr)})
				return
			}
		}
		ipsBytes, _ := json.Marshal(req.ManualIPs)
		manualIPsJSON = string(ipsBytes)
	}

	domain := &models.Domain{
		Domain:      req.Domain,
		PolicyID:    req.PolicyID,
		AutoResolve: req.AutoResolve,
		ManualIPs:   manualIPsJSON,
		Resolved:    len(req.ManualIPs) > 0, // 如果配置了手动IP，标记为已解析
	}

	if err := database.DB.Create(domain).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 如果配置了手动IP，立即添加路由
	if len(req.ManualIPs) > 0 {
		now := time.Now()
		domain.ResolvedAt = &now
		// 保存解析时间
		database.DB.Save(domain)
		// 添加路由
		if h.vpnServer != nil {
			go h.addDomainRoutes(domain, req.ManualIPs)
		}
	} else if req.AutoResolve {
		// 如果启用自动解析且没有手动IP，立即解析
		go h.resolveDomain(domain.ID)
	}

	// 预加载策略
	database.DB.Preload("Policy").First(domain, domain.ID)

	c.JSON(http.StatusCreated, convertDomainToResponse(*domain))
}

// ResolveDomain 解析域名
func (h *DomainHandler) ResolveDomain(c *gin.Context) {
	id := c.Param("id")
	var domain models.Domain
	if err := database.DB.First(&domain, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "域名不存在"})
		return
	}

	// 解析域名
	ips, err := h.resolveDomain(domain.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "域名解析失败: " + err.Error()})
		return
	}

	// 重新加载域名
	database.DB.Preload("Policy").First(&domain, domain.ID)

	c.JSON(http.StatusOK, gin.H{
		"message": "域名解析成功",
		"domain":  convertDomainToResponse(domain),
		"ips":     ips,
	})
}

// resolveDomain 内部方法：解析域名并添加路由
func (h *DomainHandler) resolveDomain(domainID uint) ([]string, error) {
	var domain models.Domain
	if err := database.DB.Preload("Policy").First(&domain, domainID).Error; err != nil {
		return nil, err
	}

	// 使用DNS拦截器解析域名（DNS拦截器始终启用）
	var ips []string
	if h.vpnServer == nil || h.vpnServer.GetDNSInterceptor() == nil {
		return nil, fmt.Errorf("DNS拦截器不可用")
	}

	ipAddrs, err := h.vpnServer.GetDNSInterceptor().ResolveDomain(domain.Domain)
	if err != nil {
		return nil, fmt.Errorf("域名解析失败: %w", err)
	}
	for _, ip := range ipAddrs {
		ips = append(ips, ip.String())
	}

	// 更新域名解析结果
	ipsJSON, _ := json.Marshal(ips)
	now := time.Now()
	domain.IPs = string(ipsJSON)
	domain.Resolved = len(ips) > 0
	if len(ips) > 0 {
		domain.ResolvedAt = &now
	}

	if err := database.DB.Save(&domain).Error; err != nil {
		return nil, err
	}

	// 如果解析成功，添加路由到内核路由表（用于域名动态拆分隧道）
	if len(ips) > 0 && h.vpnServer != nil {
		h.addDomainRoutes(&domain, ips)
	}

	return ips, nil
}

// addDomainRoutes 将域名解析的IP添加到内核路由表
func (h *DomainHandler) addDomainRoutes(domain *models.Domain, ips []string) {
	if h.vpnServer == nil {
		return
	}

	// 解析VPN网络用于检查IP是否在VPN网络中
	_, vpnNet, err := net.ParseCIDR(h.config.VPN.Network)
	if err != nil {
		return
	}

	// 获取VPN网关IP（优先使用TUN设备IP，支持多服务器横向扩容）
	gateway := h.vpnServer.GetVPNGatewayIP()
	if gateway == nil {
		// Fallback to configured gateway IP
		gateway = make(net.IP, len(vpnNet.IP))
		copy(gateway, vpnNet.IP)
		gateway[len(gateway)-1] = 1
	}

	// 获取路由管理器
	routeMgr := h.vpnServer.GetRouteManager()
	if routeMgr == nil {
		return
	}

	// 为每个解析的IP添加路由（支持 IPv4 和 IPv6）
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue // 跳过无效IP
		}

		// 检查IP是否在VPN网络中，如果是则跳过
		if vpnNet.Contains(ip) {
			continue
		}

		// 创建/32路由
		_, ipNet, err := net.ParseCIDR(ipStr + "/32")
		if err != nil {
			continue
		}

		// 添加路由到内核路由表（通过netlink）
		if err := routeMgr.AddRoute(ipNet, gateway, 100); err != nil {
			// 路由可能已存在，这是正常的，但记录日志以便调试
			log.Printf("Domain %s: Route for %s/32 via %s: %v (may already exist)",
				domain.Domain, ipStr, gateway.String(), err)
		} else {
			log.Printf("Domain %s: Added route for %s/32 via %s", domain.Domain, ipStr, gateway.String())
		}

		// 如果域名关联了策略，也可以通过eBPF添加策略规则
		if domain.PolicyID != nil && h.vpnServer.GetEBPFProgram() != nil {
			// 这里可以添加eBPF策略规则，例如允许该IP的流量
			// 注意：eBPF策略需要更复杂的配置，这里只是示例
			log.Printf("Domain %s: Policy %d associated, eBPF rules can be applied for %s",
				domain.Domain, *domain.PolicyID, ipStr)
		}
	}
}

// UpdateDomain 更新域名
func (h *DomainHandler) UpdateDomain(c *gin.Context) {
	id := c.Param("id")
	var req CreateDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 查找域名
	var domain models.Domain
	if err := database.DB.First(&domain, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "域名不存在"})
		return
	}

	// 验证策略是否存在（如果提供了）
	if req.PolicyID != nil {
		var policy models.Policy
		if err := database.DB.First(&policy, *req.PolicyID).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "策略不存在"})
			return
		}
	}

	// 如果域名改变了，检查新域名是否已存在
	if req.Domain != domain.Domain {
		var existingDomain models.Domain
		if err := database.DB.Where("domain = ?", req.Domain).First(&existingDomain).Error; err == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "域名已存在"})
			return
		}
		// 检查软删除的记录
		var deletedDomain models.Domain
		if err := database.DB.Unscoped().Where("domain = ?", req.Domain).First(&deletedDomain).Error; err == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "域名已存在（之前被删除）"})
			return
		}
	}

	// 处理手动配置的IP
	var manualIPsJSON string
	if len(req.ManualIPs) > 0 {
		// 验证IP地址格式
		for _, ipStr := range req.ManualIPs {
			if net.ParseIP(ipStr) == nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("无效的IP地址: %s", ipStr)})
				return
			}
		}
		ipsBytes, _ := json.Marshal(req.ManualIPs)
		manualIPsJSON = string(ipsBytes)
	} else {
		manualIPsJSON = ""
	}

	// 更新域名信息
	domain.Domain = req.Domain
	domain.PolicyID = req.PolicyID
	domain.AutoResolve = req.AutoResolve
	domain.ManualIPs = manualIPsJSON

	// 如果配置了手动IP，标记为已解析
	if len(req.ManualIPs) > 0 {
		domain.Resolved = true
		now := time.Now()
		domain.ResolvedAt = &now
	} else if !req.AutoResolve {
		// 如果禁用了自动解析且没有手动IP，清除解析状态
		domain.Resolved = false
		domain.ResolvedAt = nil
		domain.IPs = ""
	}

	if err := database.DB.Save(&domain).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 如果配置了手动IP，立即添加路由
	if len(req.ManualIPs) > 0 {
		if h.vpnServer != nil {
			go h.addDomainRoutes(&domain, req.ManualIPs)
		}
	} else if req.AutoResolve {
		// 如果启用自动解析且没有手动IP，立即解析
		go h.resolveDomain(domain.ID)
	}

	// 预加载策略
	database.DB.Preload("Policy").First(&domain, domain.ID)

	c.JSON(http.StatusOK, convertDomainToResponse(domain))
}

// DeleteDomain 删除域名
func (h *DomainHandler) DeleteDomain(c *gin.Context) {
	id := c.Param("id")
	if err := database.DB.Delete(&models.Domain{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "域名删除成功"})
}

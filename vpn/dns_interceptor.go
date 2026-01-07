package vpn

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/vpn/policy"
	"github.com/miekg/dns"
)

// DNSInterceptor 拦截DNS查询并记录，用于域名动态拆分隧道
type DNSInterceptor struct {
	server      *VPNServer
	dnsServer   *dns.Server
	domainCache map[string]*DomainInfo // 域名到IP的缓存
	cacheLock   sync.RWMutex
	auditLogger *policy.AuditLogger
	upstreamDNS []string // 上游DNS服务器列表（从配置读取）
}

// DomainInfo 存储域名解析信息
type DomainInfo struct {
	Domain      string
	IPs         []net.IP
	ResolvedAt  time.Time
	LastUsed    time.Time
	AccessCount uint64
}

// NewDNSInterceptor 创建DNS拦截器
func NewDNSInterceptor(server *VPNServer) *DNSInterceptor {
	interceptor := &DNSInterceptor{
		server:      server,
		domainCache: make(map[string]*DomainInfo),
		auditLogger: policy.GetAuditLogger(),
	}
	// 从配置中获取上游DNS服务器列表
	interceptor.upstreamDNS = interceptor.getUpstreamDNS()
	return interceptor
}

// getUpstreamDNS 从配置中获取上游DNS服务器列表
func (di *DNSInterceptor) getUpstreamDNS() []string {
	if di.server == nil {
		// 默认使用国内DNS
		return []string{"114.114.114.114:53"}
	}

	cfg := di.server.GetConfig()
	if cfg == nil || cfg.VPN.UpstreamDNS == "" {
		// 默认使用国内DNS
		return []string{"114.114.114.114:53"}
	}

	// 解析逗号分隔的DNS服务器列表
	dnsList := strings.Split(cfg.VPN.UpstreamDNS, ",")
	var upstreamDNS []string
	for _, dns := range dnsList {
		dns = strings.TrimSpace(dns)
		if dns == "" {
			continue
		}
		// 确保包含端口号
		if !strings.Contains(dns, ":") {
			dns += ":53"
		}
		upstreamDNS = append(upstreamDNS, dns)
	}

	if len(upstreamDNS) == 0 {
		// 如果解析后为空，使用默认值
		return []string{"114.114.114.114:53"}
	}

	return upstreamDNS
}

// Start 启动DNS拦截器（监听UDP 53端口）
func (di *DNSInterceptor) Start() error {
	// DNS端口固定为53，上游DNS从配置文件读取（vpn.upstreamdns）
	const dnsPort = "53"

	// 尝试绑定端口以检查权限
	addr := ":" + dnsPort
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind DNS port %s (requires root privileges): %w", dnsPort, err)
	}
	conn.Close()

	// 创建DNS服务器
	di.dnsServer = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: dns.HandlerFunc(di.handleDNS),
	}

	// 启动DNS服务器（在goroutine中）
	go func() {
		log.Printf("DNS Interceptor: Starting DNS server on %s", addr)
		if err := di.dnsServer.ListenAndServe(); err != nil {
			log.Printf("DNS Interceptor: Failed to start DNS server: %v", err)
		}
	}()

	// 启动缓存清理goroutine
	go di.cleanupCache()

	log.Printf("DNS Interceptor: Started successfully on %s", addr)
	return nil
}

// Stop 停止DNS拦截器
func (di *DNSInterceptor) Stop() error {
	if di.dnsServer != nil {
		return di.dnsServer.Shutdown()
	}
	return nil
}

// handleDNS 处理DNS查询
func (di *DNSInterceptor) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	// 记录DNS查询
	domain := ""
	if len(r.Question) > 0 {
		domain = r.Question[0].Name
		// 移除末尾的点
		if len(domain) > 0 && domain[len(domain)-1] == '.' {
			domain = domain[:len(domain)-1]
		}
	}

	// 记录DNS查询审计日志
	di.logDNSQuery(r, domain, w.RemoteAddr())

	// 先检查域名是否在域名管理列表中（支持通配符匹配）
	var domainModel models.Domain
	foundInDomainList := false
	matchedDomain := di.findMatchingDomain(domain)
	if matchedDomain != nil {
		domainModel = *matchedDomain
		foundInDomainList = true

		// 如果配置了手动IP，直接返回手动IP（类似hosts文件）
		if domainModel.ManualIPs != "" {
			var manualIPs []string
			if err := json.Unmarshal([]byte(domainModel.ManualIPs), &manualIPs); err == nil && len(manualIPs) > 0 {
				// 构建DNS响应，返回手动配置的IP
				resp := new(dns.Msg)
				resp.SetReply(r)
				resp.RecursionAvailable = true

				// 添加A记录（IPv4）和AAAA记录（IPv6）
				var resolvedIPs []net.IP
				for _, ipStr := range manualIPs {
					ip := net.ParseIP(ipStr)
					if ip == nil {
						continue
					}

					if ip.To4() != nil {
						// IPv4 A记录
						resp.Answer = append(resp.Answer, &dns.A{
							Hdr: dns.RR_Header{
								Name:   r.Question[0].Name,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							A: ip,
						})
						resolvedIPs = append(resolvedIPs, ip)
					} else {
						// IPv6 AAAA记录
						resp.Answer = append(resp.Answer, &dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   r.Question[0].Name,
								Rrtype: dns.TypeAAAA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							AAAA: ip,
						})
						resolvedIPs = append(resolvedIPs, ip)
					}
				}

				// 如果没有有效的IP记录，返回NXDOMAIN，但仍更新访问统计
				if len(resp.Answer) == 0 {
					log.Printf("DNS Interceptor: Domain %s has manual IPs but none are valid", domain)
					// 更新访问统计
					now := time.Now()
					domainModel.LastUsed = &now
					domainModel.AccessCount++
					database.DB.Save(&domainModel)
					m := new(dns.Msg)
					m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
					w.WriteMsg(m)
					return
				}

				// 添加路由（让流量走VPN，只处理IPv4）
				var ipv4IPs []net.IP
				for _, ip := range resolvedIPs {
					if ip.To4() != nil {
						ipv4IPs = append(ipv4IPs, ip)
					}
				}
				if len(ipv4IPs) > 0 {
					// 添加路由，但不更新IP列表（因为这是手动IP）
					di.addRoutesForDomain(domain, ipv4IPs, &domainModel, true)
				}
				// 无论是否有IPv4地址，都更新访问统计
				now := time.Now()
				domainModel.LastUsed = &now
				domainModel.AccessCount++
				database.DB.Save(&domainModel)

				log.Printf("DNS Interceptor: Domain %s found in domain list, returning manual IPs: %v", domain, manualIPs)
				w.WriteMsg(resp)
				return
			}
		}
	}

	// 从配置中获取上游DNS服务器列表
	upstreamDNS := di.getUpstreamDNS()

	var resp *dns.Msg
	var err error
	var lastErr error

	// 尝试使用上游DNS解析（增加超时时间，添加重试）
	for _, dnsServer := range upstreamDNS {
		client := &dns.Client{Timeout: 10 * time.Second} // 增加超时时间到10秒
		resp, _, err = client.Exchange(r, dnsServer)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			break
		}
		if err != nil {
			lastErr = err
			// 如果是超时错误，尝试下一个DNS服务器
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("DNS Interceptor: DNS server %s timeout for %s, trying next server", dnsServer, domain)
				continue
			}
		}
	}

	if err != nil || resp == nil || len(resp.Answer) == 0 {
		// 使用更详细的错误信息
		if lastErr != nil {
			log.Printf("DNS Interceptor: Failed to resolve %s: %v (tried %d DNS servers)", domain, lastErr, len(upstreamDNS))
		} else {
			log.Printf("DNS Interceptor: Failed to resolve %s: no answer from DNS servers", domain)
		}
		// 如果域名在域名管理列表中但解析失败，仍然更新访问统计
		if foundInDomainList {
			now := time.Now()
			domainModel.LastUsed = &now
			domainModel.AccessCount++
			database.DB.Save(&domainModel)
			log.Printf("DNS Interceptor: Updated access stats for domain %s (resolution failed)", domain)
		}
		// 返回错误
		if foundInDomainList {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
			w.WriteMsg(m)
			return
		}
		// 如果不在列表中，也返回错误
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	// 提取解析的IP地址
	var resolvedIPs []net.IP
	for _, answer := range resp.Answer {
		if a, ok := answer.(*dns.A); ok {
			resolvedIPs = append(resolvedIPs, a.A)
		} else if aaaa, ok := answer.(*dns.AAAA); ok {
			resolvedIPs = append(resolvedIPs, aaaa.AAAA)
		}
	}

	// 缓存域名解析结果
	if len(resolvedIPs) > 0 {
		di.cacheDomain(domain, resolvedIPs)

		// 如果域名在域名管理列表中，添加路由（让流量走VPN）
		if foundInDomainList {
			log.Printf("DNS Interceptor: Domain %s found in domain list, resolved to %v, adding routes",
				domain, resolvedIPs)
			// 使用checkDynamicRouting，它会更新统计信息
			di.checkDynamicRouting(domain, resolvedIPs)
		} else {
			log.Printf("DNS Interceptor: Domain %s resolved to %v, but not in domain list (no routes added)",
				domain, resolvedIPs)
		}
	} else {
		log.Printf("DNS Interceptor: Domain %s resolved to no IPs", domain)
	}

	// 返回响应
	w.WriteMsg(resp)
}

// logDNSQuery 记录DNS查询审计日志
func (di *DNSInterceptor) logDNSQuery(req *dns.Msg, domain string, clientAddr net.Addr) {
	if di.auditLogger == nil || !di.auditLogger.IsEnabled() {
		return
	}

	// 根据设置决定是否记录DNS查询日志
	// 使用 policy 包的函数检查DNS是否应该记录
	if !policy.ShouldLogProtocol("dns", 53) {
		return
	}

	// 尝试从客户端IP找到用户
	var userID uint
	var username string

	clientIP := ""
	if addr, ok := clientAddr.(*net.UDPAddr); ok {
		clientIP = addr.IP.String()
		// 查找VPN客户端
		if di.server != nil {
			// 通过VPN IP查找用户
			var users []models.User
			if err := database.DB.Where("vpn_ip = ?", clientIP).Find(&users).Error; err == nil && len(users) > 0 {
				userID = users[0].ID
				username = users[0].Username
			}
		}
	}

	// 创建DNS查询审计日志
	auditLog := models.AuditLog{
		UserID:       userID,
		Username:     username,
		Type:         models.AuditLogTypeAccess,
		Action:       models.AuditLogActionLog,
		SourceIP:     clientIP,
		Protocol:     "dns",
		ResourceType: "dns_query",
		ResourcePath: domain,
		Domain:       domain,
		Result:       "resolved",
		Reason:       fmt.Sprintf("DNS query for %s", domain),
	}

	di.auditLogger.WriteLogDirectly(auditLog)
}

// cacheDomain 缓存域名解析结果
func (di *DNSInterceptor) cacheDomain(domain string, ips []net.IP) {
	di.cacheLock.Lock()
	defer di.cacheLock.Unlock()

	di.domainCache[domain] = &DomainInfo{
		Domain:      domain,
		IPs:         ips,
		ResolvedAt:  time.Now(),
		LastUsed:    time.Now(),
		AccessCount: 1,
	}
}

// GetDomainIPs 获取域名的IP地址（从缓存）
func (di *DNSInterceptor) GetDomainIPs(domain string) []net.IP {
	di.cacheLock.RLock()
	defer di.cacheLock.RUnlock()

	if info, ok := di.domainCache[domain]; ok {
		info.LastUsed = time.Now()
		info.AccessCount++
		return info.IPs
	}
	return nil
}

// checkDynamicRouting 检查是否需要动态添加路由（域名拆分隧道）
// 会自动更新域名的访问统计和解析结果
func (di *DNSInterceptor) checkDynamicRouting(domain string, ips []net.IP) {
	matchedDomain := di.findMatchingDomain(domain)
	if matchedDomain == nil {
		return
	}
	di.addRoutesForDomain(domain, ips, matchedDomain, false)
}

// addRoutesForDomain 为域名添加路由（内部方法）
// skipStatsUpdate: 如果为true，跳过统计信息更新（用于手动IP场景，统计已在外部更新）
func (di *DNSInterceptor) addRoutesForDomain(domain string, ips []net.IP, domainModel *models.Domain, skipStatsUpdate bool) {
	if di.server == nil || di.server.routeMgr == nil {
		log.Printf("DNS Interceptor: Cannot add routes for %s - server or routeMgr is nil", domain)
		return
	}

	// 如果域名未启用自动解析且没有手动IP，不添加路由
	// 注意：如果配置了手动IP，即使AutoResolve为false，也应该添加路由
	if !domainModel.AutoResolve && domainModel.ManualIPs == "" {
		log.Printf("DNS Interceptor: Domain %s has AutoResolve=false and no ManualIPs, skipping route addition", domain)
		return
	}

	// 获取VPN网关IP（优先使用TUN设备IP，支持多服务器横向扩容）
	gateway := di.server.GetVPNGatewayIP()
	if gateway == nil {
		log.Printf("DNS Interceptor: Cannot get VPN gateway IP for domain %s", domain)
		return
	}

	// 为每个解析的IP添加路由（如果不在VPN网络中）
	addedCount := 0
	skippedCount := 0
	for _, ip := range ips {
		// Support both IPv4 and IPv6

		// 检查是否在VPN网络中
		if di.isInVPNNetwork(ip) {
			log.Printf("DNS Interceptor: IP %s is in VPN network, skipping route for domain %s", ip.String(), domain)
			skippedCount++
			continue // 跳过VPN网络内的IP
		}

		// 创建/32路由
		_, ipNet, err := net.ParseCIDR(ip.String() + "/32")
		if err != nil {
			log.Printf("DNS Interceptor: Failed to parse CIDR for %s: %v", ip.String(), err)
			continue
		}

		// 添加路由到内核路由表（通过netlink）
		if err := di.server.routeMgr.AddRoute(ipNet, gateway, 100); err != nil {
			// 路由可能已存在，这是正常的，但记录日志以便调试
			log.Printf("DNS Interceptor: Route for %s/32 via %s: %v (may already exist)",
				ip.String(), gateway.String(), err)
		} else {
			log.Printf("DNS Interceptor: Domain %s resolved to %s, added dynamic route via %s",
				domain, ip.String(), gateway.String())
			addedCount++
		}
	}

	if addedCount > 0 || skippedCount > 0 {
		log.Printf("DNS Interceptor: Domain %s routing summary - added: %d, skipped: %d, total IPs: %d",
			domain, addedCount, skippedCount, len(ips))
	}

	// 如果域名关联了策略，可以通过eBPF应用策略规则
	if domainModel.PolicyID != nil && di.server.GetEBPFProgram() != nil {
		// eBPF策略规则可以在这里添加
		// 例如：允许该IP的流量通过VPN
		log.Printf("DNS Interceptor: Domain %s (Policy %d) - eBPF rules can be applied for resolved IPs",
			domain, *domainModel.PolicyID)
	}

	// 更新域名的解析结果和访问统计（如果未跳过）
	if !skipStatsUpdate {
		now := time.Now()
		domainModel.LastUsed = &now
		domainModel.AccessCount++

		// 更新自动解析的IP列表（不覆盖手动IP）
		// 将net.IP转换为字符串数组
		var ipStrings []string
		for _, ip := range ips {
			ipStrings = append(ipStrings, ip.String())
		}
		ipsJSON, _ := json.Marshal(ipStrings)
		domainModel.IPs = string(ipsJSON)
		domainModel.Resolved = true
		domainModel.ResolvedAt = &now

		database.DB.Save(domainModel)
	}
}

// isInVPNNetwork 检查IP是否在VPN网络中
func (di *DNSInterceptor) isInVPNNetwork(ip net.IP) bool {
	if di.server == nil || di.server.config == nil {
		return false
	}

	_, vpnNet, err := net.ParseCIDR(di.server.config.VPN.Network)
	if err != nil {
		return false
	}

	return vpnNet.Contains(ip)
}

// findMatchingDomain 查找匹配的域名配置（支持通配符）
// 例如：查询 sub.example.com 可以匹配 *.example.com 或 sub.example.com
func (di *DNSInterceptor) findMatchingDomain(queryDomain string) *models.Domain {
	// 先尝试精确匹配
	var domain models.Domain
	if err := database.DB.Where("domain = ?", queryDomain).First(&domain).Error; err == nil {
		log.Printf("DNS Interceptor: Found exact match for domain %s (ID: %d)", queryDomain, domain.ID)
		return &domain
	}

	// 尝试通配符匹配：查找所有通配符域名，检查是否匹配
	var wildcardDomains []models.Domain
	if err := database.DB.Where("domain LIKE ?", "*%").Find(&wildcardDomains).Error; err == nil {
		for _, wildcardDomain := range wildcardDomains {
			if di.matchWildcardDomain(wildcardDomain.Domain, queryDomain) {
				log.Printf("DNS Interceptor: Found wildcard match for domain %s (pattern: %s, ID: %d)",
					queryDomain, wildcardDomain.Domain, wildcardDomain.ID)
				return &wildcardDomain
			}
		}
	}

	// 对于本地域名（.local），不记录日志以减少噪音
	if !strings.HasSuffix(strings.ToLower(queryDomain), ".local") {
		log.Printf("DNS Interceptor: No matching domain found for %s", queryDomain)
	}
	return nil
}

// matchWildcardDomain 检查查询域名是否匹配通配符域名
// 例如：*.example.com 匹配 sub.example.com, api.example.com 等
func (di *DNSInterceptor) matchWildcardDomain(wildcardPattern, queryDomain string) bool {
	// 移除通配符前缀
	if !strings.HasPrefix(wildcardPattern, "*.") {
		return false
	}

	// 获取通配符后的域名部分（例如：example.com）
	suffix := wildcardPattern[2:]

	// 检查查询域名是否以该后缀结尾
	if !strings.HasSuffix(queryDomain, suffix) {
		return false
	}

	// 确保不是完全匹配（通配符应该匹配子域名）
	if queryDomain == suffix {
		return false
	}

	// 确保匹配的是子域名（例如：sub.example.com 匹配 *.example.com）
	// 但不匹配 example.com 本身
	if len(queryDomain) > len(suffix) && queryDomain[len(queryDomain)-len(suffix)-1] == '.' {
		return true
	}

	return false
}

// cleanupCache 定期清理缓存
func (di *DNSInterceptor) cleanupCache() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		di.cacheLock.Lock()
		now := time.Now()
		for domain, info := range di.domainCache {
			// 删除超过1小时未使用的缓存
			if now.Sub(info.LastUsed) > 1*time.Hour {
				delete(di.domainCache, domain)
			}
		}
		di.cacheLock.Unlock()
	}
}

// ResolveDomain 解析域名（用于域名动态拆分隧道）
func (di *DNSInterceptor) ResolveDomain(domain string) ([]net.IP, error) {
	// 先检查缓存
	if ips := di.GetDomainIPs(domain); len(ips) > 0 {
		return ips, nil
	}

	// 从配置中获取上游DNS服务器列表
	upstreamDNS := di.getUpstreamDNS()

	// 执行DNS查询
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	client := &dns.Client{Timeout: 10 * time.Second} // 增加超时时间到10秒
	var resp *dns.Msg
	var err error
	var lastErr error

	// 尝试使用上游DNS解析（添加重试）
	for _, dnsServer := range upstreamDNS {
		resp, _, err = client.Exchange(m, dnsServer)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			break
		}
		if err != nil {
			lastErr = err
			// 如果是超时错误，尝试下一个DNS服务器
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("DNS Interceptor: DNS server %s timeout for %s, trying next server", dnsServer, domain)
				continue
			}
		}
	}

	if err != nil || resp == nil || len(resp.Answer) == 0 {
		// 使用更详细的错误信息
		if lastErr != nil {
			return nil, fmt.Errorf("failed to resolve domain %s: %v (tried %d DNS servers)", domain, lastErr, len(upstreamDNS))
		}
		return nil, fmt.Errorf("failed to resolve domain %s: no answer from DNS servers", domain)
	}

	var ips []net.IP
	for _, answer := range resp.Answer {
		if a, ok := answer.(*dns.A); ok {
			ips = append(ips, a.A)
		} else if aaaa, ok := answer.(*dns.AAAA); ok {
			ips = append(ips, aaaa.AAAA)
		}
	}

	// 缓存结果
	if len(ips) > 0 {
		di.cacheDomain(domain, ips)
	}

	return ips, nil
}

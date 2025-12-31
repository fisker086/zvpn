package routes

import (
	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/handlers"
	"github.com/fisker/zvpn/middleware"
	"github.com/fisker/zvpn/vpn"
	"github.com/gin-gonic/gin"
)

// RegisterAPIRoutes 注册所有 API 路由
func RegisterAPIRoutes(router *gin.Engine, cfg *config.Config, vpnServer *vpn.VPNServer) {
	// 初始化处理器
	authHandler := handlers.NewAuthHandler(cfg, vpnServer)
	userHandler := handlers.NewUserHandler(cfg)
	policyHandler := handlers.NewPolicyHandler(cfg)
	vpnHandler := handlers.NewVPNHandler(cfg)
	hookHandler := handlers.NewHookHandler(cfg)
	groupHandler := handlers.NewGroupHandler(cfg)
	ldapConfigHandler := handlers.NewLDAPConfigHandler()
	auditLogHandler := handlers.NewAuditLogHandler()
	settingsHandler := handlers.NewSettingsHandler(cfg)
	systemHandler := handlers.NewSystemHandler(cfg.VPN.EBPFInterfaceName)

	// 设置 VPN 服务器
	vpnHandler.SetVPNServer(vpnServer)
	hookHandler.SetVPNServer(vpnServer)
	settingsHandler.SetVPNServer(vpnServer)

	// API 版本组
	api := router.Group("/api/v1")

	// 注册公开路由
	registerPublicRoutes(api, authHandler, ldapConfigHandler)

	// 注册受保护路由
	registerProtectedRoutes(api, cfg, authHandler, vpnHandler, userHandler, policyHandler, hookHandler, groupHandler, ldapConfigHandler, auditLogHandler, settingsHandler, systemHandler)
}

// registerPublicRoutes 注册公开路由（无需认证）
func registerPublicRoutes(api *gin.RouterGroup, authHandler *handlers.AuthHandler, ldapConfigHandler *handlers.LDAPConfigHandler) {
	// 认证接口
	api.POST("/auth/login", authHandler.Login)

	// LDAP配置状态（公开接口，用于前端判断登录方式）
	api.GET("/ldap/status", ldapConfigHandler.GetLDAPStatus)

	// 健康检查接口（无需认证）
	// 支持 GET 和 HEAD 方法（Docker healthcheck 使用 HEAD）
	healthHandler := func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"service": "zvpn",
		})
	}
	api.GET("/health", healthHandler)
	api.HEAD("/health", healthHandler)
}

// registerProtectedRoutes 注册受保护路由（需要认证）
func registerProtectedRoutes(
	api *gin.RouterGroup,
	cfg *config.Config,
	authHandler *handlers.AuthHandler,
	vpnHandler *handlers.VPNHandler,
	userHandler *handlers.UserHandler,
	policyHandler *handlers.PolicyHandler,
	hookHandler *handlers.HookHandler,
	groupHandler *handlers.GroupHandler,
	ldapConfigHandler *handlers.LDAPConfigHandler,
	auditLogHandler *handlers.AuditLogHandler,
	settingsHandler *handlers.SettingsHandler,
	systemHandler *handlers.SystemHandler,
) {
	// 应用认证中间件
	protected := api.Group("")
	protected.Use(middleware.AuthMiddleware(cfg))

	// 认证相关路由
	registerAuthRoutes(protected, authHandler)

	// VPN 相关路由
	registerVPNRoutes(protected, vpnHandler)

	// 审计日志路由（普通用户可查看，管理员可删除）
	registerAuditLogRoutes(protected, auditLogHandler)

	// 只读路由（普通用户可查看）
	registerReadOnlyRoutes(protected, userHandler, policyHandler, hookHandler, groupHandler, settingsHandler)

	// 管理员路由（仅管理员可编辑）
	registerAdminRoutes(protected, userHandler, policyHandler, hookHandler, groupHandler, ldapConfigHandler, settingsHandler)

	// 系统指标
	system := protected.Group("/system")
	{
		system.GET("/metrics", systemHandler.GetMetrics)
	}
}

// registerAuthRoutes 注册认证路由
func registerAuthRoutes(protected *gin.RouterGroup, authHandler *handlers.AuthHandler) {
	auth := protected.Group("/auth")
	{
		auth.GET("/profile", authHandler.Profile)
		auth.POST("/logout", authHandler.Logout)
	}
}

// registerVPNRoutes 注册 VPN 路由
func registerVPNRoutes(protected *gin.RouterGroup, vpnHandler *handlers.VPNHandler) {
	vpn := protected.Group("/vpn")
	{
		// 用户 VPN 连接管理
		vpn.POST("/connect", vpnHandler.Connect)
		vpn.POST("/disconnect", vpnHandler.Disconnect)
		vpn.GET("/status", vpnHandler.GetConnectionStatus)
		vpn.GET("/config", vpnHandler.GetConfig)

		// VPN 管理员状态（只读，普通用户可查看）
		admin := vpn.Group("/admin")
		{
			admin.GET("/status", vpnHandler.GetStatus)
			admin.GET("/connected", vpnHandler.GetConnectedUsers)
			admin.GET("/ebpf/stats", vpnHandler.GetEBPFStats)
			admin.GET("/ebpf/stats/stream", vpnHandler.StreamEBPFStats) // SSE stream endpoint
			admin.GET("/config", vpnHandler.GetAdminConfig)
		}

		// VPN 管理员配置（需要管理员权限）
		adminConfig := vpn.Group("/admin")
		adminConfig.Use(middleware.AdminMiddleware())
		{
			adminConfig.POST("/config/compression", vpnHandler.UpdateCompressionConfig)
			// DNS拦截器配置已写死在代码中，不需要API接口
		}
	}
}

// registerAuditLogRoutes 注册审计日志路由（普通用户可查看，管理员可删除）
func registerAuditLogRoutes(protected *gin.RouterGroup, auditLogHandler *handlers.AuditLogHandler) {
	audit := protected.Group("/audit-logs")
	{
		// 普通用户和管理员都可以查看
		audit.GET("", auditLogHandler.ListAuditLogs)
		audit.GET("/stats", auditLogHandler.GetAuditLogStats)
		audit.GET("/:id", auditLogHandler.GetAuditLog)

		// 只有管理员可以删除
		adminAudit := audit.Group("")
		adminAudit.Use(middleware.AdminMiddleware())
		{
			adminAudit.DELETE("", auditLogHandler.DeleteAuditLogs) // 批量删除
		}
	}
}

// registerReadOnlyRoutes 注册只读路由（普通用户可查看）
func registerReadOnlyRoutes(
	protected *gin.RouterGroup,
	userHandler *handlers.UserHandler,
	policyHandler *handlers.PolicyHandler,
	hookHandler *handlers.HookHandler,
	groupHandler *handlers.GroupHandler,
	settingsHandler *handlers.SettingsHandler,
) {
	// 用户管理（只读）
	users := protected.Group("/users")
	{
		users.GET("", userHandler.ListUsers)
		users.GET("/:id", userHandler.GetUser)
		users.GET("/:id/otp", userHandler.GetOTP)
	}

	// 策略管理（只读）
	policies := protected.Group("/policies")
	{
		policies.GET("", policyHandler.ListPolicies)
		policies.GET("/:id", policyHandler.GetPolicy)
	}

	// Hook 管理（只读）
	hooks := protected.Group("/hooks")
	{
		hooks.GET("", hookHandler.ListHooks)
		hooks.GET("/:id", hookHandler.GetHook)
		hooks.GET("/sync/status", hookHandler.GetSyncStatus) // 获取同步状态
		hooks.GET("/:id/stats", hookHandler.GetHookStats)
	}

	// 用户组管理（只读）
	groups := protected.Group("/groups")
	{
		groups.GET("", groupHandler.ListGroups)
		groups.GET("/:id", groupHandler.GetGroup)
		groups.GET("/:id/users", groupHandler.GetGroupUsers)
		groups.GET("/:id/policies", groupHandler.GetGroupPolicies)
	}

	// 性能设置（只读，普通用户可查看）
	settings := protected.Group("/settings")
	{
		settings.GET("/performance", settingsHandler.GetPerformanceSettings)
		settings.GET("/security", settingsHandler.GetSecuritySettings)
		settings.GET("/distributed-sync", settingsHandler.GetDistributedSyncSettings)
		settings.GET("/audit-log", settingsHandler.GetAuditLogSettings)
	}
}

// registerAdminRoutes 注册管理员路由（需要管理员权限）
func registerAdminRoutes(
	protected *gin.RouterGroup,
	userHandler *handlers.UserHandler,
	policyHandler *handlers.PolicyHandler,
	hookHandler *handlers.HookHandler,
	groupHandler *handlers.GroupHandler,
	ldapConfigHandler *handlers.LDAPConfigHandler,
	settingsHandler *handlers.SettingsHandler,
) {
	// 应用管理员中间件
	admin := protected.Group("")
	admin.Use(middleware.AdminMiddleware())

	// 用户管理（编辑）
	users := admin.Group("/users")
	{
		users.POST("", userHandler.CreateUser)
		users.PUT("/:id", userHandler.UpdateUser)
		users.DELETE("/:id", userHandler.DeleteUser)
		users.PUT("/:id/password", userHandler.ChangePassword)
		// OTP相关路由
		users.POST("/:id/otp/generate", userHandler.GenerateOTP)
		users.DELETE("/:id/otp", userHandler.DisableOTP)
	}

	// 策略管理（编辑）
	policies := admin.Group("/policies")
	{
		policies.POST("", policyHandler.CreatePolicy)
		policies.PUT("/:id", policyHandler.UpdatePolicy)
		policies.DELETE("/:id", policyHandler.DeletePolicy)
		policies.POST("/:id/routes", policyHandler.AddRoute)
		policies.PUT("/:id/routes/:route_id", policyHandler.UpdateRoute)
		policies.DELETE("/:id/routes/:route_id", policyHandler.DeleteRoute)
		policies.POST("/:id/exclude-routes", policyHandler.AddExcludeRoute)
		policies.PUT("/:id/exclude-routes/:exclude_route_id", policyHandler.UpdateExcludeRoute)
		policies.DELETE("/:id/exclude-routes/:exclude_route_id", policyHandler.DeleteExcludeRoute)
		policies.POST("/:id/groups", policyHandler.AssignGroups)
	}

	// Hook 管理（编辑）
	hooks := admin.Group("/hooks")
	{
		hooks.POST("", hookHandler.CreateHook)
		hooks.PUT("/:id", hookHandler.UpdateHook)
		hooks.DELETE("/:id", hookHandler.DeleteHook)
		hooks.PUT("/:id/toggle", hookHandler.ToggleHook)
		hooks.POST("/sync", hookHandler.ForceSync) // 强制全量同步
		hooks.POST("/:id/test", hookHandler.TestHook)
		hooks.POST("/:id/sync", hookHandler.SyncHook) // 同步特定 Hook
	}

	// 用户组管理（编辑）
	groups := admin.Group("/groups")
	{
		groups.POST("", groupHandler.CreateGroup)
		groups.PUT("/:id", groupHandler.UpdateGroup)
		groups.DELETE("/:id", groupHandler.DeleteGroup)
		groups.POST("/:id/users", groupHandler.AssignUsers)
		groups.POST("/:id/policies", groupHandler.AssignPolicies)
	}

	// LDAP配置管理
	registerLDAPConfigRoutes(admin, ldapConfigHandler)

	// 性能设置管理（编辑，需要管理员权限）
	settings := admin.Group("/settings")
	{
		settings.POST("/performance", settingsHandler.UpdatePerformanceSettings)
		settings.POST("/security", settingsHandler.UpdateSecuritySettings)
		settings.POST("/distributed-sync", settingsHandler.UpdateDistributedSyncSettings)
		settings.POST("/audit-log", settingsHandler.UpdateAuditLogSettings)
		// 密码爆破防护管理
		settings.GET("/bruteforce/stats", settingsHandler.GetBruteforceStats)
		settings.GET("/bruteforce/blocked", settingsHandler.GetBlockedIPs)
		settings.POST("/bruteforce/block", settingsHandler.BlockIP)
		settings.POST("/bruteforce/unblock", settingsHandler.UnblockIP)
		settings.GET("/bruteforce/whitelist", settingsHandler.GetWhitelistIPs)
		settings.POST("/bruteforce/whitelist", settingsHandler.AddWhitelistIP)
		settings.DELETE("/bruteforce/whitelist", settingsHandler.RemoveWhitelistIP)
	}
}

// registerLDAPConfigRoutes 注册LDAP配置管理路由
func registerLDAPConfigRoutes(admin *gin.RouterGroup, ldapConfigHandler *handlers.LDAPConfigHandler) {
	ldap := admin.Group("/ldap")
	{
		ldap.GET("/config", ldapConfigHandler.GetLDAPConfig)
		ldap.PUT("/config", ldapConfigHandler.UpdateLDAPConfig)
		ldap.POST("/test", ldapConfigHandler.TestLDAPConnection)
		ldap.POST("/test-auth", ldapConfigHandler.TestLDAPAuth)
		ldap.POST("/sync-users", ldapConfigHandler.SyncLDAPUsers)
	}
}

package routes

import (
	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/handlers"
	"github.com/fisker/zvpn/middleware"
	"github.com/fisker/zvpn/vpn"
	"github.com/gin-gonic/gin"
)

func RegisterAPIRoutes(router *gin.Engine, cfg *config.Config, vpnServer *vpn.VPNServer, certManager handlers.CertificateManager) {
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
	certHandler := handlers.NewCertificateHandler()

	vpnHandler.SetVPNServer(vpnServer)
	hookHandler.SetVPNServer(vpnServer)
	settingsHandler.SetVPNServer(vpnServer)

	if certManager != nil {
		certHandler.SetCertificateManager(certManager)
	}

	api := router.Group("/api/v1")

	registerPublicRoutes(api, authHandler, ldapConfigHandler)

	registerProtectedRoutes(api, cfg, authHandler, vpnHandler, userHandler, policyHandler, hookHandler, groupHandler, ldapConfigHandler, auditLogHandler, settingsHandler, systemHandler, certHandler)
}

func registerPublicRoutes(api *gin.RouterGroup, authHandler *handlers.AuthHandler, ldapConfigHandler *handlers.LDAPConfigHandler) {
	api.POST("/auth/login", authHandler.Login)

	api.GET("/ldap/status", ldapConfigHandler.GetLDAPStatus)

	healthHandler := func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"service": "zvpn",
		})
	}
	api.GET("/health", healthHandler)
	api.HEAD("/health", healthHandler)
}

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
	certHandler *handlers.CertificateHandler,
) {
	protected := api.Group("")
	protected.Use(middleware.AuthMiddleware(cfg))

	registerAuthRoutes(protected, authHandler)

	registerVPNRoutes(protected, vpnHandler)

	registerAuditLogRoutes(protected, auditLogHandler)

	registerReadOnlyRoutes(protected, userHandler, policyHandler, hookHandler, groupHandler, settingsHandler)

	registerAdminRoutes(protected, userHandler, policyHandler, hookHandler, groupHandler, ldapConfigHandler, settingsHandler, certHandler)

	system := protected.Group("/system")
	{
		system.GET("/metrics", systemHandler.GetMetrics)
	}
}

func registerAuthRoutes(protected *gin.RouterGroup, authHandler *handlers.AuthHandler) {
	auth := protected.Group("/auth")
	{
		auth.GET("/profile", authHandler.Profile)
		auth.POST("/logout", authHandler.Logout)
	}
}

func registerVPNRoutes(protected *gin.RouterGroup, vpnHandler *handlers.VPNHandler) {
	vpn := protected.Group("/vpn")
	{
		vpn.POST("/connect", vpnHandler.Connect)
		vpn.POST("/disconnect", vpnHandler.Disconnect)
		vpn.GET("/status", vpnHandler.GetConnectionStatus)
		vpn.GET("/config", vpnHandler.GetConfig)

		admin := vpn.Group("/admin")
		{
			admin.GET("/status", vpnHandler.GetStatus)
			admin.GET("/connected", vpnHandler.GetConnectedUsers)
			admin.GET("/ebpf/stats", vpnHandler.GetEBPFStats)
			admin.GET("/ebpf/stats/stream", vpnHandler.StreamEBPFStats) // SSE stream endpoint
			admin.GET("/config", vpnHandler.GetAdminConfig)
		}

		adminConfig := vpn.Group("/admin")
		adminConfig.Use(middleware.AdminMiddleware())
		{
			adminConfig.POST("/config/compression", vpnHandler.UpdateCompressionConfig)
		}
	}
}

func registerAuditLogRoutes(protected *gin.RouterGroup, auditLogHandler *handlers.AuditLogHandler) {
	audit := protected.Group("/audit-logs")
	{
		audit.GET("", auditLogHandler.ListAuditLogs)
		audit.GET("/stats", auditLogHandler.GetAuditLogStats)
		audit.GET("/:id", auditLogHandler.GetAuditLog)

		adminAudit := audit.Group("")
		adminAudit.Use(middleware.AdminMiddleware())
		{
			adminAudit.DELETE("", auditLogHandler.DeleteAuditLogs) // 批量删除
		}
	}
}

func registerReadOnlyRoutes(
	protected *gin.RouterGroup,
	userHandler *handlers.UserHandler,
	policyHandler *handlers.PolicyHandler,
	hookHandler *handlers.HookHandler,
	groupHandler *handlers.GroupHandler,
	settingsHandler *handlers.SettingsHandler,
) {
	users := protected.Group("/users")
	{
		users.GET("", userHandler.ListUsers)
		users.GET("/:id", userHandler.GetUser)
		users.GET("/:id/otp", userHandler.GetOTP)
	}

	policies := protected.Group("/policies")
	{
		policies.GET("", policyHandler.ListPolicies)
		policies.GET("/:id", policyHandler.GetPolicy)
	}

	hooks := protected.Group("/hooks")
	{
		hooks.GET("", hookHandler.ListHooks)
		hooks.GET("/:id", hookHandler.GetHook)
		hooks.GET("/sync/status", hookHandler.GetSyncStatus) // 获取同步状态
		hooks.GET("/:id/stats", hookHandler.GetHookStats)
	}

	groups := protected.Group("/groups")
	{
		groups.GET("", groupHandler.ListGroups)
		groups.GET("/:id", groupHandler.GetGroup)
		groups.GET("/:id/users", groupHandler.GetGroupUsers)
		groups.GET("/:id/policies", groupHandler.GetGroupPolicies)
	}

	settings := protected.Group("/settings")
	{
		settings.GET("/performance", settingsHandler.GetPerformanceSettings)
		settings.GET("/security", settingsHandler.GetSecuritySettings)
		settings.GET("/distributed-sync", settingsHandler.GetDistributedSyncSettings)
		settings.GET("/audit-log", settingsHandler.GetAuditLogSettings)
		settings.GET("/banner", settingsHandler.GetBannerSettings)
		settings.GET("/vpn-profile", settingsHandler.GetVPNProfileSettings)
	}
}

func registerAdminRoutes(
	protected *gin.RouterGroup,
	userHandler *handlers.UserHandler,
	policyHandler *handlers.PolicyHandler,
	hookHandler *handlers.HookHandler,
	groupHandler *handlers.GroupHandler,
	ldapConfigHandler *handlers.LDAPConfigHandler,
	settingsHandler *handlers.SettingsHandler,
	certHandler *handlers.CertificateHandler,
) {
	admin := protected.Group("")
	admin.Use(middleware.AdminMiddleware())

	users := admin.Group("/users")
	{
		users.POST("", userHandler.CreateUser)
		users.PUT("/:id", userHandler.UpdateUser)
		users.DELETE("/:id", userHandler.DeleteUser)
		users.PUT("/:id/password", userHandler.ChangePassword)
		users.POST("/:id/otp/generate", userHandler.GenerateOTP)
		users.DELETE("/:id/otp", userHandler.DisableOTP)
	}

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

	groups := admin.Group("/groups")
	{
		groups.POST("", groupHandler.CreateGroup)
		groups.PUT("/:id", groupHandler.UpdateGroup)
		groups.DELETE("/:id", groupHandler.DeleteGroup)
		groups.POST("/:id/users", groupHandler.AssignUsers)
		groups.POST("/:id/policies", groupHandler.AssignPolicies)
	}

	registerLDAPConfigRoutes(admin, ldapConfigHandler)

	settings := admin.Group("/settings")
	{
		settings.POST("/performance", settingsHandler.UpdatePerformanceSettings)
		settings.POST("/security", settingsHandler.UpdateSecuritySettings)
		settings.POST("/distributed-sync", settingsHandler.UpdateDistributedSyncSettings)
		settings.POST("/audit-log", settingsHandler.UpdateAuditLogSettings)
		settings.POST("/banner", settingsHandler.UpdateBannerSettings)
		settings.POST("/vpn-profile", settingsHandler.UpdateVPNProfileSettings)
		settings.GET("/bruteforce/stats", settingsHandler.GetBruteforceStats)
		settings.GET("/bruteforce/blocked", settingsHandler.GetBlockedIPs)
		settings.POST("/bruteforce/block", settingsHandler.BlockIP)
		settings.POST("/bruteforce/unblock", settingsHandler.UnblockIP)
		settings.GET("/bruteforce/whitelist", settingsHandler.GetWhitelistIPs)
		settings.POST("/bruteforce/whitelist", settingsHandler.AddWhitelistIP)
		settings.DELETE("/bruteforce/whitelist", settingsHandler.RemoveWhitelistIP)
	}

	certificates := admin.Group("/certificates")
	{
		certificates.GET("", certHandler.ListCertificates)                 // 获取所有证书列表
		certificates.POST("/sni", certHandler.AddSNICertificate)           // 添加 SNI 证书
		certificates.DELETE("/sni/:sni", certHandler.RemoveSNICertificate) // 删除 SNI 证书
		certificates.PUT("/default", certHandler.UpdateDefaultCertificate) // 更新默认证书
	}
}

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


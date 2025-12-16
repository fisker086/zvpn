package routes

import (
	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/vpn"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
	"path"
	"strings"
)

// SetupRouter 初始化并配置路由
func SetupRouter(cfg *config.Config, vpnServer *vpn.VPNServer) *gin.Engine {
	// 设置运行模式
	gin.SetMode(cfg.Server.Mode)
	
	router := gin.Default()

	// 应用 CORS 中间件
	router.Use(corsMiddleware())

	// 注册 API 路由
	RegisterAPIRoutes(router, cfg, vpnServer)

	// 前端静态资源（构建后放置于 ./web）
	const frontendDir = "./web"
	if info, err := os.Stat(frontendDir); err == nil && info.IsDir() {
		assetsDir := path.Join(frontendDir, "assets")
		router.Static("/assets", assetsDir)

		// SPA 回退：尝试命中文件，否则返回 index.html；/api/* 不处理
		router.NoRoute(func(c *gin.Context) {
			if strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.JSON(http.StatusNotFound, gin.H{"error": "API route not found"})
				return
			}
			requestPath := c.Request.URL.Path
			if requestPath == "/" || requestPath == "" {
				c.File(path.Join(frontendDir, "index.html"))
				return
			}
			// 尝试返回静态文件
			cleanPath := path.Clean(requestPath)
			filePath := path.Join(frontendDir, cleanPath)
			if info, err := os.Stat(filePath); err == nil && !info.IsDir() {
				c.File(filePath)
				return
			}
			// 回退到 index.html
			c.File(path.Join(frontendDir, "index.html"))
		})
	}

	return router
}

// corsMiddleware CORS 中间件
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}


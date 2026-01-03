package routes

import (
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/handlers"
	"github.com/fisker/zvpn/middleware"
	"github.com/fisker/zvpn/vpn"
	"github.com/gin-gonic/gin"
)

func SetupRouter(cfg *config.Config, vpnServer *vpn.VPNServer, certManager handlers.CertificateManager) *gin.Engine {
	gin.SetMode(cfg.Server.Mode)

	router := gin.Default()

	router.Use(middleware.CorsMiddleware())

	RegisterAPIRoutes(router, cfg, vpnServer, certManager)

	const frontendDir = "./web"
	if info, err := os.Stat(frontendDir); err == nil && info.IsDir() {
		assetsDir := path.Join(frontendDir, "assets")
		router.Static("/assets", assetsDir)

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
			cleanPath := path.Clean(requestPath)
			filePath := path.Join(frontendDir, cleanPath)
			if info, err := os.Stat(filePath); err == nil && !info.IsDir() {
				c.File(filePath)
				return
			}
			c.File(path.Join(frontendDir, "index.html"))
		})
	}

	return router
}


package main

import (
	"log"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/server"
	"github.com/fisker/zvpn/vpn"
)

// 版本信息（通过构建时注入）
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	// 加载配置
	cfg := config.Load()

	// 初始化数据库
	if err := database.Init(cfg); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// 初始化 VPN 服务器
	vpnServer, err := vpn.NewVPNServer(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize VPN server: %v", err)
	}

	// 创建并启动服务器
	srv := server.New(cfg, vpnServer)
	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

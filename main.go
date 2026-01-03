package main

import (
	"log"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/server"
	"github.com/fisker/zvpn/vpn"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	cfg := config.Load()

	if err := database.Init(cfg); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	vpnServer, err := vpn.NewVPNServer(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize VPN server: %v", err)
	}

	srv := server.New(cfg, vpnServer)
	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

package config

import (
	"fmt"
	"log"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	VPN      VPNConfig
	JWT      JWTConfig
	LDAP     LDAPConfig
}

type ServerConfig struct {
	Host string
	Port string
	Mode string // debug, release
}

type DatabaseConfig struct {
	Type            string // mysql, postgres
	DSN             string
	MaxOpenConns    int `mapstructure:"maxopenconns"`    // 最大打开连接数（默认：25）
	MaxIdleConns    int `mapstructure:"maxidleconns"`    // 最大空闲连接数（默认：10）
	ConnMaxLifetime int `mapstructure:"connmaxlifetime"` // 连接最大生存时间（秒，默认：300）
	ConnMaxIdleTime int `mapstructure:"connmaxidletime"` // 连接最大空闲时间（秒，默认：60）
}

type VPNConfig struct {
	InterfaceName     string `mapstructure:"interfacename"`
	Network           string `mapstructure:"network"` // CIDR format, e.g., "10.8.0.0/24"
	MTU               int    `mapstructure:"mtu"`
	CertFile          string `mapstructure:"certfile"`
	KeyFile           string `mapstructure:"keyfile"`
	EBPFInterfaceName string `mapstructure:"ebpfinterfacename"` // Network interface for eBPF XDP program

	EnableCustomProtocol bool   `mapstructure:"enablecustomprotocol"` // Enable custom SSL VPN protocol
	CustomPort           string `mapstructure:"customport"`           // Custom protocol port (default: 443)
	EnableOpenConnect    bool   `mapstructure:"enableopenconnect"`    // Enable OpenConnect protocol
	OpenConnectPort      string `mapstructure:"openconnectport"`      // OpenConnect HTTPS port (default: 443)
	EnableDTLS           bool   `mapstructure:"enabledtls"`           // Enable DTLS (UDP) for better performance
	DTLSPort             string `mapstructure:"dtlsport"`             // DTLS UDP port (default: 443, UDP)

	EnableAFXDP  bool `mapstructure:"enableafxdp"`  // Enable AF_XDP zero-copy (experimental)
	AFXDPQueueID int  `mapstructure:"afxdpqueueid"` // AF_XDP queue ID (default: 0)

	EnableBatchProcessing bool  `mapstructure:"enablebatchprocessing"` // Enable batch TUN processing (epoll)
	LogSampleRate         int64 `mapstructure:"logsamplerate"`         // Log sampling rate (0=all, N=every N packets)
	EnableShardedLocks    bool  `mapstructure:"enableshardedlocks"`    // Enable sharded locks for better concurrency
	ShardCount            int   `mapstructure:"shardcount"`            // Number of shards for sharded locks (default: 16)
	EnableCSTPBatch       bool  `mapstructure:"enablecstpbatch"`       // Enable CSTP batch encapsulation
	CSTPBatchMaxPackets   int   `mapstructure:"cstpbatchmaxpackets"`   // Max packets per batch (default: 10)
	CSTPBatchMaxSize      int   `mapstructure:"cstpbatchmaxsize"`      // Max batch size in bytes (default: 8192)
	CSTPBatchTimeout      int   `mapstructure:"cstpbatchtimeout"`      // Batch timeout in milliseconds (default: 10)
	WriteChanBufferSize   int   `mapstructure:"writechanbuffersize"`   // Write channel buffer size (default: 100)
	EnableWriteBatching   bool  `mapstructure:"enablewritebatching"`   // Enable write batching in WriteLoop
	WriteBatchSize        int   `mapstructure:"writebatchsize"`        // Max packets per write batch (default: 10)
	WriteBatchTimeout     int   `mapstructure:"writebatchtimeout"`     // Write batch timeout in milliseconds (default: 1)

	EnableDistributedSync bool `mapstructure:"enabledistributedsync"` // Enable distributed sync for multi-node (default: true)
	SyncInterval          int  `mapstructure:"syncinterval"`          // Full sync interval in seconds (default: 60)
	ChangeCheckInterval   int  `mapstructure:"changecheckinterval"`   // Change check interval in seconds (default: 5)

	EnableCompression bool   `mapstructure:"enablecompression"` // Enable traffic compression (default: false)
	CompressionType   string `mapstructure:"compressiontype"`   // Compression type: none, lz4, gzip (default: none)

	CSTPDPD         int    `mapstructure:"cstpdpd"`         // CSTP dead peer detection interval in seconds (default: 30)
	CSTPKeepalive   int    `mapstructure:"cstpkeepalive"`   // CSTP keepalive interval in seconds (default: 20)
	MobileDPD       int    `mapstructure:"mobiledpd"`       // Mobile client DPD interval in seconds (default: 60)
	MobileKeepalive int    `mapstructure:"mobilekeepalive"` // Mobile client keepalive interval in seconds (default: 30)
	UpstreamDNS     string `mapstructure:"upstreamdns"`     // Upstream DNS server (default: 8.8.8.8)

	EnableRateLimit      bool  `mapstructure:"enableratelimit"`      // Enable rate limiting (default: true)
	RateLimitPerIP       int64 `mapstructure:"ratelimitperip"`       // Rate limit per IP (packets per second, default: 1000)
	RateLimitPerUser     int64 `mapstructure:"ratelimitperuser"`     // Rate limit per user (bytes per second, default: 10485760 = 10MB/s)
	EnableDDoSProtection bool  `mapstructure:"enableddosprotection"` // Enable DDoS protection (default: true)
	DDoSThreshold        int64 `mapstructure:"ddosthreshold"`        // DDoS detection threshold (packets per second per IP, default: 10000)
	DDoSBlockDuration    int   `mapstructure:"ddosblockduration"`    // DDoS block duration in seconds (default: 300 = 5 minutes)

	EnableBruteforceProtection bool `mapstructure:"enablebruteforceprotection"` // Enable bruteforce protection (default: true)
	MaxLoginAttempts           int  `mapstructure:"maxloginattempts"`           // Maximum failed login attempts before blocking (default: 5)
	LoginLockoutDuration       int  `mapstructure:"loginlockoutduration"`       // Lockout duration in seconds (default: 900 = 15 minutes)
	LoginAttemptWindow         int  `mapstructure:"loginattemptwindow"`         // Time window for counting attempts in seconds (default: 300 = 5 minutes)

	AllowMultiClientLogin bool `mapstructure:"allowmulticlientlogin"` // Allow same account multiple concurrent logins
}

type JWTConfig struct {
	Secret     string
	Expiration int // hours
}

type LDAPConfig struct {
	Enabled      bool
	Host         string
	Port         int
	BindDN       string
	BindPassword string
	BaseDN       string
	UserFilter   string
	AdminGroup   string
}

func Load() *Config {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/zvpn")

	setDefaults()

	viper.BindEnv("vpn.network", "VPN_NETWORK")
	viper.BindEnv("vpn.certfile", "VPN_CERT")
	viper.BindEnv("vpn.keyfile", "VPN_KEY")
	viper.BindEnv("vpn.ebpfinterfacename", "VPN_EBPF_INTERFACE")
	viper.BindEnv("vpn.enableafxdp", "VPN_ENABLE_AFXDP")
	viper.BindEnv("vpn.afxdpqueueid", "VPN_AFXDP_QUEUE_ID")
	viper.BindEnv("vpn.enablebatchprocessing", "VPN_ENABLE_BATCH_PROCESSING")
	viper.BindEnv("vpn.logsamplerate", "VPN_LOG_SAMPLE_RATE")
	viper.BindEnv("vpn.enableshardedlocks", "VPN_ENABLE_SHARDED_LOCKS")
	viper.BindEnv("vpn.shardcount", "VPN_SHARD_COUNT")
	viper.BindEnv("vpn.enablecstpbatch", "VPN_ENABLE_CSTP_BATCH")
	viper.BindEnv("vpn.cstpbatchmaxpackets", "VPN_CSTP_BATCH_MAX_PACKETS")
	viper.BindEnv("vpn.cstpbatchmaxsize", "VPN_CSTP_BATCH_MAX_SIZE")
	viper.BindEnv("vpn.cstpbatchtimeout", "VPN_CSTP_BATCH_TIMEOUT")
	viper.BindEnv("vpn.enableratelimit", "VPN_ENABLE_RATE_LIMIT")
	viper.BindEnv("vpn.ratelimitperip", "VPN_RATE_LIMIT_PER_IP")
	viper.BindEnv("vpn.ratelimitperuser", "VPN_RATE_LIMIT_PER_USER")
	viper.BindEnv("vpn.enableddosprotection", "VPN_ENABLE_DDOS_PROTECTION")
	viper.BindEnv("vpn.ddosthreshold", "VPN_DDOS_THRESHOLD")
	viper.BindEnv("vpn.ddosblockduration", "VPN_DDOS_BLOCK_DURATION")
	viper.BindEnv("vpn.enablebruteforceprotection", "VPN_ENABLE_BRUTEFORCE_PROTECTION")
	viper.BindEnv("vpn.maxloginattempts", "VPN_MAX_LOGIN_ATTEMPTS")
	viper.BindEnv("vpn.loginlockoutduration", "VPN_LOGIN_LOCKOUT_DURATION")
	viper.BindEnv("vpn.loginattemptwindow", "VPN_LOGIN_ATTEMPT_WINDOW")
	viper.BindEnv("vpn.allowmulticlientlogin", "VPN_ALLOW_MULTI_CLIENT_LOGIN")

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Println("⚠️  配置文件未找到，使用默认配置")
		} else {
			log.Fatalf("❌ 读取配置文件失败: %v", err)
		}
	} else {
		log.Printf("✓ 配置文件加载成功: %s", viper.ConfigFileUsed())
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		log.Fatalf("❌ 解析配置失败: %v", err)
	}

	if err := validateConfig(&config); err != nil {
		log.Fatalf("❌ 配置验证失败: %v", err)
	}

	printConfigSummary(&config)

	return &config
}

func setDefaults() {
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", "18080")
	viper.SetDefault("server.mode", "debug")

	viper.SetDefault("database.type", "mysql")
	viper.SetDefault("database.dsn", "zvpn:zvpn@tcp(127.0.0.1:3306)/zvpn?charset=utf8mb4&parseTime=True&loc=Local")

	// 支持环境变量覆盖数据库类型和 DSN
	viper.BindEnv("database.type", "DB_TYPE", "DATABASE_TYPE")
	viper.BindEnv("database.dsn", "DB_DSN", "DATABASE_DSN")
	viper.SetDefault("database.maxopenconns", 25)     // 最大打开连接数
	viper.SetDefault("database.maxidleconns", 10)     // 最大空闲连接数
	viper.SetDefault("database.connmaxlifetime", 300) // 连接最大生存时间（秒）
	viper.SetDefault("database.connmaxidletime", 60)  // 连接最大空闲时间（秒）

	viper.SetDefault("vpn.interfacename", "zvpn0")
	viper.SetDefault("vpn.ebpfinterfacename", "eth0")
	viper.SetDefault("vpn.network", "10.8.0.0/24")
	viper.SetDefault("vpn.mtu", 1500)
	viper.SetDefault("vpn.certfile", "./certs/server.crt")
	viper.SetDefault("vpn.keyfile", "./certs/server.key")
	viper.SetDefault("vpn.enablecustomprotocol", false)
	viper.SetDefault("vpn.customport", "443")
	viper.SetDefault("vpn.enableopenconnect", true)
	viper.SetDefault("vpn.openconnectport", "443")
	viper.SetDefault("vpn.enabledtls", true)
	viper.SetDefault("vpn.dtlsport", "443")
	viper.SetDefault("vpn.enableafxdp", false) // Disabled by default (experimental)
	viper.SetDefault("vpn.afxdpqueueid", 0)
	viper.SetDefault("vpn.enablebatchprocessing", true) // Enabled by default for better performance
	viper.SetDefault("vpn.logsamplerate", 1000)         // Log every 1000 packets by default
	viper.SetDefault("vpn.enableshardedlocks", true)    // Enabled by default for better concurrency
	viper.SetDefault("vpn.shardcount", 16)              // 16 shards by default (power of 2)
	viper.SetDefault("vpn.enablecstpbatch", false)      // Disabled by default (experimental)
	viper.SetDefault("vpn.cstpbatchmaxpackets", 10)     // Max 10 packets per batch
	viper.SetDefault("vpn.cstpbatchmaxsize", 8192)      // Max 8KB per batch
	viper.SetDefault("vpn.cstpbatchtimeout", 10)        // 10ms timeout

	viper.SetDefault("vpn.enabledistributedsync", true) // Enabled by default for multi-node support
	viper.SetDefault("vpn.syncinterval", 60)            // Full sync every 60 seconds

	viper.SetDefault("vpn.enablecompression", false) // Disabled by default
	viper.SetDefault("vpn.compressiontype", "none")  // none, lz4, gzip
	viper.SetDefault("vpn.mobiledpd", 60)            // Mobile client DPD interval (default: 60 seconds)
	viper.SetDefault("vpn.mobilekeepalive", 4)       // Mobile client keepalive interval (default: 4 seconds, aligned with anylink)
	viper.SetDefault("vpn.upstreamdns", "8.8.8.8")   // Upstream DNS server (default: 8.8.8.8)

	viper.SetDefault("vpn.changecheckinterval", 5)  // Check for changes every 5 seconds
	viper.SetDefault("vpn.cstpbatchmaxpackets", 10) // Max 10 packets per batch
	viper.SetDefault("vpn.cstpbatchmaxsize", 8192)  // Max 8KB per batch
	viper.SetDefault("vpn.cstpbatchtimeout", 10)    // 10ms timeout

	viper.SetDefault("vpn.enableratelimit", false)      // Disable rate limiting by default
	viper.SetDefault("vpn.ratelimitperip", 1000)        // 1000 packets per second per IP (when enabled)
	viper.SetDefault("vpn.ratelimitperuser", 10485760)  // 10MB/s per user (bytes per second, when enabled)
	viper.SetDefault("vpn.enableddosprotection", false) // Disable DDoS protection by default
	viper.SetDefault("vpn.ddosthreshold", 10000)        // 10000 packets per second per IP (when enabled)
	viper.SetDefault("vpn.ddosblockduration", 300)      // Block for 5 minutes (when enabled)
	viper.SetDefault("vpn.allowmulticlientlogin", true) // Allow same account multiple concurrent logins by default

	viper.SetDefault("vpn.enablebruteforceprotection", true) // Enable bruteforce protection by default
	viper.SetDefault("vpn.maxloginattempts", 5)              // 5 failed attempts before blocking
	viper.SetDefault("vpn.loginlockoutduration", 900)        // Block for 15 minutes
	viper.SetDefault("vpn.loginattemptwindow", 300)          // Count attempts within 5 minutes

	viper.SetDefault("jwt.secret", "your-secret-key-change-this")
	viper.SetDefault("jwt.expiration", 24)

	viper.SetDefault("ldap.enabled", false)
	viper.SetDefault("ldap.host", "ldap.company.com")
	viper.SetDefault("ldap.port", 389)
	viper.SetDefault("ldap.usessl", false)
	viper.SetDefault("ldap.binddn", "")
	viper.SetDefault("ldap.bindpassword", "")
	viper.SetDefault("ldap.basedn", "")
	viper.SetDefault("ldap.userfilter", "(uid=%s)")
	viper.SetDefault("ldap.admingroup", "")
	viper.SetDefault("ldap.skiptlsverify", false)
}

func validateConfig(cfg *Config) error {
	validTypes := []string{"mysql", "postgres", "postgresql", "sqlite", "sqlite3"}
	isValid := false
	for _, t := range validTypes {
		if cfg.Database.Type == t {
			isValid = true
			break
		}
	}
	if !isValid {
		return fmt.Errorf("不支持的数据库类型: %s (支持: mysql, postgres, sqlite)", cfg.Database.Type)
	}

	// SQLite 的 DSN 是文件路径，可以为空（使用默认路径）
	if cfg.Database.DSN == "" {
		if cfg.Database.Type == "sqlite" || cfg.Database.Type == "sqlite3" {
			// SQLite 默认使用 data/zvpn.db
			cfg.Database.DSN = "data/zvpn.db"
			log.Printf("SQLite DSN 未设置，使用默认路径: %s", cfg.Database.DSN)
		} else {
			return fmt.Errorf("数据库 DSN 不能为空")
		}
	}

	if cfg.JWT.Secret == "your-secret-key-change-this" {
		log.Println("⚠️  警告: 使用默认 JWT Secret，生产环境请修改！")
	}

	if cfg.LDAP.Enabled {
		if cfg.LDAP.Host == "" || cfg.LDAP.BindDN == "" || cfg.LDAP.BaseDN == "" {
			return fmt.Errorf("LDAP 已启用，但配置不完整")
		}
	}

	return nil
}

func printConfigSummary(cfg *Config) {
	log.Println("==================== 当前配置 ====================")
	log.Printf("管理 API: http://%s:%s (mode: %s)", cfg.Server.Host, cfg.Server.Port, cfg.Server.Mode)
	if cfg.VPN.EnableOpenConnect {
		log.Printf("OpenConnect VPN: https://%s:%s", cfg.Server.Host, cfg.VPN.OpenConnectPort)
		if cfg.VPN.EnableDTLS {
			log.Printf("  └─ DTLS 加速: udp://%s:%s (启用)", cfg.Server.Host, cfg.VPN.DTLSPort)
		} else {
			log.Printf("  └─ DTLS 加速: 禁用")
		}
	}
	if cfg.VPN.EnableCustomProtocol {
		log.Printf("自定义协议: ssl://%s:%s", cfg.Server.Host, cfg.VPN.CustomPort)
	}
	log.Printf("数据库: %s", cfg.Database.Type)
	log.Printf("VPN 网段: %s", cfg.VPN.Network)

	log.Printf("LDAP 认证: %v", cfg.LDAP.Enabled)
	if cfg.LDAP.Enabled {
		log.Printf("LDAP 服务器: %s:%d", cfg.LDAP.Host, cfg.LDAP.Port)
	}
	log.Println("==================================================")
}


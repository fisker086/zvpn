package vpn

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/vpn/ebpf"
	"github.com/fisker/zvpn/vpn/policy"
	"github.com/fisker/zvpn/vpn/security"
	"github.com/vishvananda/netlink"
)

type VPNServer struct {
	config      *config.Config
	routeMgr    *RouteManager
	policyMgr   *policy.Manager
	ebpfProgram *ebpf.XDPProgram // XDP program for ingress traffic (eth0) - policy checking only
	tcProgram   interface{}      // *ebpf.TCProgram (avoid circular import) - TC egress program for NAT
	forwarder   *PacketForwarder
	ipPool      *IPPool
	tunDevice   *TUNDevice // 共享的TUN设备实例
	xdpSocket   *XDPSocket // AF_XDP socket for zero-copy (experimental)

	// Lock optimization: use sharded maps if enabled, otherwise use regular maps with locks
	useShardedLocks bool
	clients         map[uint]*VPNClient // Used when sharded locks disabled
	clientsLock     sync.RWMutex        // Used when sharded locks disabled
	shardedClients  *ShardedClientMap   // Used when sharded locks enabled
	vpnIPToUser     map[string]uint     // Used when sharded locks disabled
	vpnIPLock       sync.RWMutex        // Used when sharded locks disabled
	shardedVPNIP    *ShardedVPNIPMap    // Used when sharded locks enabled

	// Compression manager
	CompressionMgr *CompressionManager

	// Memory pool for packet buffers
	packetPool *sync.Pool

	// Bruteforce protection
	bruteforceProtection interface{} // *security.BruteforceProtection (avoid circular import)

	// Egress IP for NAT masquerading (stored for user-space NAT)
	egressIP     net.IP
	egressIPLock sync.RWMutex
}

type VPNClient struct {
	UserID     uint
	User       *models.User
	Conn       net.Conn
	DTLSConn   net.Conn // DTLS connection (if DTLS is enabled and established)
	IP         net.IP
	UserAgent  string
	ClientOS   string
	ClientVer  string
	Connected  bool
	lock       sync.Mutex
	writeLock  sync.Mutex    // Separate lock for writes to avoid blocking reads
	WriteChan  chan []byte   // Channel for queuing packets to send
	WriteClose chan struct{} // Channel to signal write goroutine to stop
	server     *VPNServer    // Reference to server for config access (optional)
}

// NewVPNServer creates a new VPN server
func NewVPNServer(cfg *config.Config) (*VPNServer, error) {
	// 初始化路由管理器
	routeMgr := NewRouteManager(cfg.VPN.InterfaceName)

	// 尝试创建和配置TUN设备
	log.Printf("Attempting to create and configure TUN device: %s", cfg.VPN.InterfaceName)
	var tunDevice *TUNDevice
	// 解析VPN网络并创建TUN设备
	_, ipNet, err := net.ParseCIDR(cfg.VPN.Network)
	if err != nil {
		return nil, fmt.Errorf("invalid VPN network: %w", err)
	}

	// 计算网关IP和TUN地址
	gatewayIP := make(net.IP, len(ipNet.IP))
	copy(gatewayIP, ipNet.IP)
	gatewayIP[len(gatewayIP)-1] = 1
	ones, _ := ipNet.Mask.Size()
	tunAddress := fmt.Sprintf("%s/%d", gatewayIP.String(), ones)
	log.Printf("TUN device will be configured with IP address: %s (gateway IP: %s)", tunAddress, gatewayIP.String())

	tunDevice, err = NewTUNDevice(cfg.VPN.InterfaceName, tunAddress, cfg.VPN.MTU)
	if err != nil {
		log.Printf("Warning: Failed to create TUN device: %v", err)
		log.Printf("Using existing virtual network interface if available: %s", cfg.VPN.InterfaceName)
	} else {
		log.Printf("TUN device created successfully")
	}

	// 检查接口是否存在
	_, err = netlink.LinkByName(cfg.VPN.InterfaceName)
	if err != nil {
		log.Printf("Warning: Virtual network interface %s not found. VPN functionality may be limited.", cfg.VPN.InterfaceName)
	} else {
		log.Printf("Virtual network interface %s is available", cfg.VPN.InterfaceName)
		// 如果接口存在但创建失败，尝试获取现有接口
		if tunDevice == nil {
			tunDevice, err = NewTUNDevice(cfg.VPN.InterfaceName, tunAddress, cfg.VPN.MTU)
			if err != nil {
				log.Printf("Warning: Failed to open existing TUN device: %v", err)
			} else {
				log.Printf("Opened existing TUN device successfully")
			}
		}
	}

	// 创建IP池
	ipPool, err := NewIPPool(ipNet)
	if err != nil {
		return nil, fmt.Errorf("failed to create IP pool: %w", err)
	}
	// Reserve gateway IP to avoid assigning to clients
	ipPool.Reserve(gatewayIP)

	// Initialize policy manager
	policyMgr := policy.NewManager()

	// 注册默认路由策略
	if err = registerDefaultPolicies(policyMgr, cfg); err != nil {
		log.Printf("Warning: Failed to register default policies: %v", err)
	}

	// Initialize eBPF XDP (required)
	var ebpfProg *ebpf.XDPProgram

	// Load eBPF program on the main network interface (required)
	log.Printf("Loading eBPF XDP program on interface: %s", cfg.VPN.EBPFInterfaceName)
	ebpfProg, err = ebpf.LoadXDPProgram(cfg.VPN.EBPFInterfaceName)
	if err != nil {
		log.Fatalf("Failed to load eBPF XDP program on %s: %v (eBPF is required)", cfg.VPN.EBPFInterfaceName, err)
	}
	log.Printf("eBPF XDP program loaded successfully on %s", cfg.VPN.EBPFInterfaceName)

	// 初始化 eBPF rate limit 和 DDoS 防护配置
	if err := initializeEBPFRateLimitConfig(ebpfProg, cfg); err != nil {
		log.Printf("Warning: Failed to initialize eBPF rate limit config: %v", err)
	} else {
		log.Printf("eBPF rate limit and DDoS protection config initialized")
	}

	// 设置策略管理器的eBPF加载器（eBPF已加载）
	ebpfLoader := policy.NewEBPFLoader(ebpfProg)
	policyMgr.SetEBPFLoader(ebpfLoader)
	log.Printf("Policy manager integrated with eBPF")

	// Initialize public IP for NAT masquerading
	// Automatically detect and set the egress interface IP
	// Note: We'll set the egress IP in server after creation
	publicIP, err := GetEgressInterfaceIP()
	if err != nil {
		log.Printf("Warning: Failed to auto-detect egress interface IP: %v", err)
		log.Printf("Attempting to use interface IP from other methods...")

		// Fallback: try to get IP from any non-loopback interface
		ifaces, err := net.Interfaces()
		if err == nil {
			for _, iface := range ifaces {
				if iface.Flags&net.FlagLoopback != 0 {
					continue
				}
				addrs, err := iface.Addrs()
				if err != nil {
					continue
				}
				for _, addr := range addrs {
					ipNet, ok := addr.(*net.IPNet)
					if ok && ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() && !ipNet.IP.IsLinkLocalUnicast() {
						publicIP = ipNet.IP
						log.Printf("Using IP from interface %s: %s", iface.Name, publicIP.String())
						break
					}
				}
				if publicIP != nil {
					break
				}
			}
		}
	}

	var egressIPForServer net.IP
	var tcProg interface{} // *ebpf.TCProgram

	// Always set up NAT, even if egress IP detection failed
	// MASQUERADE will automatically use the interface IP
	if publicIP != nil {
		// Set in eBPF XDP map (for reference, XDP is used for policy checking only)
		if err := ebpfProg.SetPublicIP(publicIP); err != nil {
			log.Printf("Warning: Failed to set egress IP in eBPF XDP map: %v", err)
		} else {
			log.Printf("✅ eBPF XDP: Public IP configured: %s (for policy checking)", publicIP.String())
		}

		// NAT 策略: eBPF TC (优先，内核 5.19+) -> nftables (fallback)
		log.Printf("配置 NAT: 优先尝试 eBPF TC egress NAT (需要内核 5.19+)")
		tcProg, err = loadEBPFTCNAT(cfg.VPN.EBPFInterfaceName, publicIP, cfg.VPN.Network)
		if err != nil {
			log.Printf("⚠️  eBPF TC NAT 加载失败: %v", err)
			log.Printf("   原因可能是: 内核版本 < 5.19 (TCX egress 需要 5.19+) 或权限不足")
			log.Printf("   回退到 nftables MASQUERADE...")

			// Fallback to nftables
			if err := setupIPTablesNAT(cfg.VPN.Network, cfg.VPN.EBPFInterfaceName); err != nil {
				log.Printf("❌ NAT 配置失败: nftables MASQUERADE 设置失败: %v", err)
				log.Printf("   NAT 将无法工作 - VPN 客户端无法访问外部网络")
			} else {
				log.Printf("✅ NAT 配置成功: 使用 nftables MASQUERADE (fallback)")
			}
		} else {
			log.Printf("✅ eBPF TC NAT 加载成功: 使用 eBPF TC egress NAT (高性能，内核级 NAT)")
			// 即使 eBPF TC NAT 加载成功，也设置 nftables 规则作为备用
			// 因为 eBPF TC NAT 可能在某些情况下不工作（权限、内核版本等）
			log.Printf("配置 NAT: 同时设置 nftables MASQUERADE 作为备用...")
			if err := setupIPTablesNAT(cfg.VPN.Network, cfg.VPN.EBPFInterfaceName); err != nil {
				log.Printf("⚠️  备用 NAT 配置失败: nftables MASQUERADE 设置失败: %v", err)
				log.Printf("   将仅依赖 eBPF TC NAT，如果 eBPF NAT 不工作，NAT 可能失败")
			} else {
				log.Printf("✅ 备用 NAT 配置成功: nftables MASQUERADE 已设置")
			}
		}

		egressIPForServer = publicIP
	} else {
		log.Printf("Warning: Failed to detect egress interface IP.")
		log.Printf("配置 NAT: 使用 MASQUERADE (自动检测出口 IP)...")
		// Set up NAT anyway - MASQUERADE will auto-detect the egress IP
		// This is important for Docker containers where IP detection might fail
		if err := setupIPTablesNAT(cfg.VPN.Network, cfg.VPN.EBPFInterfaceName); err != nil {
			log.Printf("❌ NAT 配置失败: nftables MASQUERADE 设置失败: %v", err)
			log.Printf("   NAT 将无法工作 - VPN 客户端无法访问外部网络")
			log.Printf("   请手动添加 NAT 规则: nft add rule ip nat POSTROUTING ip saddr %s oifname %s masquerade", cfg.VPN.Network, cfg.VPN.EBPFInterfaceName)
		} else {
			log.Printf("✅ NAT 配置成功: 使用 nftables MASQUERADE (自动检测出口 IP)")
		}
	}

	// Distributed hook synchronization is managed via DB/system settings (SettingsHandler).

	// Initialize packet forwarder
	forwarder, err := NewPacketForwarder()
	if err != nil {
		log.Printf("Warning: Failed to initialize packet forwarder: %v", err)
	}

	// Enable IP forwarding
	if err := EnableIPForwarding(); err != nil {
		log.Printf("Warning: Failed to enable IP forwarding: %v", err)
	}

	// Note: We do NOT add a route for the VPN network (e.g., 10.8.0.0/24) to the TUN device
	// because:
	// 1. When TUN device is configured with IP address (e.g., 10.8.0.1/24), the kernel
	//    automatically recognizes 10.8.0.1 as a local IP address and will respond to
	//    packets sent to it (e.g., ICMP echo requests)
	// 2. Client IPs (e.g., 10.8.0.2) should be reached via the OpenConnect tunnel (gateway),
	//    not via TUN device routing
	// 3. Adding a route like "10.8.0.0/24 dev tun0" would cause the kernel to route ALL
	//    packets in that network through TUN, which prevents proper local IP recognition
	//
	// The kernel will automatically handle:
	// - Packets to 10.8.0.1 (server VPN IP) -> recognized as local, kernel generates response
	// - Packets from clients -> handled by our OpenConnect protocol handler
	log.Printf("TUN device IP configured: %s - kernel will automatically recognize this as local IP", tunAddress)

	// Initialize lock optimization based on config
	useShardedLocks := cfg.VPN.EnableShardedLocks
	shardCount := cfg.VPN.ShardCount
	if shardCount <= 0 {
		shardCount = 16 // Default to 16 shards
	}

	server := &VPNServer{
		config:          cfg,
		routeMgr:        routeMgr,
		policyMgr:       policyMgr,
		ebpfProgram:     ebpfProg,
		tcProgram:       tcProg, // eBPF TC program for NAT (may be nil if fallback to nftables)
		forwarder:       forwarder,
		ipPool:          ipPool,
		tunDevice:       tunDevice,
		xdpSocket:       nil,
		useShardedLocks: useShardedLocks,
		egressIP:        egressIPForServer, // Store egress IP (for reference)
	}

	// Initialize client storage based on lock optimization setting
	if useShardedLocks {
		server.shardedClients = NewShardedClientMap(shardCount)
		server.shardedVPNIP = NewShardedVPNIPMap(shardCount)
		log.Printf("Sharded locks enabled with %d shards for better concurrency", shardCount)
	} else {
		server.clients = make(map[uint]*VPNClient)
		server.vpnIPToUser = make(map[string]uint)
		log.Printf("Using standard locks (sharded locks disabled)")
	}

	// Initialize compression manager
	compressionType := CompressionType(cfg.VPN.CompressionType)
	if compressionType == "" {
		compressionType = CompressionNone
	}
	if cfg.VPN.EnableCompression && compressionType != CompressionNone {
		server.CompressionMgr = NewCompressionManager(compressionType)
		log.Printf("Traffic compression enabled: %s", compressionType)
	} else {
		server.CompressionMgr = NewCompressionManager(CompressionNone)
	}

	// Initialize packet buffer pool
	server.packetPool = &sync.Pool{
		New: func() interface{} {
			// Default buffer size: MTU + IP header + CSTP header
			return make([]byte, 1600)
		},
	}

	// Initialize bruteforce protection if enabled
	if cfg.VPN.EnableBruteforceProtection {
		maxAttempts := cfg.VPN.MaxLoginAttempts
		if maxAttempts <= 0 {
			maxAttempts = 5 // Default
		}
		lockoutDuration := time.Duration(cfg.VPN.LoginLockoutDuration) * time.Second
		if lockoutDuration <= 0 {
			lockoutDuration = 15 * time.Minute // Default 15 minutes
		}
		windowDuration := time.Duration(cfg.VPN.LoginAttemptWindow) * time.Second
		if windowDuration <= 0 {
			windowDuration = 5 * time.Minute // Default 5 minutes
		}

		// Create bruteforce protection instance
		bruteforceProtection := security.NewBruteforceProtection(maxAttempts, lockoutDuration, windowDuration)
		server.bruteforceProtection = bruteforceProtection

		// Set eBPF program if available (for kernel-level blocking)
		if ebpfProg != nil {
			bruteforceProtection.SetEBPFProgram(ebpfProg)
			log.Printf("Bruteforce protection initialized with eBPF kernel-level blocking support")
		} else {
			log.Printf("Bruteforce protection initialized (eBPF not available, using user-space only)")
		}
	}

	// Try to initialize AF_XDP socket for zero-copy (experimental)
	if cfg.VPN.EnableAFXDP {
		log.Printf("Attempting to initialize AF_XDP zero-copy optimization...")
		if cfg.VPN.EBPFInterfaceName != "" {
			xdpSock, err := NewXDPSocket(cfg.VPN.EBPFInterfaceName, cfg.VPN.AFXDPQueueID)
			if err != nil {
				log.Printf("Warning: Failed to create AF_XDP socket: %v", err)
				log.Printf("Falling back to TUN device")
			} else {
				// Enable the socket
				if err := xdpSock.Enable(); err != nil {
					log.Printf("Warning: Failed to enable AF_XDP socket: %v", err)
					xdpSock.Close()
					log.Printf("Falling back to TUN device")
				} else {
					server.xdpSocket = xdpSock
					log.Printf("✅ AF_XDP socket created and enabled for interface %s (queue %d)",
						cfg.VPN.EBPFInterfaceName, cfg.VPN.AFXDPQueueID)
					log.Printf("Note: AF_XDP provides zero-copy packet processing")
					log.Printf("Note: Ensure eBPF XDP program redirects packets to AF_XDP socket")
				}
			}
		} else {
			log.Printf("Warning: AF_XDP enabled but EBPFInterfaceName not set, falling back to TUN")
		}
	}

	// Start packet listener (AF_XDP if enabled, otherwise TUN)
	// Configure log sampling rate
	if cfg.VPN.LogSampleRate > 0 {
		SetLogSampleRate(cfg.VPN.LogSampleRate)
		log.Printf("Log sampling enabled: logging every %d packets", cfg.VPN.LogSampleRate)
	}

	// Start eBPF audit logger if eBPF is enabled
	// This will be handled by a build-tagged function
	startEBPFAuditLoggerIfEnabled(ebpfProg)

	// If AF_XDP is enabled and working, use it; otherwise fallback to TUN
	// Note: listenAFXDP is only available on Linux (via build tag)
	if server.xdpSocket != nil && server.xdpSocket.IsEnabled() {
		if listenAFXDPFunc := getAFXDPListener(); listenAFXDPFunc != nil {
			log.Printf("Starting AF_XDP packet listener (zero-copy mode)")
			go listenAFXDPFunc(server, server.xdpSocket)
		} else {
			log.Printf("Warning: AF_XDP enabled but listener not available on this platform, falling back to TUN")
		}
	}

	if tunDevice != nil && (server.xdpSocket == nil || !server.xdpSocket.IsEnabled()) {
		// Use batch processing if enabled (better performance)
		// Note: Batch processing requires Linux (uses epoll)
		if cfg.VPN.EnableBatchProcessing {
			// Try batch processing (Linux only)
			if batchFunc := getBatchListener(); batchFunc != nil {
				go batchFunc(server, tunDevice)
				log.Println("Global TUN device batch listener started (optimized)")
			} else {
				log.Println("Batch processing not available on this platform, using regular listener")
				go server.listenTUNDevice(tunDevice)
				log.Println("Global TUN device listener started")
			}
		} else {
			go server.listenTUNDevice(tunDevice)
			log.Println("Global TUN device listener started")
		}
	}

	// Start packet receiver if forwarder is enabled
	if forwarder != nil && forwarder.enabled {
		// Create a function to get VPN IP to user mapping
		getVPNIPUser := func(ip string) (uint, bool) {
			return server.getVPNIPUser(ip)
		}
		forwarder.StartPacketReceiver(ipNet, getVPNIPUser, func(userID uint, packet []byte) {
			// Handle incoming packets from network
			// Forward to appropriate client
			client, exists := server.getClient(userID)

			if exists && client.Connected {
				if err := forwarder.ForwardToClient(userID, packet, client.Conn); err != nil {
					log.Printf("Failed to forward packet to client %d: %v", userID, err)
				}
			}
		})
	}

	return server, nil
}

// GetBruteforceProtection returns the bruteforce protection instance
// Returns nil if not enabled or not initialized
func (s *VPNServer) GetBruteforceProtection() interface{} {
	return s.bruteforceProtection
}

// GetEBPFProgram returns the eBPF XDP program
func (s *VPNServer) GetEBPFProgram() *ebpf.XDPProgram {
	return s.ebpfProgram
}

// GetConfig returns the VPN server configuration
func (s *VPNServer) GetConfig() *config.Config {
	return s.config
}

// GetPacketBuffer retrieves a buffer from the packet pool
func (s *VPNServer) GetPacketBuffer() []byte {
	return s.packetPool.Get().([]byte)
}

// PutPacketBuffer returns a buffer to the packet pool
func (s *VPNServer) PutPacketBuffer(buf []byte) {
	// Clear buffer before putting back to pool
	for i := range buf {
		buf[i] = 0
	}
	s.packetPool.Put(buf)
}

// BuildCSTPPacket builds a CSTP packet using the packet pool
// Server-to-client packets always use BIG-ENDIAN for length field at byte 4-5 (per OpenConnect protocol spec)
func (s *VPNServer) BuildCSTPPacket(payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("payload cannot be empty")
	}

	// Per OpenConnect spec draft-mavrogiannopoulos-openconnect-02:
	// Byte 0-2: 'S', 'T', 'F' (fixed)
	// Byte 3: 0x01 (fixed)
	// Byte 4-5: Length (BIG-ENDIAN) - length of payload that follows header (NOT including header)
	// Byte 6: Payload type (0x00 for DATA)
	// Byte 7: 0x00 (fixed)
	// Byte 8+: Payload
	// Calculate required packet size: STF(3) + Header(5) + Payload
	packetSize := 3 + 5 + len(payload)

	// Get buffer from pool
	buf := s.GetPacketBuffer()

	// Ensure buffer is large enough
	if len(buf) < packetSize {
		// If buffer is too small, allocate a new one (should rarely happen)
		s.PutPacketBuffer(buf)
		buf = make([]byte, packetSize)
	}

	// Build CSTP packet in buffer
	packet := buf[:packetSize]

	// Add "STF" prefix
	packet[0] = 'S'
	packet[1] = 'T'
	packet[2] = 'F'

	// CSTP header starts after STF prefix (at offset 3)
	packet[3] = 0x01 // Version (fixed to 0x01)
	// Byte 4-5: Length (BIG-ENDIAN) - payload length only, NOT including header
	payloadLen := uint16(len(payload))
	binary.BigEndian.PutUint16(packet[4:6], payloadLen)
	// Byte 6: Payload type (0x00 for DATA)
	packet[6] = 0x00
	// Byte 7: Reserved (fixed to 0x00)
	packet[7] = 0x00

	// Copy payload after header (starts at byte 8)
	copy(packet[8:], payload)

	return packet, nil
}


// GetPolicyManager returns the policy manager
func (s *VPNServer) GetPolicyManager() *policy.Manager {
	return s.policyMgr
}

// GetRouteManager 已废弃
func (s *VPNServer) GetRouteManager() *RouteManager {
	return s.routeMgr
}

// GetForwarder returns the packet forwarder
func (s *VPNServer) GetForwarder() *PacketForwarder {
	return s.forwarder
}

// GetTUNDevice returns the shared TUN device instance
func (s *VPNServer) GetTUNDevice() *TUNDevice {
	return s.tunDevice
}

// GetVPNGatewayIP returns the VPN gateway IP address
// Priority: TUN device actual IP > configured gateway IP (usually .1)
// This supports multi-server horizontal scaling
func (s *VPNServer) GetVPNGatewayIP() net.IP {
	// Try to get TUN device IP first (supports multi-server)
	if s.tunDevice != nil {
		if tunIP, err := s.tunDevice.GetIP(); err == nil {
			return tunIP
		}
	}

	// Fallback to configured gateway IP (usually .1)
	if s.config != nil {
		_, vpnNet, err := net.ParseCIDR(s.config.VPN.Network)
		if err == nil {
			gatewayIP := make(net.IP, len(vpnNet.IP))
			copy(gatewayIP, vpnNet.IP)
			gatewayIP[len(gatewayIP)-1] = 1
			return gatewayIP
		}
	}

	return nil
}

// GetIPPool returns the IP pool
func (s *VPNServer) GetIPPool() *IPPool {
	return s.ipPool
}

// registerDefaultPolicies registers default routing policies
func registerDefaultPolicies(policyMgr *policy.Manager, cfg *config.Config) error {
	// 允许VPN网段内的通信
	vpnNetworkHook := policy.NewACLHook(
		"vpn_network_allow",
		policy.HookPreRouting,
		10,
		policy.ActionAllow,
	)

	// 添加VPN网段
	if _, ipNet, err := net.ParseCIDR(cfg.VPN.Network); err == nil {
		vpnNetworkHook.AddDestinationNetwork(ipNet)
		vpnNetworkHook.AddSourceNetwork(ipNet)
	}

	if err := policyMgr.RegisterHook(vpnNetworkHook); err != nil {
		return fmt.Errorf("failed to register VPN network hook: %w", err)
	}

	log.Printf("Registered default VPN network policy")
	return nil
}

// CreatePolicyHooks creates policy hooks for a user
func (s *VPNServer) CreatePolicyHooks(user *models.User) error {
	if s.policyMgr == nil {
		return nil
	}
	return policy.CreatePolicyHooks(s.policyMgr, user)
}

// RemovePolicyHooks removes policy hooks for a user
func (s *VPNServer) RemovePolicyHooks(userID uint) error {
	if s.policyMgr == nil {
		return nil
	}
	return policy.RemovePolicyHooks(s.policyMgr, userID)
}

// initializeEBPFRateLimitConfig initializes eBPF rate limit and DDoS protection configuration
func initializeEBPFRateLimitConfig(ebpfProg *ebpf.XDPProgram, cfg *config.Config) error {
	if ebpfProg == nil {
		return fmt.Errorf("eBPF program not loaded")
	}

	rateLimitConfig := ebpf.RateLimitConfig{
		EnableRateLimit:      boolToUint8(cfg.VPN.EnableRateLimit),
		RateLimitPerIP:       uint64(cfg.VPN.RateLimitPerIP),
		EnableDDoSProtection: boolToUint8(cfg.VPN.EnableDDoSProtection),
		DDoSThreshold:        uint64(cfg.VPN.DDoSThreshold),
		DDoSBlockDuration:    uint64(cfg.VPN.DDoSBlockDuration) * 1000000000, // Convert seconds to nanoseconds
	}

	if err := ebpfProg.UpdateRateLimitConfig(rateLimitConfig); err != nil {
		return fmt.Errorf("failed to update eBPF rate limit config: %w", err)
	}

	return nil
}

// boolToUint8 converts bool to uint8 (0 or 1)
func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// loadEBPFTCNAT loads eBPF TC program for NAT masquerading
// Returns the TC program instance or error if loading fails
func loadEBPFTCNAT(ifName string, publicIP net.IP, vpnNetwork string) (interface{}, error) {
	// Use build tag to conditionally compile TC loader
	// This function will call the actual loader if available
	return loadEBPFTCNATImpl(ifName, publicIP, vpnNetwork)
}

// initializePublicIP automatically detects and sets the egress interface IP for NAT masquerading
// This is called after eBPF program is loaded to configure the public IP used for NAT
func initializePublicIP(ebpfProg *ebpf.XDPProgram) error {
	if ebpfProg == nil {
		return fmt.Errorf("eBPF program is nil")
	}

	// Try to automatically detect the egress interface IP
	publicIP, err := GetEgressInterfaceIP()
	if err != nil {
		log.Printf("Warning: Failed to auto-detect egress interface IP: %v", err)
		log.Printf("Attempting to use interface IP from TUN device or other methods...")

		// Fallback: try to get IP from any non-loopback interface
		ifaces, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("failed to list interfaces: %w", err)
		}

		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}

			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}

				if ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() && !ipNet.IP.IsLinkLocalUnicast() {
					publicIP = ipNet.IP
					log.Printf("Using IP from interface %s: %s", iface.Name, publicIP.String())
					break
				}
			}

			if publicIP != nil {
				break
			}
		}
	}

	if publicIP == nil {
		log.Printf("Warning: Failed to detect public IP address. eBPF NAT will not work.")
		log.Printf("Please configure egress interface IP manually or ensure interface has an IP address.")
		return fmt.Errorf("failed to detect egress interface IP for eBPF NAT")
	}

	// Set egress IP in eBPF map for NAT masquerading (for ingress traffic)
	if err := ebpfProg.SetPublicIP(publicIP); err != nil {
		log.Printf("Warning: Failed to set egress IP in eBPF map: %v", err)
		log.Printf("eBPF NAT may not work correctly. Falling back to kernel NAT (requires nftables).")
		return err
	}

	// Store egress IP in VPNServer for user-space NAT (for egress traffic from TUN)
	// Note: We need to find the VPNServer instance to store the IP
	// This will be set after server creation
	log.Printf("✅ eBPF NAT: Public IP configured: %s", publicIP.String())
	log.Printf("Note: User-space NAT will be used for packets from VPN clients to external networks")
	return nil
}

// RegisterClient registers a VPN client
func (s *VPNServer) RegisterClient(userID uint, client *VPNClient) {
	// Set WriteChan buffer size from config if not already set
	if cap(client.WriteChan) == 0 {
		bufferSize := s.config.VPN.WriteChanBufferSize
		if bufferSize <= 0 {
			bufferSize = 100 // Default
		}
		client.WriteChan = make(chan []byte, bufferSize)
	}

	// Set server reference for config access
	client.server = s

	s.setClient(userID, client)
	vpnIPStr := client.IP.String()
	s.setVPNIPUser(vpnIPStr, userID)
	log.Printf("Registered VPN client: userID=%d, IP=%s (stored as '%s')", userID, client.IP.String(), vpnIPStr)

	// Register with packet forwarder
	if s.forwarder != nil {
		clientAddr := &net.IPAddr{IP: client.IP}
		s.forwarder.RegisterClient(userID, client.IP, clientAddr)
	}

	// Register VPN client IP in eBPF maps for NAT masquerading
	// Get client's real IP from connection
	var clientRealIP net.IP
	if client.Conn != nil {
		if remoteAddr := client.Conn.RemoteAddr(); remoteAddr != nil {
			host, _, err := net.SplitHostPort(remoteAddr.String())
			if err == nil {
				clientRealIP = net.ParseIP(host)
			}
		}
	}

	// If we couldn't get real IP from connection, use VPN IP as fallback
	// (eBPF map needs a value, even if it's the same as VPN IP)
	// For NAT purposes, we can use VPN IP itself as the "real IP"
	// The important thing is that eBPF can identify this as a VPN client
	if clientRealIP == nil {
		clientRealIP = client.IP
	}

	// Register in XDP program (for ingress traffic)
	if s.ebpfProgram != nil {
		if err := s.ebpfProgram.AddVPNClient(client.IP, clientRealIP); err != nil {
			log.Printf("Warning: Failed to register VPN client in eBPF XDP map: %v", err)
			log.Printf("eBPF XDP NAT may not work for client %s", client.IP.String())
		} else {
			log.Printf("✅ Registered VPN client in eBPF XDP map: VPN IP=%s, Real IP=%s", client.IP.String(), clientRealIP.String())
		}
	}

	// Register in TC program (for egress NAT) if available
	if err := s.tcProgramAddVPNClient(client.IP, clientRealIP); err != nil {
		log.Printf("Warning: Failed to register VPN client in eBPF TC map: %v", err)
	} else if s.tcProgram != nil {
		log.Printf("✅ Registered VPN client in eBPF TC map: VPN IP=%s, Real IP=%s", client.IP.String(), clientRealIP.String())
	}
}

// GetClient exposes client info for administrative queries
func (s *VPNServer) GetClient(userID uint) (*VPNClient, bool) {
	return s.getClient(userID)
}

// UnregisterClient unregisters a VPN client
func (s *VPNServer) UnregisterClient(userID uint, vpnIP string) {
	client, exists := s.getClient(userID)
	if exists {
		// Signal write goroutine to stop
		select {
		case <-client.WriteClose:
			// Already closed
		default:
			close(client.WriteClose)
		}
		// Close write channel (with protection against double-close panic)
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Channel already closed, ignore panic
					log.Printf("Warning: WriteChan already closed for client %d", userID)
				}
			}()
			close(client.WriteChan)
		}()

		// Remove VPN client from eBPF maps
		if client.IP != nil {
			// Remove from XDP program
			if s.ebpfProgram != nil {
				if err := s.ebpfProgram.RemoveVPNClient(client.IP); err != nil {
					log.Printf("Warning: Failed to remove VPN client from eBPF XDP map: %v", err)
				} else {
					log.Printf("Removed VPN client from eBPF XDP map: VPN IP=%s", client.IP.String())
				}
			}

			// Remove from TC program (for egress NAT) if available
			if err := s.tcProgramRemoveVPNClient(client.IP); err != nil {
				log.Printf("Warning: Failed to remove VPN client from eBPF TC map: %v", err)
			} else if s.tcProgram != nil {
				log.Printf("Removed VPN client from eBPF TC map: VPN IP=%s", client.IP.String())
			}
		}
	}
	s.deleteClient(userID)
	s.deleteVPNIPUser(vpnIP)

	if s.forwarder != nil {
		s.forwarder.UnregisterClient(userID)
	}
}

func (s *VPNServer) Stop() error {
	// Stop hook synchronization
	if s.policyMgr != nil {
		s.policyMgr.StopHookSync()
	}
	// Close all clients
	clients := s.getAllClients()
	for _, client := range clients {
		client.Conn.Close()
		client.User.Connected = false
		database.DB.Save(client.User)
	}

	// Close eBPF programs if loaded
	if s.ebpfProgram != nil {
		if err := s.ebpfProgram.Close(); err != nil {
			log.Printf("Error closing eBPF XDP program: %v", err)
		}
	}

	// Close TC program if loaded
	if err := s.tcProgramClose(); err != nil {
		log.Printf("Error closing eBPF TC program: %v", err)
	}

	// Close packet forwarder
	if s.forwarder != nil {
		if err := s.forwarder.Close(); err != nil {
			log.Printf("Error closing packet forwarder: %v", err)
		}
	}

	return nil
}

// ============================================================================
// Client and VPN IP Map Access Methods
// ============================================================================

// getClient retrieves a client by user ID (works with both sharded and non-sharded modes)
func (s *VPNServer) getClient(userID uint) (*VPNClient, bool) {
	if s.useShardedLocks {
		return s.shardedClients.Get(userID)
	}
	s.clientsLock.RLock()
	defer s.clientsLock.RUnlock()
	client, exists := s.clients[userID]
	return client, exists
}

// setClient stores a client by user ID
func (s *VPNServer) setClient(userID uint, client *VPNClient) {
	if s.useShardedLocks {
		s.shardedClients.Set(userID, client)
		return
	}
	s.clientsLock.Lock()
	defer s.clientsLock.Unlock()
	s.clients[userID] = client
}

// deleteClient removes a client by user ID
func (s *VPNServer) deleteClient(userID uint) {
	if s.useShardedLocks {
		s.shardedClients.Delete(userID)
		return
	}
	s.clientsLock.Lock()
	defer s.clientsLock.Unlock()
	delete(s.clients, userID)
}

// getVPNIPUser retrieves a user ID by VPN IP
func (s *VPNServer) getVPNIPUser(ip string) (uint, bool) {
	if s.useShardedLocks {
		return s.shardedVPNIP.Get(ip)
	}
	s.vpnIPLock.RLock()
	defer s.vpnIPLock.RUnlock()
	userID, exists := s.vpnIPToUser[ip]
	return userID, exists
}

// setVPNIPUser stores a VPN IP to user ID mapping
func (s *VPNServer) setVPNIPUser(ip string, userID uint) {
	if s.useShardedLocks {
		s.shardedVPNIP.Set(ip, userID)
		return
	}
	s.vpnIPLock.Lock()
	defer s.vpnIPLock.Unlock()
	s.vpnIPToUser[ip] = userID
}

// deleteVPNIPUser removes a VPN IP mapping
func (s *VPNServer) deleteVPNIPUser(ip string) {
	if s.useShardedLocks {
		s.shardedVPNIP.Delete(ip)
		return
	}
	s.vpnIPLock.Lock()
	defer s.vpnIPLock.Unlock()
	delete(s.vpnIPToUser, ip)
}

// GetVPNIPUser returns user ID by VPN IP (public wrapper).
func (s *VPNServer) GetVPNIPUser(ip string) (uint, bool) {
	return s.getVPNIPUser(ip)
}

// AllocateVPNIP allocates an IP from the shared pool.
func (s *VPNServer) AllocateVPNIP() (net.IP, error) {
	if s.ipPool == nil {
		return nil, fmt.Errorf("ip pool not initialized")
	}
	return s.ipPool.Allocate()
}

// ReleaseVPNIP releases an IP back to the shared pool.
func (s *VPNServer) ReleaseVPNIP(ip net.IP) {
	if s.ipPool == nil || ip == nil {
		return
	}
	s.ipPool.Release(ip)
}

// ReserveVPNIP marks an IP as used in the shared pool (e.g., when reusing existing assignment).
func (s *VPNServer) ReserveVPNIP(ip net.IP) {
	if s.ipPool == nil || ip == nil {
		return
	}
	s.ipPool.Reserve(ip)
}

// getAllClients returns all clients (for shutdown, etc.)
// This is expensive with sharded locks as it needs to lock all shards
func (s *VPNServer) getAllClients() []*VPNClient {
	var clients []*VPNClient

	if s.useShardedLocks {
		s.shardedClients.Range(func(userID uint, client *VPNClient) bool {
			clients = append(clients, client)
			return true
		})
	} else {
		s.clientsLock.RLock()
		for _, client := range s.clients {
			clients = append(clients, client)
		}
		s.clientsLock.RUnlock()
	}

	return clients
}

// logAllRegisteredIPs logs all registered VPN IPs for debugging
func (s *VPNServer) logAllRegisteredIPs() {
	if s.useShardedLocks {
		// For sharded locks, iterate through all clients to get their IPs
		log.Printf("Registered VPN IPs (sharded mode):")
		count := 0
		s.shardedClients.Range(func(userID uint, client *VPNClient) bool {
			if client != nil {
				log.Printf("  UserID: %d -> IP: '%s'", userID, client.IP.String())
				count++
			}
			return true
		})
		if count == 0 {
			log.Printf("  (no clients registered)")
		}
	} else {
		s.vpnIPLock.RLock()
		log.Printf("Registered VPN IPs (standard mode):")
		if len(s.vpnIPToUser) == 0 {
			log.Printf("  (no IPs registered)")
		} else {
			for ip, userID := range s.vpnIPToUser {
				log.Printf("  IP: '%s' -> UserID: %d", ip, userID)
			}
		}
		s.vpnIPLock.RUnlock()

		// Also log from clients map
		s.clientsLock.RLock()
		log.Printf("Registered clients (standard mode):")
		if len(s.clients) == 0 {
			log.Printf("  (no clients)")
		} else {
			for userID, client := range s.clients {
				if client != nil {
					log.Printf("  UserID: %d -> IP: '%s'", userID, client.IP.String())
				}
			}
		}
		s.clientsLock.RUnlock()
	}
}

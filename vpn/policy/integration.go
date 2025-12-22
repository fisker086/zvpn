package policy

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/database"
	"github.com/fisker/zvpn/models"
	"github.com/fisker/zvpn/vpn/ebpf"
)

// IntegrateWithVPN integrates policy manager with VPN server
func IntegrateWithVPN(cfg *config.Config, xdpProgram *ebpf.XDPProgram) (*Manager, error) {
	manager := NewManager()

	// Set eBPF loader if XDP program is available
	if xdpProgram != nil {
		ebpfLoader := NewEBPFLoader(xdpProgram)
		manager.SetEBPFLoader(ebpfLoader)
		log.Println("Policy manager integrated with eBPF XDP")
	}

	// Load policies from database
	if err := loadPoliciesFromDB(manager); err != nil {
		log.Printf("Warning: Failed to load policies from database: %v", err)
	}

	// Load hooks from database
	if err := loadHooksFromDB(manager); err != nil {
		log.Printf("Warning: Failed to load hooks from database: %v", err)
	}

	// Start periodic flush for audit logs
	startAuditLogFlusher()

	return manager, nil
}

// startAuditLogFlusher starts a goroutine to periodically flush audit logs
func startAuditLogFlusher() {
	go func() {
		ticker := time.NewTicker(10 * time.Second) // Flush every 10 seconds
		defer ticker.Stop()

		for range ticker.C {
			auditLogger := GetAuditLogger()
			if err := auditLogger.Flush(); err != nil {
				log.Printf("Failed to flush audit logs: %v", err)
			}
		}
	}()
	log.Println("Audit log flusher started (interval: 10s)")
}

// loadPoliciesFromDB loads all policies from database and creates hooks
func loadPoliciesFromDB(manager *Manager) error {
	var policies []models.Policy
	if err := database.DB.Preload("AllowedNetworks").Preload("Routes").Find(&policies).Error; err != nil {
		return err
	}

	for _, policy := range policies {
		if err := manager.LoadPolicyFromDB(&policy); err != nil {
			log.Printf("Failed to load policy %d: %v", policy.ID, err)
			continue
		}
	}

	return nil
}

// CreatePolicyHooks creates hooks for a user's policy
func CreatePolicyHooks(manager *Manager, user *models.User) error {
	if user.PolicyID == 0 {
		return nil
	}

	var policy models.Policy
	if err := database.DB.Preload("AllowedNetworks").Preload("Routes").First(&policy, user.PolicyID).Error; err != nil {
		return err
	}

	// Create ACL hooks for allowed networks
	for _, allowedNet := range policy.AllowedNetworks {
		_, ipNet, err := net.ParseCIDR(allowedNet.Network)
		if err != nil {
			continue
		}

		hookName := fmt.Sprintf("user_%d_policy_%d_network_%s", user.ID, policy.ID, allowedNet.Network)
		hook := NewACLHook(
			hookName,
			HookPreRouting,
			int(policy.ID)*100+int(user.ID), // Priority based on policy and user
			ActionAllow,
		)
		hook.AddDestinationNetwork(ipNet)

		if err := manager.RegisterHook(hook); err != nil {
			log.Printf("Failed to register hook for user %d: %v", user.ID, err)
		}
	}

	return nil
}

// RemovePolicyHooks removes hooks for a user
func RemovePolicyHooks(manager *Manager, userID uint) error {
	// Find and remove all hooks for this user
	allHooks := manager.GetRegistry().GetAllHooks()
	for hookPoint, hooks := range allHooks {
		for _, hook := range hooks {
			hookName := hook.Name()
			// Check if hook belongs to this user
			if len(hookName) > 5 && hookName[:5] == fmt.Sprintf("user_%d_", userID) {
				if err := manager.UnregisterHook(hookName, hookPoint); err != nil {
					log.Printf("Failed to unregister hook %s: %v", hookName, err)
				}
			}
		}
	}
	return nil
}

// loadHooksFromDB loads all hooks from database and registers them
func loadHooksFromDB(manager *Manager) error {
	var hooks []models.Hook
	if err := database.DB.Find(&hooks).Error; err != nil {
		return err
	}

	for _, hookModel := range hooks {
		if !hookModel.Enabled {
			continue // Skip disabled hooks
		}

		hook := convertModelHookToPolicyHook(&hookModel)
		if hook == nil {
			log.Printf("Failed to convert hook %s to policy hook", hookModel.ID)
			continue
		}

		if err := manager.RegisterHook(hook); err != nil {
			log.Printf("Failed to register hook %s: %v", hookModel.ID, err)
			continue
		}

		log.Printf("Loaded hook %s (%s) at %s", hookModel.Name, hookModel.ID, hookModel.HookPoint)
	}

	return nil
}

// convertModelHookToPolicyHook uses the shared converter
func convertModelHookToPolicyHook(hookModel *models.Hook) Hook {
	return ConvertModelHookToPolicyHook(hookModel)
}

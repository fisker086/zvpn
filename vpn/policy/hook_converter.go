package policy

import (
	"net"

	"github.com/fisker/zvpn/models"
)

// ConvertModelHookToPolicyHook converts a models.Hook to a policy.Hook
// This is a shared function used by both handlers and sync managers
func ConvertModelHookToPolicyHook(hookModel *models.Hook) Hook {
	hookPoint := HookPoint(hookModel.HookPoint)

	switch hookModel.Type {
	case models.ACLHook:
		return convertToACLHook(hookModel, hookPoint)
	case models.PortFilterHook:
		return convertToPortFilterHook(hookModel, hookPoint)
	case models.UserPolicyHook:
		return convertToUserPolicyHook(hookModel, hookPoint)
	default:
		// For custom hooks, create a generic ACL hook
		return convertToACLHook(hookModel, hookPoint)
	}
}

// convertToACLHook converts a models.Hook to an ACLHook
func convertToACLHook(hookModel *models.Hook, hookPoint HookPoint) Hook {
	action := convertAction(hookModel.Rules)
	hook := NewACLHook(hookModel.ID, hookPoint, hookModel.Priority, action)

	// Process rules
	for _, rule := range hookModel.Rules {
		// Add source IPs/networks
		for _, ipStr := range rule.SourceIPs {
			if ip := net.ParseIP(ipStr); ip != nil {
				hook.AddSourceIP(ip)
			}
		}
		for _, netStr := range rule.SourceNetworks {
			if _, ipNet, err := net.ParseCIDR(netStr); err == nil {
				hook.AddSourceNetwork(ipNet)
			}
		}

		// Add destination IPs/networks
		for _, ipStr := range rule.DestinationIPs {
			if ip := net.ParseIP(ipStr); ip != nil {
				hook.AddDestinationIP(ip)
			}
		}
		for _, netStr := range rule.DestinationNetworks {
			if _, ipNet, err := net.ParseCIDR(netStr); err == nil {
				hook.AddDestinationNetwork(ipNet)
			}
		}
		
		// Add protocols
		for _, protocol := range rule.Protocols {
			hook.AddProtocol(protocol)
		}
		
		// Note: ACLHook doesn't support ports directly
		// Port filtering should be done via PortFilterHook
	}

	return hook
}

// convertToPortFilterHook converts a models.Hook to a PortFilterHook
func convertToPortFilterHook(hookModel *models.Hook, hookPoint HookPoint) Hook {
	action := convertAction(hookModel.Rules)
	hook := NewPortFilterHook(hookModel.ID, hookPoint, hookModel.Priority, action)

	// Process rules
	for _, rule := range hookModel.Rules {
		// Add ports
		for _, port := range rule.DestinationPorts {
			hook.AddPort(uint16(port))
		}
		for _, port := range rule.SourcePorts {
			hook.AddPort(uint16(port))
		}

		// Add port ranges
		for _, portRange := range rule.PortRanges {
			hook.AddPortRange(uint16(portRange.Start), uint16(portRange.End))
		}
		
		// Add protocols
		for _, protocol := range rule.Protocols {
			hook.AddProtocol(protocol)
		}
	}

	return hook
}

// convertToUserPolicyHook converts a models.Hook to a UserPolicyHook
func convertToUserPolicyHook(hookModel *models.Hook, hookPoint HookPoint) Hook {
	hook := NewUserPolicyHook(hookModel.ID, hookPoint, hookModel.Priority)

	// Process rules - 直接使用用户ID，无需查询数据库
	for _, rule := range hookModel.Rules {
		action := convertAction([]models.HookRule{rule})
		for _, userID := range rule.UserIDs {
			if action == ActionAllow {
				hook.AllowUser(userID)
			} else {
				hook.DenyUser(userID)
			}
		}
	}

	return hook
}

// convertAction converts models.PolicyAction to policy.Action
func convertAction(rules []models.HookRule) Action {
	if len(rules) == 0 {
		return ActionAllow
	}

	switch rules[0].Action {
	case models.Allow:
		return ActionAllow
	case models.Deny:
		return ActionDeny
	case models.Redirect:
		return ActionRedirect
	case models.Log:
		return ActionLog
	default:
		return ActionAllow
	}
}


package vpn

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

// calculateIPChecksum calculates the IP header checksum
func calculateIPChecksum(header []byte) uint16 {
	if len(header) < 20 {
		return 0
	}

	// IP header length in 4-byte units
	ihl := int(header[0] & 0x0F)
	if ihl < 5 || len(header) < ihl*4 {
		return 0
	}

	var sum uint32
	// Sum all 16-bit words in IP header
	for i := 0; i < ihl*2; i++ {
		if i*2+1 < len(header) {
			sum += uint32(binary.BigEndian.Uint16(header[i*2 : i*2+2]))
		}
	}

	// Fold 32-bit sum to 16-bit
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	// Take one's complement
	return ^uint16(sum)
}

// PerformUserSpaceNAT performs NAT masquerading in user space
// Modifies the packet in place: changes source IP and recalculates checksums
func (s *VPNServer) PerformUserSpaceNAT(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}

	// Check if it's IPv4
	if packet[0]>>4 != 4 {
		return false
	}

	// Get egress IP
	s.egressIPLock.RLock()
	egressIP := s.egressIP
	s.egressIPLock.RUnlock()

	if egressIP == nil {
		return false // No egress IP configured
	}

	// Extract source and destination IPs
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	// Get VPN network
	_, vpnNet, err := net.ParseCIDR(s.config.VPN.Network)
	if err != nil {
		return false
	}

	// Only perform NAT if source is VPN client and destination is external
	if !vpnNet.Contains(srcIP) || vpnNet.Contains(dstIP) {
		return false // Not a VPN client to external network packet
	}

	// Change source IP to egress IP
	copy(packet[12:16], egressIP.To4())

	// Recalculate IP checksum
	packet[10] = 0
	packet[11] = 0
	checksum := calculateIPChecksum(packet[:20])
	binary.BigEndian.PutUint16(packet[10:12], checksum)

	// Reset transport layer checksum (let kernel recalculate)
	protocol := packet[9]
	ipHeaderLen := int((packet[0] & 0x0F) * 4)

	if protocol == 6 { // TCP
		if len(packet) >= ipHeaderLen+16 {
			packet[ipHeaderLen+16] = 0
			packet[ipHeaderLen+17] = 0
		}
	} else if protocol == 17 { // UDP
		if len(packet) >= ipHeaderLen+6 {
			packet[ipHeaderLen+6] = 0
			packet[ipHeaderLen+7] = 0
		}
	} else if protocol == 1 { // ICMP
		if len(packet) >= ipHeaderLen+2 {
			packet[ipHeaderLen+2] = 0
			packet[ipHeaderLen+3] = 0
		}
	}

	return true // NAT performed
}

// checkNATRuleExists checks if NAT rule already exists (set by docker-entrypoint.sh)
func checkNATRuleExists(vpnNetwork, egressInterface string) bool {
	// Check iptables rule
	if ipt, err := iptables.New(); err == nil {
		natRule := []string{"-s", vpnNetwork, "-o", egressInterface, "-j", "MASQUERADE"}
		if exists, err := ipt.Exists("nat", "POSTROUTING", natRule...); err == nil && exists {
			return true
		}
	}

	// Check nftables rule (if nft command exists)
	if _, err := exec.LookPath("nft"); err == nil {
		cmd := exec.Command("nft", "list", "ruleset")
		if output, err := cmd.CombinedOutput(); err == nil {
			outputStr := string(output)
			// Check if rule exists: contains VPN network, egress interface, and masquerade
			if strings.Contains(outputStr, vpnNetwork) && strings.Contains(outputStr, egressInterface) && strings.Contains(outputStr, "masquerade") {
				return true
			}
		}
	}

	return false
}

// setupIPTablesNAT configures NAT masquerading using nftables (preferred) or iptables (fallback)
// This allows VPN clients to access external networks by masquerading their IP addresses
// Note: This is a fallback mechanism. The docker-entrypoint.sh script should have already
// set up the rules. If NAT rule exists, we skip adding it but still perform other checks
// (kernel modules, FORWARD rules, verification, etc.)
func setupIPTablesNAT(vpnNetwork, egressInterface string) error {
	// Check if NAT rule already exists (set by docker-entrypoint.sh)
	natRuleExists := checkNATRuleExists(vpnNetwork, egressInterface)

	if natRuleExists {
		log.Printf("NAT: ✅ NAT masquerade 规则已存在（docker-entrypoint.sh 已设置）")
		log.Printf("NAT: 继续执行其他必要检查（内核模块、FORWARD 规则、验证等）...")
	} else {
		log.Printf("NAT: 未检测到 NAT 规则，开始完整配置（docker-entrypoint.sh 可能未执行或失败）...")
	}

	// Try nftables first (modern Linux systems)
	err := setupNftablesNAT(vpnNetwork, egressInterface, natRuleExists)
	if err == nil {
		if !natRuleExists {
			log.Printf("NAT: ✅ NAT 规则已配置（使用 nftables，作为兜底）")
		} else {
			log.Printf("NAT: ✅ nftables NAT 规则验证完成（规则已存在）")
		}
		return nil
	}
	log.Printf("NAT: nftables 配置失败: %v, 回退到 iptables", err)

	// Fallback to iptables (works with iptables-nft backend)
	err = setupIPTablesNATLegacy(vpnNetwork, egressInterface, natRuleExists)
	if err != nil {
		return fmt.Errorf("both nftables and iptables failed: nftables=%v, iptables=%w", err, err)
	}
	if !natRuleExists {
		log.Printf("NAT: ✅ NAT 规则已配置（使用 iptables，作为兜底）")
	}
	return nil
}

// setupNftablesNAT configures NAT using nftables
// natRuleExists indicates if NAT rule already exists (set by docker-entrypoint.sh)
func setupNftablesNAT(vpnNetwork, egressInterface string, natRuleExists bool) error {
	// Check if nftables is available
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nftables not available: %w", err)
	}

	// For systems using iptables-nft backend, we need to use ip table instead of inet
	// Try "ip nat" first (compatible with iptables-nft), then "inet nat"
	tableNames := []string{"ip nat", "inet nat"}
	var tableName string
	var chainName = "POSTROUTING"

	for _, tn := range tableNames {
		// Try to add table (ignore error if it already exists)
		if output, err := exec.Command("nft", "add", "table", tn).CombinedOutput(); err != nil {
			outputStr := string(output)
			// Check if table already exists (this is fine, we can continue)
			if strings.Contains(outputStr, "exists") || strings.Contains(outputStr, "File exists") || strings.Contains(outputStr, "managed by") {
				// Table exists or is managed by iptables-nft, use it
				tableName = tn
				break
			}
			// Try next table name
			continue
		}
		// Table created successfully
		tableName = tn
		break
	}

	if tableName == "" {
		return fmt.Errorf("failed to create or find nftables table")
	}

	// Try to add chain (ignore error if it already exists)
	chainCmd := exec.Command("nft", "add", "chain", tableName, chainName, "{ type nat hook postrouting priority 100; }")
	if output, err := chainCmd.CombinedOutput(); err != nil {
		outputStr := string(output)
		// Check if chain already exists (this is fine)
		if !strings.Contains(outputStr, "exists") && !strings.Contains(outputStr, "File exists") {
			return fmt.Errorf("failed to create nftables chain: %w, output: %s", err, outputStr)
		}
		// Chain exists, continue
	}

	// Add masquerade rule for VPN network (only if it doesn't exist)
	// Rule: masquerade packets from VPN network going out through egress interface
	if !natRuleExists {
		rule := fmt.Sprintf("ip saddr %s oifname %s masquerade", vpnNetwork, egressInterface)

		cmd := exec.Command("nft", "add", "rule", tableName, chainName, rule)
		if output, err := cmd.CombinedOutput(); err != nil {
			outputStr := string(output)
			// Check if rule already exists
			if !strings.Contains(outputStr, "File exists") && !strings.Contains(outputStr, "exists") {
				return fmt.Errorf("failed to add nftables rule: %w, output: %s", err, outputStr)
			}
			// Rule already exists, which is fine
			log.Printf("NAT: nftables rule already exists")
		} else {
			log.Printf("NAT: Successfully added nftables masquerade rule: %s", rule)
		}
	} else {
		log.Printf("NAT: 跳过添加 nftables NAT 规则（docker-entrypoint.sh 已设置）")
		// Verify rule exists
		cmd := exec.Command("nft", "list", "ruleset")
		if output, err := cmd.CombinedOutput(); err == nil {
			outputStr := string(output)
			if strings.Contains(outputStr, vpnNetwork) && strings.Contains(outputStr, egressInterface) && strings.Contains(outputStr, "masquerade") {
				log.Printf("NAT: ✅ nftables NAT 规则验证成功")
			} else {
				log.Printf("NAT: ⚠️  警告: nftables NAT 规则验证失败，但继续执行")
			}
		}
	}

	return nil
}

// loadKernelModule loads a kernel module if not already loaded
func loadKernelModule(moduleName string) error {
	// Try to load module using modprobe
	cmd := exec.Command("modprobe", moduleName)
	if output, err := cmd.CombinedOutput(); err != nil {
		outputStr := string(output)
		// Module might already be loaded, which is fine
		if !strings.Contains(outputStr, "already loaded") && !strings.Contains(outputStr, "exists") {
			log.Printf("NAT: Warning: Failed to load kernel module %s: %v, output: %s", moduleName, err, outputStr)
			// Don't return error, as module might already be loaded
		}
	}
	return nil
}

// setupIPTablesNATLegacy configures NAT using iptables (fallback)
// natRuleExists indicates if NAT rule already exists (set by docker-entrypoint.sh)
func setupIPTablesNATLegacy(vpnNetwork, egressInterface string, natRuleExists bool) error {
	// Always load necessary kernel modules
	// This is important for NAT to work correctly, especially in containers
	// Even if rule exists, modules might not be loaded
	log.Printf("NAT: 加载内核模块（iptables NAT 支持）...")
	loadKernelModule("iptable_filter")
	loadKernelModule("iptable_nat")

	// Create iptables client
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("failed to create iptables client: %w", err)
	}

	// Add NAT masquerade rule (only if it doesn't exist)
	natRule := []string{"-s", vpnNetwork, "-o", egressInterface, "-j", "MASQUERADE"}
	if !natRuleExists {
		// First check if rule already exists (double-check)
		exists, err := ipt.Exists("nat", "POSTROUTING", natRule...)
		if err != nil {
			log.Printf("NAT: Warning: Failed to check if NAT rule exists: %v", err)
			// Continue anyway, try to add the rule
			exists = false
		}

		if !exists {
			// Try to insert at position 1 (highest priority), if that fails, append
			err = ipt.Insert("nat", "POSTROUTING", 1, natRule...)
			if err != nil {
				// If insert fails (e.g., position conflict), try append
				log.Printf("NAT: Insert at position 1 failed: %v, trying append...", err)
				err = ipt.Append("nat", "POSTROUTING", natRule...)
				if err != nil {
					log.Printf("NAT: Failed to add NAT rule: %v", err)
					return fmt.Errorf("failed to add NAT rule: %w", err)
				}
				log.Printf("NAT: ✅ 已添加 NAT masquerade 规则（追加）: -s %s -o %s -j MASQUERADE", vpnNetwork, egressInterface)
			} else {
				log.Printf("NAT: ✅ 已添加 NAT masquerade 规则（位置 1）: -s %s -o %s -j MASQUERADE", vpnNetwork, egressInterface)
			}
		} else {
			log.Printf("NAT: ✅ NAT masquerade 规则已存在: -s %s -o %s -j MASQUERADE", vpnNetwork, egressInterface)
		}
	} else {
		log.Printf("NAT: 跳过添加 NAT masquerade 规则（docker-entrypoint.sh 已设置）")
	}

	// Add FORWARD chain rule to allow forwarding
	// This is important for packets to be forwarded through the VPN
	// Note: In Docker containers, FORWARD chain might have default DROP policy
	forwardRule := []string{"-j", "ACCEPT"}
	forwardExists, err := ipt.Exists("filter", "FORWARD", forwardRule...)
	if err != nil {
		log.Printf("NAT: Warning: Failed to check if FORWARD rule exists: %v", err)
		forwardExists = false
	}

	if !forwardExists {
		err = ipt.Insert("filter", "FORWARD", 1, forwardRule...)
		if err != nil {
			// Try append if insert fails
			err = ipt.Append("filter", "FORWARD", forwardRule...)
			if err != nil {
				log.Printf("NAT: Warning: Failed to add FORWARD rule: %v (NAT may still work)", err)
				// Don't return error, as FORWARD rule might not be critical in all cases
			} else {
				log.Printf("NAT: Successfully appended FORWARD rule to allow packet forwarding")
			}
		} else {
			log.Printf("NAT: Successfully inserted FORWARD rule to allow packet forwarding")
		}
	} else {
		log.Printf("NAT: FORWARD rule already exists")
	}

	// Verify rules were added correctly
	natRules, err := ipt.List("nat", "POSTROUTING")
	if err == nil {
		log.Printf("NAT: Current NAT POSTROUTING rules:")
		for i, rule := range natRules {
			log.Printf("NAT:   [%d] %s", i, rule)
		}
		// Check if our rule is in the list
		ruleFound := false
		for _, rule := range natRules {
			if strings.Contains(rule, vpnNetwork) && strings.Contains(rule, egressInterface) && strings.Contains(rule, "MASQUERADE") {
				ruleFound = true
				log.Printf("NAT: ✅ Verified: NAT rule found in POSTROUTING chain")
				break
			}
		}
		if !ruleFound {
			log.Printf("NAT: ⚠️  警告: NAT 规则在 POSTROUTING 链中未找到（可能 docker-entrypoint.sh 已设置但格式不同）")
			log.Printf("NAT: 检查命令: iptables -t nat -L POSTROUTING -n -v")
			// Try to add again as a last resort (兜底机制)
			log.Printf("NAT: 尝试再次添加规则（兜底机制）...")
			if err := ipt.Append("nat", "POSTROUTING", natRule...); err != nil {
				log.Printf("NAT: ⚠️  兜底添加失败: %v（如果 docker-entrypoint.sh 已设置规则，可忽略此错误）", err)
				// 不返回错误，因为规则可能已经通过其他方式存在
			} else {
				log.Printf("NAT: ✅ 规则已通过兜底机制添加成功")
			}
		}
	} else {
		log.Printf("NAT: Warning: Failed to list NAT POSTROUTING rules: %v", err)
		log.Printf("NAT: Cannot verify rule, but assuming it was added successfully")
	}

	forwardRules, err := ipt.List("filter", "FORWARD")
	if err == nil {
		log.Printf("NAT: Current FILTER FORWARD rules:")
		for i, rule := range forwardRules {
			log.Printf("NAT:   [%d] %s", i, rule)
		}
	}

	log.Printf("NAT: ✅ iptables NAT configuration completed successfully")
	return nil
}

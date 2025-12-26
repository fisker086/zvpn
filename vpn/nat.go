package vpn

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
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

// setupNftablesNATConfig configures NAT masquerading using nftables
// This allows VPN clients to access external networks by masquerading their IP addresses
// Note: This is a fallback mechanism. The docker-entrypoint.sh script should have already
// set up the rules. If NAT rule exists, we skip adding it but still perform other checks
// (FORWARD rules, verification, etc.)
// Note: Function name kept as setupIPTablesNAT for backward compatibility with existing code
func setupIPTablesNAT(vpnNetwork, egressInterface string) error {
	// Check if NAT rule already exists (set by docker-entrypoint.sh)
	natRuleExists := checkNATRuleExists(vpnNetwork, egressInterface)

	if natRuleExists {
		log.Printf("NAT: ✅ NAT masquerade 规则已存在（docker-entrypoint.sh 已设置）")
		log.Printf("NAT: 继续执行其他必要检查（FORWARD 规则、验证等）...")
	} else {
		log.Printf("NAT: 未检测到 NAT 规则，开始完整配置（docker-entrypoint.sh 可能未执行或失败）...")
	}

	// Use nftables (modern Linux systems)
	err := setupNftablesNAT(vpnNetwork, egressInterface, natRuleExists)
	if err != nil {
		return fmt.Errorf("nftables configuration failed: %w", err)
	}

		if !natRuleExists {
			log.Printf("NAT: ✅ NAT 规则已配置（使用 nftables，作为兜底）")
		} else {
			log.Printf("NAT: ✅ nftables NAT 规则验证完成（规则已存在）")
		}

	// Add FORWARD rule using nftables
	if err := setupNftablesForwardRule(); err != nil {
		log.Printf("NAT: ⚠️  警告: 无法添加 FORWARD 规则: %v (NAT 可能仍然工作)", err)
	}

	// Add INPUT rule using nftables (allow ICMP and other packets to server VPN IP)
	if err := setupNftablesInputRule(); err != nil {
		log.Printf("NAT: ⚠️  警告: 无法添加 INPUT 规则: %v (ICMP ping 可能失败)", err)
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

	// Try "ip nat" first (standard nftables table), then "inet nat"
	tableNames := []string{"ip nat", "inet nat"}
	var tableName string
	var chainName = "POSTROUTING"

	for _, tn := range tableNames {
		// Try to add table (ignore error if it already exists)
		if output, err := exec.Command("nft", "add", "table", tn).CombinedOutput(); err != nil {
			outputStr := string(output)
			// Check if table already exists (this is fine, we can continue)
			if strings.Contains(outputStr, "exists") || strings.Contains(outputStr, "File exists") || strings.Contains(outputStr, "managed by") {
				// Table exists, use it
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

// setupNftablesForwardRule configures FORWARD chain rule using nftables
func setupNftablesForwardRule() error {
	// Check if nftables is available
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nftables not available: %w", err)
	}

	// Try "ip filter" first, then "inet filter"
	tableNames := []string{"ip filter", "inet filter"}
	var tableName string
	var chainName = "FORWARD"

	for _, tn := range tableNames {
		// Try to add table (ignore error if it already exists)
		if output, err := exec.Command("nft", "add", "table", tn).CombinedOutput(); err != nil {
			outputStr := string(output)
			// Check if table already exists (this is fine)
			if strings.Contains(outputStr, "exists") || strings.Contains(outputStr, "File exists") {
				tableName = tn
				break
			}
			continue
		}
		tableName = tn
		break
		}

	if tableName == "" {
		return fmt.Errorf("failed to create or find nftables filter table")
	}

	// Try to add chain (ignore error if it already exists)
	chainCmd := exec.Command("nft", "add", "chain", tableName, chainName, "{ type filter hook forward priority 0; }")
	if output, err := chainCmd.CombinedOutput(); err != nil {
		outputStr := string(output)
		// Check if chain already exists (this is fine)
		if !strings.Contains(outputStr, "exists") && !strings.Contains(outputStr, "File exists") {
			return fmt.Errorf("failed to create nftables FORWARD chain: %w, output: %s", err, outputStr)
			}
	}

	// Check if accept rule already exists
	cmd := exec.Command("nft", "list", "ruleset")
	if output, err := cmd.CombinedOutput(); err == nil {
		outputStr := string(output)
		if strings.Contains(outputStr, "chain "+chainName) && strings.Contains(outputStr, "accept") {
			log.Printf("NAT: FORWARD accept rule already exists")
			return nil
		}
	}

	// Add accept rule
	ruleCmd := exec.Command("nft", "add", "rule", tableName, chainName, "accept")
	if output, err := ruleCmd.CombinedOutput(); err != nil {
		outputStr := string(output)
		if !strings.Contains(outputStr, "File exists") && !strings.Contains(outputStr, "exists") {
			return fmt.Errorf("failed to add nftables FORWARD rule: %w, output: %s", err, outputStr)
			}
		log.Printf("NAT: FORWARD accept rule already exists")
	} else {
		log.Printf("NAT: Successfully added nftables FORWARD accept rule")
	}

	return nil
	}

// setupNftablesInputRule configures INPUT chain rule using nftables
// This is important for allowing ICMP echo requests to reach the server VPN IP
func setupNftablesInputRule() error {
	// Check if nftables is available
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nftables not available: %w", err)
	}

	// Try "ip filter" first, then "inet filter"
	tableNames := []string{"ip filter", "inet filter"}
	var tableName string
	var chainName = "INPUT"

	for _, tn := range tableNames {
		// Try to add table (ignore error if it already exists)
		if output, err := exec.Command("nft", "add", "table", tn).CombinedOutput(); err != nil {
			outputStr := string(output)
			// Check if table already exists (this is fine)
			if strings.Contains(outputStr, "exists") || strings.Contains(outputStr, "File exists") {
				tableName = tn
				break
			}
			continue
		}
		tableName = tn
		break
	}

	if tableName == "" {
		return fmt.Errorf("failed to create or find nftables filter table")
	}

	// Try to add chain (ignore error if it already exists)
	chainCmd := exec.Command("nft", "add", "chain", tableName, chainName, "{ type filter hook input priority 0; }")
	if output, err := chainCmd.CombinedOutput(); err != nil {
		outputStr := string(output)
		// Check if chain already exists (this is fine)
		if !strings.Contains(outputStr, "exists") && !strings.Contains(outputStr, "File exists") {
			return fmt.Errorf("failed to create nftables INPUT chain: %w, output: %s", err, outputStr)
		}
	}

	// Check if accept rule already exists
	cmd := exec.Command("nft", "list", "ruleset")
	if output, err := cmd.CombinedOutput(); err == nil {
		outputStr := string(output)
		// Check if there's already an accept rule in INPUT chain
		if strings.Contains(outputStr, "chain "+chainName) {
			// Check if there's a specific rule for TUN device or VPN network
			// If INPUT chain exists and has rules, assume it's configured
			if strings.Contains(outputStr, "iifname") || strings.Contains(outputStr, "accept") {
				log.Printf("NAT: INPUT chain already has rules, skipping")
				return nil
			}
		}
	}

	// Add accept rule for packets to TUN device (server VPN IP)
	// This allows ICMP echo requests and other packets to reach the server
	// Note: We accept all INPUT packets because the kernel will handle routing
	// and the TUN device is configured with the server VPN IP
	ruleCmd := exec.Command("nft", "add", "rule", tableName, chainName, "accept")
	if output, err := ruleCmd.CombinedOutput(); err != nil {
		outputStr := string(output)
		if !strings.Contains(outputStr, "File exists") && !strings.Contains(outputStr, "exists") {
			return fmt.Errorf("failed to add nftables INPUT rule: %w, output: %s", err, outputStr)
		}
		log.Printf("NAT: INPUT accept rule already exists")
	} else {
		log.Printf("NAT: Successfully added nftables INPUT accept rule")
	}

	return nil
}

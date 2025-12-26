#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netdevice.h>
#include <linux/pkt_cls.h>

// Include bpf helpers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Define types for compatibility
#ifndef __u32
#define __u32 unsigned int
#endif

#ifndef __u16
#define __u16 unsigned short
#endif

#ifndef __u8
#define __u8 unsigned char
#endif

// Map to store server egress IP for NAT masquerading
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);    // Server egress IP for NAT
} server_egress_ip SEC(".maps");

// Map to store VPN network configuration
// key 0: VPN network address (e.g., 10.8.0.0)
// key 1: VPN network mask (e.g., 0xFFFFFF00 for /24)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} vpn_network_config SEC(".maps");

// Map to store VPN client IP to real IP mapping
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);      // VPN IP
    __type(value, __u32);    // Real client IP (not used for NAT, but for reference)
} vpn_clients SEC(".maps");

// Statistics map to track NAT operations
// key 0: NAT performed count
// key 1: VPN network check passed count
// key 2: VPN client found count
// key 3: Egress IP found count
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} nat_stats SEC(".maps");

// Helper function to recalculate IP checksum after modifying IP header
// IP header fields are in network byte order, so we sum them directly
static __always_inline void recalculate_ip_checksum(struct iphdr *ip, void *data_end) {
    // Bounds check: ensure we can access the IP header
    if ((void *)ip + sizeof(struct iphdr) > data_end) {
        return; // Cannot access IP header
    }
    
    // Validate IP header length
    __u8 ihl = ip->ihl;
    if (ihl < 5 || ihl > 15) {
        return; // Invalid IP header length
    }
    
    // Ensure we can access the full IP header (including options)
    __u32 ip_header_len = ihl * 4;
    if ((void *)ip + ip_header_len > data_end) {
        return; // Cannot access full IP header
    }
    
    ip->check = 0;
    __u32 sum = 0;
    
    // Sum all 16-bit words in IP header (IP header length is in 4-byte units)
    // Access fields directly to help verifier understand bounds
    // NOTE: IP header fields are already in network byte order, so we sum them directly
    // without byte order conversion. The checksum calculation works correctly with
    // network byte order data.
    __u16 *ptr = (__u16 *)ip;
    __u16 num_words = ip_header_len / 2;
    
    // Bounded loop with explicit checks for each access
    // Max 15 * 4 / 2 = 30 words, but we check bounds for each access
    for (int i = 0; i < num_words && i < 30; i++) {
        __u16 *word_ptr = ptr + i;
        // Bounds check: ensure we can access this word
        if ((void *)(word_ptr + 1) <= data_end) {
            // Sum directly without byte order conversion - IP header is network byte order
            sum += *word_ptr;
        }
    }
    
    // Fold 32-bit sum to 16-bit
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Take one's complement and store in network byte order
    ip->check = ~((__u16)sum);
}

// Helper function to recalculate transport layer checksum
// Note: For eth0, IP header is after Ethernet header
static __always_inline void recalculate_transport_checksum(struct iphdr *ip, void *data_end) {
    __u8 protocol = ip->protocol;
    __u16 ip_header_len = ip->ihl * 4;
    void *transport_start = (void *)ip + ip_header_len;
    
    if (transport_start + 8 > data_end) {
        return; // Not enough data for transport header
    }
    
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)transport_start;
        if ((void *)tcp + sizeof(struct tcphdr) > data_end) {
            return;
        }
        tcp->check = 0; // Let kernel recalculate
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)transport_start;
        if ((void *)udp + sizeof(struct udphdr) > data_end) {
            return;
        }
        udp->check = 0; // Let kernel recalculate (0 means kernel should calculate)
    } else if (protocol == IPPROTO_ICMP) {
        // ICMP checksum is at offset 2
        __u16 *icmp_check = (__u16 *)((void *)transport_start + 2);
        if ((void *)icmp_check + 2 > data_end) {
            return;
        }
        *icmp_check = 0; // Let kernel recalculate
    }
}

// Check if IP is in VPN network (read from eBPF map)
static __always_inline int is_vpn_network(__u32 ip) {
    // Read VPN network address from map (key 0)
    __u32 key = 0;
    __u32 *vpn_net = bpf_map_lookup_elem(&vpn_network_config, &key);
    if (!vpn_net) {
        // Fallback to default 10.8.0.0/24 if map not configured
    return (ip & 0xFFFFFF00) == 0x0A080000;
    }
    
    // Read VPN network mask from map (key 1)
    key = 1;
    __u32 *vpn_mask = bpf_map_lookup_elem(&vpn_network_config, &key);
    if (!vpn_mask) {
        // Fallback to default /24 mask if map not configured
        return (ip & 0xFFFFFF00) == *vpn_net;
    }
    
    // Check if IP is in VPN network
    return (ip & *vpn_mask) == *vpn_net;
}

// TC egress hook: Perform NAT masquerading for packets from VPN clients to external networks
// 
// 架构说明：
// TC 职责（eth0 egress）：
// 1. NAT MASQUERADE：将 VPN 客户端 IP 转换为服务器出口 IP
// 2. 校验和重算：重新计算 IP 和传输层校验和
// 3. 仅处理：VPN 客户端 → 外部网络的流量
//
// 为什么在 eth0 而不是 TUN 设备：
// - TUN 设备是三层设备，数据包写入后内核会路由
// - 如果目标是外部，内核会直接通过 eth0 发送
// - TC hook 在 TUN egress 上可能无法拦截到这些数据包
// - 在 eth0 egress 上可以拦截所有从 eth0 出去的流量
//
// TC 不处理：
// - 策略检查（由 XDP eth0 ingress 处理）
// - VPN 内部流量（不需要 NAT）
// - 反向流量（由内核 conntrack 处理）
//
// 注意：
// - 使用 TCX_EGRESS attach type (kernel 5.19+)
// - eth0 是物理网卡，数据包有以太网头
SEC("tc")
int tc_nat_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Strict bounds checking - early exit for invalid packets
    // Check minimum packet size (eth0 has Ethernet header)
    if (data + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_OK; // Pass packet, too small for Ethernet header
    }
    
    // Skip Ethernet header (eth0 is Layer 2 device)
    struct ethhdr *eth = (struct ethhdr *)data;
    
    // Bounds check: ensure we can access the entire Ethernet header
    // This is required before accessing eth->h_proto (offset 12)
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK; // Cannot access Ethernet header fully
    }
    
    // Only process IPv4 packets - fast path for non-IP traffic
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK; // Not IPv4, pass
    }
    
    // Get IP header (after Ethernet header)
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    
    // Strict bounds check: ensure we can access at least the minimum IP header (20 bytes)
    if ((void *)(ip + 1) > data_end || (void *)ip + sizeof(struct iphdr) > data_end) {
        return TC_ACT_OK; // Cannot access IP header
    }
    
    // Only process IPv4
    if (ip->version != 4) {
        return TC_ACT_OK;
    }
    
    // Additional check: ensure IP header length is valid
    if (ip->ihl < 5 || ip->ihl > 15) {
        return TC_ACT_OK; // Invalid IP header length
    }
    
    // Ensure we can access the full IP header (including options)
    __u16 ip_header_len = ip->ihl * 4;
    if ((void *)ip + ip_header_len > data_end) {
        return TC_ACT_OK; // IP header extends beyond packet
    }
    
    // Check if source IP is VPN client and destination is external
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    
    // Update statistics: packets processed
    __u32 stat_key = 4; // Total packets processed
    __u64 *stat_value = bpf_map_lookup_elem(&nat_stats, &stat_key);
    if (stat_value) {
        (*stat_value)++;
    }
    
    if (!is_vpn_network(src_ip) || is_vpn_network(dst_ip)) {
        return TC_ACT_OK; // Not VPN client to external, pass
    }
    
    // Update statistics: VPN network check passed
    stat_key = 1;
    stat_value = bpf_map_lookup_elem(&nat_stats, &stat_key);
    if (stat_value) {
        (*stat_value)++;
    }
    
    // Check if VPN client is registered
    __u32 *client_real_ip = bpf_map_lookup_elem(&vpn_clients, &src_ip);
    if (!client_real_ip) {
        return TC_ACT_OK; // VPN client not registered, pass
    }
    
    // Update statistics: VPN client found
    stat_key = 2;
    stat_value = bpf_map_lookup_elem(&nat_stats, &stat_key);
    if (stat_value) {
        (*stat_value)++;
    }
    
    // Get egress IP for NAT
    __u32 key = 0;
    __u32 *egress_ip = bpf_map_lookup_elem(&server_egress_ip, &key);
    if (!egress_ip || *egress_ip == 0) {
        return TC_ACT_OK; // No egress IP configured, pass
    }
    
    // Update statistics: Egress IP found
    stat_key = 3;
    stat_value = bpf_map_lookup_elem(&nat_stats, &stat_key);
    if (stat_value) {
        (*stat_value)++;
    }
    
    // Perform NAT: change source IP to egress IP
    // Bounds check: ensure we can modify saddr (offset 12, 4 bytes)
    if ((void *)ip + 16 > data_end) {
        return TC_ACT_OK; // Cannot access saddr field
    }
    
    __u32 old_saddr = ip->saddr;
    ip->saddr = *egress_ip;
    
    // Update statistics: NAT performed
    stat_key = 0; // NAT performed count
    stat_value = bpf_map_lookup_elem(&nat_stats, &stat_key);
    if (stat_value) {
        (*stat_value)++;
    }
    
    // Recalculate IP checksum (pass data_end for bounds checking)
    recalculate_ip_checksum(ip, data_end);
    
    // Recalculate transport layer checksum
    recalculate_transport_checksum(ip, data_end);
    
    // Return TC_ACT_OK to pass packet to kernel (kernel will handle routing)
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";


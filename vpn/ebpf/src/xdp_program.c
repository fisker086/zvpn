#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netdevice.h>

// Include bpf helpers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Define types for compatibility with different kernel versions
#ifndef __u32
#define __u32 unsigned int
#endif

#ifndef __u16
#define __u16 unsigned short
#endif

#ifndef __u8
#define __u8 unsigned char
#endif

// Define macro for compatibility
#ifndef __uint
#define __uint(x, v) int __##x = (v)
#endif

#ifndef __type
#define __type(x, v) typeof(v) __##x
#endif

// Policy action types
#define POLICY_ACTION_ALLOW     0
#define POLICY_ACTION_DENY      1
#define POLICY_ACTION_REDIRECT  2  // Redirect to zvpn0

// Policy hook points
#define HOOK_PRE_ROUTING     0
#define HOOK_POST_ROUTING    1
#define HOOK_FORWARD         2
#define HOOK_INPUT           3
#define HOOK_OUTPUT          4

// Flags layout (2 bits per field to carry match type):
// bits 0-1: src IP match type, 2-3: dst IP match type, 4-5: src port, 6-7: dst port
// match type: 0=exact, 1=any (0), 2=mask/range
// Policy structure (stored in map)
struct policy_entry {
    __u32 policy_id;
    __u32 action;
    __u32 hook_point;
    __u32 priority;
    __u32 src_ip;
    __u32 dst_ip;
    __u32 src_ip_mask;  // Network mask for source IP (CIDR)
    __u32 dst_ip_mask;  // Network mask for destination IP (CIDR)
    __u16 src_port;
    __u16 dst_port;
    __u16 src_port_end;  // End of source port range (0 = single port)
    __u16 dst_port_end;  // End of destination port range (0 = single port)
    __u8  protocol;
    __u8  protocol_mask; // Bitmask: bit 0=TCP, bit 1=UDP, bit 2=ICMP (0 = any protocol)
    __u8  flags;
};

// Map to store VPN client IP to real IP mapping
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);      // VPN IP
    __type(value, __u32);    // Real client IP
} vpn_clients SEC(".maps");

// Map to store server egress IP for NAT masquerading
// Key: 0 (single entry), Value: server egress IP in network byte order
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);    // Server egress IP for NAT
} server_egress_ip SEC(".maps");

// Map to store network interfaces by name
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, char[16]);      // Interface name
    __type(value, int);         // Interface index
} interfaces SEC(".maps");

// Map to store policies (indexed by policy_id)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u32);      // Policy ID
    __type(value, struct policy_entry);
} policies SEC(".maps");

// Map to store policy chain (ordered list of policy IDs for each hook)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct {
        __u32 hook_point;
        __u32 index;
    });
    __type(value, __u32);  // Policy ID
} policy_chains SEC(".maps");

// Statistics map (per-CPU)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Policy match statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);      // Policy ID
    __type(value, __u64);    // Match count
} policy_stats SEC(".maps");

// Policy events (for audit logging in user space)
// Stores recent policy match events: policy_id -> packet info
struct policy_event {
    __u32 policy_id;
    __u32 action;      // POLICY_ACTION_ALLOW, DENY, etc.
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u32 timestamp;  // Kernel jiffies (approximate)
};

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 2048);  // Increased size to handle both allow and deny events
    __type(value, struct policy_event);
} policy_events SEC(".maps");

// Rate limiting maps
// Token bucket for rate limiting per IP (packets per second)
struct rate_limit_entry {
    __u64 tokens;      // Current tokens
    __u64 last_update; // Last update time (nanoseconds)
    __u64 rate;        // Tokens per second
    __u64 burst;       // Maximum burst size
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);  // Support up to 4096 IPs
    __type(key, __u32);         // IP address
    __type(value, struct rate_limit_entry);
} rate_limit_map SEC(".maps");

// DDoS protection: track packet count per IP
struct ddos_tracker {
    __u64 packet_count;  // Packet count in current window
    __u64 window_start;  // Window start time (nanoseconds)
    __u64 block_until;   // Block until this time (0 = not blocked)
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);  // Support up to 4096 IPs
    __type(key, __u32);         // IP address
    __type(value, struct ddos_tracker);
} ddos_tracker_map SEC(".maps");

// Connection tracking removed - no connection limits

// Global rate limit settings (updated from user space)
struct rate_limit_config {
    __u8  enable_rate_limit;
    __u64 rate_limit_per_ip;      // Packets per second per IP
    __u8  enable_ddos_protection;
    __u64 ddos_threshold;          // Packets per second threshold
    __u64 ddos_block_duration;     // Block duration in nanoseconds
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rate_limit_config);
} rate_limit_config_map SEC(".maps");

// Blocked IPs map for bruteforce protection
// Key: IP address (__u32), Value: block_until timestamp (__u64, nanoseconds, 0 = permanent block)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);  // Support up to 4096 blocked IPs
    __type(key, __u32);         // IP address
    __type(value, __u64);        // Block until timestamp (0 = permanent block)
} blocked_ips_map SEC(".maps");

// Helper function to check if IP matches policy
// match_type: 0 = exact match, 1 = any match (0.0.0.0), 2 = network match (using mask)
static __always_inline int match_ip(__u32 ip, __u32 policy_ip, __u32 policy_mask, __u8 match_type) {
    if (match_type == 0) {  // Exact match
        return ip == policy_ip;
    } else if (match_type == 1) {  // Any match (0.0.0.0)
        return policy_ip == 0;
    } else {  // Network match using CIDR mask
        if (policy_mask == 0) {
            return policy_ip == 0;  // No mask specified, treat as any
        }
        return (ip & policy_mask) == (policy_ip & policy_mask);
    }
}

// Helper function to check if port matches policy
static __always_inline int match_port(__u16 port, __u16 policy_port, __u16 policy_port_end, __u8 match_type) {
    if (match_type == 0) {  // Exact match or range
        if (policy_port_end == 0 || policy_port_end == policy_port) {
            // Single port match
            return port == policy_port;
        } else {
            // Port range match
            return port >= policy_port && port <= policy_port_end;
        }
    } else {  // Any port (0)
        return policy_port == 0;
    }
}

// Extract match type from flags (2 bits per field)
// flags layout: bits 0-1=src IP, 2-3=dst IP, 4-5=src port, 6-7=dst port
static __always_inline __u8 get_src_ip_match_type(__u8 flags) { return (flags >> 0) & 0x3; }
static __always_inline __u8 get_dst_ip_match_type(__u8 flags) { return (flags >> 2) & 0x3; }
static __always_inline __u8 get_src_port_match_type(__u8 flags) { return (flags >> 4) & 0x3; }
static __always_inline __u8 get_dst_port_match_type(__u8 flags) { return (flags >> 6) & 0x3; }

// Helper function to check if protocol matches policy
// protocol_mask: bit 0=TCP, bit 1=UDP, bit 2=ICMP (0 = any protocol)

static __always_inline int match_protocol(__u8 protocol, __u8 policy_protocol, __u8 protocol_mask) {
    if (protocol_mask == 0) {
        // No protocol mask specified, use exact match with policy_protocol
        return policy_protocol == 0 || protocol == policy_protocol;
    }
    
    // Check protocol using bitmask
    if (protocol == IPPROTO_TCP && (protocol_mask & 0x01)) {
        return 1;
    }
    if (protocol == IPPROTO_UDP && (protocol_mask & 0x02)) {
        return 1;
    }
    if (protocol == IPPROTO_ICMP && (protocol_mask & 0x04)) {
        return 1;
    }
    
    return 0;
}

// Execute policy chain for a hook point
static __always_inline int execute_policy_chain(__u32 hook_point, struct iphdr *ip, 
                                                 void *data_end, __u32 *action) {
    // Iterate through policies in the chain (index from 0 to 63)
    for (__u32 i = 0; i < 64; i++) {
        // Create composite key for the hash map
        struct {
            __u32 hook_point;
            __u32 index;
        } key = {hook_point, i};
        
        // Lookup policy ID for this hook point and index
        __u32 *policy_id = bpf_map_lookup_elem(&policy_chains, &key);
        if (!policy_id || *policy_id == 0) {
            break;  // End of chain
        }
        
        // Get policy entry
        struct policy_entry *policy = bpf_map_lookup_elem(&policies, policy_id);
        if (!policy) {
            continue;
        }
        
        // Check if policy matches
        int match = 1;
        
        // Match source IP (if policy specifies a source IP or mask)
        if (policy->src_ip != 0 || policy->src_ip_mask != 0) {
            if (!match_ip(ip->saddr, policy->src_ip, policy->src_ip_mask, get_src_ip_match_type(policy->flags))) {
                match = 0;
            }
        }
        
        // Match destination IP (if policy specifies a destination IP or mask)
        if (policy->dst_ip != 0 || policy->dst_ip_mask != 0) {
            if (!match_ip(ip->daddr, policy->dst_ip, policy->dst_ip_mask, get_dst_ip_match_type(policy->flags))) {
                match = 0;
            }
        }
        
        // Match protocol (if policy specifies a protocol)
        // Support both single protocol (policy->protocol) and protocol mask
        if (policy->protocol_mask != 0 || policy->protocol != 0) {
            if (!match_protocol(ip->protocol, policy->protocol, policy->protocol_mask)) {
                match = 0;
            }
        }
        
        // Match ports (if TCP/UDP)
        if (match && (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP)) {
            if ((void *)(ip + 1) > data_end) {
                break;
            }
            
            __u16 src_port = 0, dst_port = 0;
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
                if ((void *)(tcp + 1) <= data_end) {
                    src_port = bpf_ntohs(tcp->source);
                    dst_port = bpf_ntohs(tcp->dest);
                }
            } else if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = (struct udphdr *)(ip + 1);
                if ((void *)(udp + 1) <= data_end) {
                    src_port = bpf_ntohs(udp->source);
                    dst_port = bpf_ntohs(udp->dest);
                }
            }
            
            if (!match_port(src_port, policy->src_port, policy->src_port_end, get_src_port_match_type(policy->flags))) {
                match = 0;
            }
            if (!match_port(dst_port, policy->dst_port, policy->dst_port_end, get_dst_port_match_type(policy->flags))) {
                match = 0;
            }
        }
        
        // If policy matches, execute action
        if (match) {
            // Update statistics
            __u64 *count = bpf_map_lookup_elem(&policy_stats, policy_id);
            if (count) {
                (*count)++;
            }
            
            // Record policy event for audit logging (both ALLOW and DENY)
            struct policy_event event = {
                .policy_id = *policy_id,
                .action = policy->action,
                .src_ip = ip->saddr,
                .dst_ip = ip->daddr,
                .src_port = 0,
                .dst_port = 0,
                .protocol = ip->protocol,
                .timestamp = bpf_ktime_get_ns() / 1000000, // Convert to milliseconds
            };
            
            // Extract ports if TCP/UDP
            if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
                if ((void *)(ip + 1) <= data_end) {
                    if (ip->protocol == IPPROTO_TCP) {
                        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
                        if ((void *)(tcp + 1) <= data_end) {
                            event.src_port = bpf_ntohs(tcp->source);
                            event.dst_port = bpf_ntohs(tcp->dest);
                        }
                    } else if (ip->protocol == IPPROTO_UDP) {
                        struct udphdr *udp = (struct udphdr *)(ip + 1);
                        if ((void *)(udp + 1) <= data_end) {
                            event.src_port = bpf_ntohs(udp->source);
                            event.dst_port = bpf_ntohs(udp->dest);
                        }
                    }
                }
            }
            
            // Push to queue (non-blocking, may fail if queue is full)
            // Use 0 (BPF_ANY) to push to tail
            bpf_map_push_elem(&policy_events, &event, 0);
            
            *action = policy->action;
            return 1;  // Policy matched
        }
    }
    
    return 0;  // No policy matched
}

// Helper function to check if IP is in VPN network
static __always_inline int is_vpn_network(__u32 ip) {
    __u32 vpn_network = 0x0A080000; // 10.8.0.0
    __u32 vpn_mask = 0xFFFFFF00;    // /24
    return (ip & vpn_mask) == vpn_network;
}

// Rate limiting: token bucket algorithm
static __always_inline int check_rate_limit(__u32 ip) {
    __u32 config_key = 0;
    struct rate_limit_config *config = bpf_map_lookup_elem(&rate_limit_config_map, &config_key);
    if (!config || !config->enable_rate_limit) {
        return 1; // Rate limiting disabled, allow
    }
    
    if (config->rate_limit_per_ip == 0) {
        return 1; // No limit set, allow
    }
    
    struct rate_limit_entry *entry = bpf_map_lookup_elem(&rate_limit_map, &ip);
    __u64 now = bpf_ktime_get_ns();
    
    if (!entry) {
        // First packet from this IP, initialize
        struct rate_limit_entry new_entry = {
            .tokens = config->rate_limit_per_ip,
            .last_update = now,
            .rate = config->rate_limit_per_ip,
            .burst = config->rate_limit_per_ip * 2, // Allow 2x burst
        };
        bpf_map_update_elem(&rate_limit_map, &ip, &new_entry, BPF_ANY);
        return 1; // Allow first packet
    }
    
    // Update tokens based on elapsed time
    __u64 elapsed = now - entry->last_update;
    __u64 tokens_to_add = (elapsed * entry->rate) / 1000000000ULL; // Convert ns to seconds
    __u64 new_tokens = entry->tokens + tokens_to_add;
    if (new_tokens > entry->burst) {
        new_tokens = entry->burst; // Cap at burst size
    }
    
    // Check if we have enough tokens
    if (new_tokens >= 1) {
        new_tokens -= 1; // Consume one token
        entry->tokens = new_tokens;
        entry->last_update = now;
        return 1; // Allow
    }
    
    // Update timestamp even if we drop
    entry->last_update = now;
    return 0; // Drop (rate limit exceeded)
}

// DDoS protection: check if IP is blocked or should be blocked
static __always_inline int check_ddos_protection(__u32 ip) {
    __u32 config_key = 0;
    struct rate_limit_config *config = bpf_map_lookup_elem(&rate_limit_config_map, &config_key);
    if (!config || !config->enable_ddos_protection) {
        return 1; // DDoS protection disabled, allow
    }
    
    if (config->ddos_threshold == 0) {
        return 1; // No threshold set, allow
    }
    
    struct ddos_tracker *tracker = bpf_map_lookup_elem(&ddos_tracker_map, &ip);
    __u64 now = bpf_ktime_get_ns();
    __u64 window_size = 1000000000ULL; // 1 second window
    
    if (!tracker) {
        // First packet from this IP, initialize
        struct ddos_tracker new_tracker = {
            .packet_count = 1,
            .window_start = now,
            .block_until = 0,
        };
        bpf_map_update_elem(&ddos_tracker_map, &ip, &new_tracker, BPF_ANY);
        return 1; // Allow first packet
    }
    
    // Check if IP is currently blocked
    if (tracker->block_until > 0 && now < tracker->block_until) {
        return 0; // Still blocked
    }
    
    // Reset block status if block period expired
    if (tracker->block_until > 0 && now >= tracker->block_until) {
        tracker->block_until = 0;
        tracker->packet_count = 0;
        tracker->window_start = now;
    }
    
    // Check if we're in a new time window
    if (now - tracker->window_start >= window_size) {
        // New window, reset counter
        tracker->packet_count = 1;
        tracker->window_start = now;
        return 1; // Allow
    }
    
    // Increment packet count
    tracker->packet_count++;
    
    // Check if threshold exceeded
    if (tracker->packet_count > config->ddos_threshold) {
        // Block this IP
        tracker->block_until = now + (config->ddos_block_duration * 1000000000ULL);
        return 0; // Drop (DDoS detected)
    }
    
    return 1; // Allow
}

// Connection rate limiting removed - no connection limits

// Helper function to recalculate IP checksum after modifying IP header
// IP header fields are in network byte order, so we sum them directly
static __always_inline void recalculate_ip_checksum(struct iphdr *ip, void *data_end) {
    // Bounds check: ensure we can access the IP header
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return;
    
    // Validate IP header length
    __u8 ihl = ip->ihl;
    if (ihl < 5 || ihl > 15)
        return;
    
    // Ensure we can access the full IP header (including options)
    __u32 ip_header_len = ihl * 4;
    if ((void *)ip + ip_header_len > data_end)
        return;
    
    ip->check = 0;
    __u32 sum = 0;
    
    // Sum all 16-bit words in IP header (IP header length is in 4-byte units)
    // Access fields directly to help verifier understand bounds
    __u16 *ptr = (__u16 *)ip;
    __u16 num_words = ip_header_len / 2;
    
    // Unroll loop for better verifier understanding (max 15 * 4 / 2 = 30 words)
    // But we'll use a bounded loop with explicit checks
    for (int i = 0; i < num_words && i < 30; i++) {
        __u16 *word_ptr = ptr + i;
        if ((void *)(word_ptr + 1) <= data_end) {
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

// Helper function to recalculate TCP/UDP/ICMP checksum after modifying IP header
// Note: In XDP, we can't easily recalculate full checksum (requires pseudo-header for TCP/UDP)
// We set checksum to 0 and let the kernel recalculate it
// This works because the kernel will recalculate checksum before sending if it's 0
static __always_inline void recalculate_transport_checksum(struct iphdr *ip, void *data_end) {
    __u8 protocol = ip->protocol;
    void *transport_start = (void *)ip + (ip->ihl * 4);
    
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)transport_start;
        if ((void *)(tcp + 1) > data_end) {
            return;
        }
        // Set checksum to 0 - kernel will recalculate before sending
        // This is safe because TCP checksum is mandatory
        tcp->check = 0;
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)transport_start;
        if ((void *)(udp + 1) > data_end) {
            return;
        }
        // UDP checksum is optional - if it was set, set to 0 for kernel to recalculate
        // If it was 0 (no checksum), keep it as 0
        if (udp->check != 0) {
            udp->check = 0; // Let kernel recalculate
        }
    } else if (protocol == IPPROTO_ICMP) {
        // ICMP has checksum at offset 2 (after type and code)
        // ICMP header: type(1) + code(1) + checksum(2) + rest
        if ((void *)(transport_start + 4) > data_end) {
            return;
        }
        __u16 *icmp_checksum = (__u16 *)(transport_start + 2);
        *icmp_checksum = 0; // Let kernel recalculate ICMP checksum
    }
}

// 注意：XDP 不做 NAT
// NAT 应该由 TC (TUN egress) 处理，因为：
// 1. XDP 只能看到 ingress 流量（进入 eth0）
// 2. VPN 客户端访问外部的流量是从 TUN 设备出去的（egress）
// 3. XDP 无法处理 egress 流量
// 4. 因此 NAT 必须由 TC (TUN egress) 处理
//
// 此函数已移除，NAT 功能由 tc_nat.c 中的 TC 程序处理

// Check if IP is blocked (for bruteforce protection)
static __always_inline int check_blocked_ip(__u32 ip) {
    __u64 *blocked_until = bpf_map_lookup_elem(&blocked_ips_map, &ip);
    if (!blocked_until) {
        return 1; // Not blocked, allow
    }
    
    // If blocked_until is 0, it's a permanent block
    if (*blocked_until == 0) {
        return 0; // Permanently blocked, drop
    }
    
    // Check if block has expired
    __u64 now = bpf_ktime_get_ns();
    if (now >= *blocked_until) {
        // Block expired, remove from map
        bpf_map_delete_elem(&blocked_ips_map, &ip);
        return 1; // Allow (block expired)
    }
    
    return 0; // Still blocked, drop
}

// XDP program entry point
// 
// 架构说明：
// XDP 职责（eth0 ingress）：
// 1. 策略检查：PRE_ROUTING, INPUT, FORWARD hook 点
// 2. 安全防护：DDoS 防护、暴力破解防护
// 3. 流量统计：VPN 相关流量统计
// 4. 流量重定向：如果需要，重定向到 TUN 设备
//
// XDP 不处理：
// - NAT（由 TC TUN egress 处理）
// - VPN 内部流量（由 TUN 设备处理）
// - Egress 流量（XDP 只能看到 ingress）
//
// 流量路径：
// 1. VPN客户端访问外部：zvpn0 → TC egress (NAT) → 内核路由 → eth0 → XDP 不处理（egress）
// 2. 外部访问VPN客户端：eth0 → XDP ingress (策略检查) → 内核路由 → zvpn0
// 3. VPN客户端间通信：zvpn0 → 虚拟网卡直接处理，不经过 eth0 和 eBPF
// 4. VPN客户端访问服务器VPN IP：zvpn0 → 虚拟网卡处理，不经过 eth0
SEC("xdp")
int xdp_vpn_forward(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    struct iphdr *ip;
    __u32 key = 0;
    __u64 *value;
    __u32 action = POLICY_ACTION_ALLOW;
    
    // Basic bounds checking - early exit for invalid packets
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Only process IPv4 packets - fast path for non-IP traffic
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    ip = (struct iphdr *)(eth + 1);
    // Strict bounds check: ensure we can access at least the minimum IP header (20 bytes)
    if ((void *)(ip + 1) > data_end || (void *)ip + sizeof(struct iphdr) > data_end)
        return XDP_PASS;
    
    // Additional check: ensure IP header length is valid
    if (ip->ihl < 5 || ip->ihl > 15)
        return XDP_PASS;
    
    // Ensure we can access the full IP header (including options)
    if ((void *)ip + (ip->ihl * 4) > data_end)
        return XDP_PASS;
    
    // Fast path: VPN网络内部流量不应该到达eth0，如果到达了，直接PASS让内核处理
    if (is_vpn_network(ip->saddr) && is_vpn_network(ip->daddr)) {
        // VPN内部流量，应该由zvpn0处理，不应该到达eth0
        // 如果到达了，可能是路由配置问题，直接PASS（不统计）
        return XDP_PASS;
    }
    
    // Security checks: blocked IPs (bruteforce protection), rate limiting, and DDoS protection
    // Check blocked IPs first (highest priority - kernel-level blocking)
    if (!check_blocked_ip(ip->saddr)) {
        key = 4; // Blocked IP stat (bruteforce protection)
        value = bpf_map_lookup_elem(&stats, &key);
        if (value)
            (*value)++;
        return XDP_DROP;
    }
    
    // Check rate limit for source IP
    if (!check_rate_limit(ip->saddr)) {
        key = 2; // Rate limit exceeded stat
        value = bpf_map_lookup_elem(&stats, &key);
        if (value)
            (*value)++;
        return XDP_DROP;
    }
    
    // Check DDoS protection for source IP
    if (!check_ddos_protection(ip->saddr)) {
        key = 3; // DDoS blocked stat
        value = bpf_map_lookup_elem(&stats, &key);
        if (value)
            (*value)++;
        return XDP_DROP;
    }
    
    // Check if this is a packet from a VPN client accessing external network
    __u32 vpn_ip = ip->saddr;
    __u32 *client_ip = bpf_map_lookup_elem(&vpn_clients, &vpn_ip);
    
    if (client_ip) {
        // VPN客户端访问外部网络 - 更新统计（只统计VPN相关流量）
        key = 0;
        value = bpf_map_lookup_elem(&stats, &key);
        if (value)
            (*value)++;
        
        // 执行PRE_ROUTING策略检查
        if (execute_policy_chain(HOOK_PRE_ROUTING, ip, data_end, &action)) {
            if (action == POLICY_ACTION_DENY) {
                key = 1;
                value = bpf_map_lookup_elem(&stats, &key);
                if (value)
                    (*value)++;
                return XDP_DROP;
            }
            // 如果策略要求重定向到zvpn0，这里我们PASS让内核路由
            // 实际的重定向应该在路由层面配置
            return XDP_PASS; // 匹配到非 ALLOW 动作，停止后续 hook 点（洋葱模型）
        }

        // 出站流量可视为 POST_ROUTING 阶段，再检查一次
        if (execute_policy_chain(HOOK_POST_ROUTING, ip, data_end, &action)) {
            if (action == POLICY_ACTION_DENY) {
                key = 1;
                value = bpf_map_lookup_elem(&stats, &key);
                if (value)
                    (*value)++;
                return XDP_DROP;
            }
            return XDP_PASS; // 匹配到非 ALLOW 动作，停止后续 hook 点
        }
        
        // 注意：XDP 不做 NAT，因为：
        // 1. XDP 只能看到 ingress 流量（进入 eth0）
        // 2. VPN 客户端访问外部的流量是从 TUN 设备出去的（egress）
        // 3. NAT 应该由 TC (TUN egress) 处理
        // 4. 这里只做策略检查，然后 PASS 让内核路由
        return XDP_PASS;
    }
    
    // Check if destination IP is the server's own VPN IP (10.8.0.1)
    __u32 server_vpn_ip = 0x0A080001; // 10.8.0.1 in network byte order
    if (ip->daddr == server_vpn_ip) {
        // 外部访问服务器VPN IP - 更新统计（只统计VPN相关流量）
        key = 0;
        value = bpf_map_lookup_elem(&stats, &key);
        if (value)
            (*value)++;
        
        // 执行INPUT策略检查
        if (execute_policy_chain(HOOK_INPUT, ip, data_end, &action)) {
            if (action == POLICY_ACTION_DENY) {
                key = 1;
                value = bpf_map_lookup_elem(&stats, &key);
                if (value)
                    (*value)++;
                return XDP_DROP;
            }
        }
        
        // PASS让内核处理（路由到zvpn0）
        return XDP_PASS;
    }
    
    // Check if destination is VPN network (external -> VPN client)
    if (is_vpn_network(ip->daddr)) {
        // 外部访问VPN网络 - 更新统计（只统计VPN相关流量）
        key = 0;
        value = bpf_map_lookup_elem(&stats, &key);
        if (value)
            (*value)++;
        
        // 执行PRE_ROUTING策略检查
        if (execute_policy_chain(HOOK_PRE_ROUTING, ip, data_end, &action)) {
            if (action == POLICY_ACTION_DENY) {
                key = 1;
                value = bpf_map_lookup_elem(&stats, &key);
                if (value)
                    (*value)++;
                return XDP_DROP;
            }
            // 如果策略要求重定向到zvpn0，PASS让内核路由
            return XDP_PASS; // 匹配到非 ALLOW 动作，停止后续 hook 点
        }

        // 转发到 VPN 客户端的流量，可视为 FORWARD 阶段
        if (execute_policy_chain(HOOK_FORWARD, ip, data_end, &action)) {
            if (action == POLICY_ACTION_DENY) {
                key = 1;
                value = bpf_map_lookup_elem(&stats, &key);
                if (value)
                    (*value)++;
                return XDP_DROP;
            }
            return XDP_PASS; // 匹配到非 ALLOW 动作，停止后续 hook 点
        }
        
        // PASS让内核路由到zvpn0（虚拟网卡会转发给VPN客户端）
        return XDP_PASS;
    }
    
    // 其他外部流量 - 执行策略检查
    if (execute_policy_chain(HOOK_PRE_ROUTING, ip, data_end, &action)) {
        if (action == POLICY_ACTION_DENY) {
            key = 1;
            value = bpf_map_lookup_elem(&stats, &key);
            if (value)
                (*value)++;
            return XDP_DROP;
        }
        // 如果策略要求重定向到zvpn0，PASS让内核路由
        return XDP_PASS; // 匹配到非 ALLOW 动作，停止后续 hook 点
    }

    // 对非 VPN 相关的入站流量，在 OUTPUT 阶段再检查一次（近似）
    if (execute_policy_chain(HOOK_OUTPUT, ip, data_end, &action)) {
        if (action == POLICY_ACTION_DENY) {
            key = 1;
            value = bpf_map_lookup_elem(&stats, &key);
            if (value)
                (*value)++;
            return XDP_DROP;
        }
        return XDP_PASS; // 匹配到非 ALLOW 动作，停止后续 hook 点
    }
    
    // 默认：PASS让内核正常路由
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

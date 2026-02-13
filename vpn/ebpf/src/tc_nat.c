#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/pkt_cls.h>

// Include bpf helpers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Define __wsum type (checksum type used by kernel)
#ifndef __wsum
typedef __u32 __wsum;
#endif

// Constants
#define TC_ACT_OK 0
#define ETH_P_IP 0x0800
#define STAT_KEY_TOTAL_PACKETS 4
#define STAT_KEY_VPN_CHECK_PASSED 1
#define STAT_KEY_CLIENT_FOUND 2
#define STAT_KEY_EGRESS_IP_FOUND 3
#define STAT_KEY_NAT_PERFORMED 0
#define STAT_KEY_NAT_FAILED 5
#define STAT_KEY_SKIP_ALREADY_EGRESS 6
#define STAT_KEY_SHOULD_NOT_NAT 7
#define STAT_KEY_NO_VPN_CONFIG 8
#define STAT_KEY_NO_EGRESS_IP 9
#define STAT_KEY_SRC_IS_VPN 10
#define STAT_KEY_DST_IS_VPN 11
#define STAT_KEY_SRC_IS_EGRESS 12
#define STAT_KEY_DEBUG_SRC_IP 20
#define STAT_KEY_DEBUG_VPN_NET 21
#define STAT_KEY_DEBUG_VPN_MASK 22
#define STAT_KEY_DEBUG_DST_IP 26
#define STAT_KEY_DEBUG_COMPARE_RESULT 24

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} server_egress_ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} vpn_network_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} vpn_clients SEC(".maps");

struct nat_conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
    __u8  pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct nat_conn_key);
    __type(value, __u32);
} nat_conn_track SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 30);
    __type(key, __u32);
    __type(value, __u64);
} nat_stats SEC(".maps");

// Helper structures for checksum update (similar to reference project)
struct l3_fields {
    __u32 saddr;
    __u32 daddr;
};

struct l4_fields {
    __u16 sport;
    __u16 dport;
};

// Helper function to update statistics
static __always_inline void update_stat(__u32 key) {
    __u64 *value = bpf_map_lookup_elem(&nat_stats, &key);
    if (value) {
        (*value)++;
    }
}

// Check if IP is in VPN network
static __always_inline int is_ip_in_vpn_network(__u32 ip, __u32 vpn_net, __u32 vpn_mask) {
    return (ip & vpn_mask) == vpn_net;
}

// Parse and validate packet headers
static __always_inline int parse_packet_headers(struct __sk_buff *skb,
                                                void **data_end,
                                                struct ethhdr **eth,
                                                struct iphdr **ip,
                                                __u32 *ip_hlen) {
    void *data = (void *)(long)skb->data;
    *data_end = (void *)(long)skb->data_end;
    
    // Check minimum packet size for Ethernet header
    if (data + sizeof(struct ethhdr) > *data_end) {
        return -1;
    }
    
    *eth = (struct ethhdr *)data;
    
    // Bounds check for Ethernet header
    if ((void *)(*eth + 1) > *data_end) {
        return -1;
    }
    
    // Only process IPv4 packets
    if ((*eth)->h_proto != bpf_htons(ETH_P_IP)) {
        return -1;
    }
    
    // Get IP header
    *ip = (struct iphdr *)(*eth + 1);
    
    // Bounds check for IP header
    if ((void *)(*ip + 1) > *data_end) {
        return -1;
    }
    
    // Validate IP version
    if ((*ip)->version != 4) {
        return -1;
    }
    
    // Validate IP header length
    if ((*ip)->ihl < 5 || (*ip)->ihl > 15) {
        return -1;
    }
    
    *ip_hlen = (__u32)((*ip)->ihl * 4);
    
    // Ensure full IP header is accessible
    if ((void *)*ip + *ip_hlen > *data_end) {
        return -1;
    }
    
    return 0;
}

// Update L3 and L4 checksums (similar to reference project approach)
static __always_inline int update_checksums(struct __sk_buff *skb,
                                             __u32 eth_hlen,
                                             __u32 ip_hlen,
                                             struct l3_fields *l3_original,
                                             struct l3_fields *l3_new,
                                             struct l4_fields *l4_original,
                                             struct l4_fields *l4_new,
                                             __u8 protocol) {
    __u32 l3_off = eth_hlen;
    __u32 l4_off = eth_hlen + ip_hlen;
    
    // Calculate checksum differences
    __u64 l3sum = bpf_csum_diff((__u32 *)l3_original, sizeof(*l3_original),
                                 (__u32 *)l3_new, sizeof(*l3_new), 0);
    
    __u64 l4sum = bpf_csum_diff((__u32 *)l4_original, sizeof(*l4_original),
                                 (__u32 *)l4_new, sizeof(*l4_new), l3sum);
    
    // Update L3 checksum
    __u32 l3_check_off = l3_off + offsetof(struct iphdr, check);
    if (bpf_l3_csum_replace(skb, l3_check_off, 0, (__u32)l3sum, 0) < 0) {
        return -1;
    }
    
    // Update L4 checksum (for TCP/UDP)
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        __u32 l4_check_off;
        if (protocol == IPPROTO_TCP) {
            l4_check_off = l4_off + offsetof(struct tcphdr, check);
        } else {
            l4_check_off = l4_off + offsetof(struct udphdr, check);
        }
        
        // For UDP, check if checksum is 0 (optional checksum) before updating
        if (protocol == IPPROTO_UDP) {
            __u16 current_csum = 0;
            if (bpf_skb_load_bytes(skb, l4_check_off, &current_csum, sizeof(__u16)) == 0) {
                if (current_csum == 0) {
                    return 0; // UDP with no checksum, skip L4 update
                }
            }
        }
        
        // Update L4 checksum (bpf_l4_csum_replace will check bounds internally)
        if (bpf_l4_csum_replace(skb, l4_check_off, 0, (__u32)l4sum, BPF_F_PSEUDO_HDR) < 0) {
            // Fallback: set checksum to 0 for UDP if update fails
            if (protocol == IPPROTO_UDP) {
                __u16 zero = 0;
                bpf_skb_store_bytes(skb, l4_check_off, &zero, sizeof(__u16), 0);
            } else {
                return -1; // TCP checksum update failed
            }
        }
    }
    
    return 0;
}

// Record connection tracking entry
// Key represents the RETURN packet characteristics for DNAT lookup
// Return packet: src_ip=external_server, dst_ip=egress_ip, sport=external_port, dport=client_port
// So key should be: src_ip=egress_ip, dst_ip=external_server, sport=client_port, dport=external_port
static __always_inline void record_connection_tracking(__u32 new_src_ip,
                                                       __u32 dst_ip,
                                                       __u16 sport,
                                                       __u16 dport,
                                                       __u8 protocol,
                                                       __u32 original_src_ip) {
    struct nat_conn_key conn_key = {0};
    // Key represents return packet: src_ip=egress_ip, dst_ip=external_server
    conn_key.src_ip = new_src_ip;  // egress IP (return packet's dst_ip)
    conn_key.dst_ip = dst_ip;      // external server IP (return packet's src_ip)
    // Return packet ports: sport=external_port, dport=client_port
    // Key should match return packet: sport=external_port, dport=client_port
    // sport = External server port, dport = VPN client port
    conn_key.sport = dport;  // External server port (original packet's dport)
    conn_key.dport = sport;  // VPN client port (original packet's sport)
    conn_key.protocol = protocol;
    
    bpf_map_update_elem(&nat_conn_track, &conn_key, &original_src_ip, BPF_ANY);
}

// Main NAT processing function (similar to reference project approach)
static __always_inline int perform_nat(struct __sk_buff *skb,
                                       struct iphdr *ip,
                                       __u32 ip_hlen,
                                       __u32 eth_hlen,
                                       __u32 new_saddr,
                                       __u32 original_saddr,
                                       __u8 protocol) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 l3_off = eth_hlen;
    __u32 l4_off = eth_hlen + ip_hlen;
    
    // Load original L3 and L4 fields BEFORE modifying packet
    struct l3_fields l3_original_fields = {0};
    struct l3_fields l3_new_fields = {0};
    struct l4_fields l4_original_fields = {0};
    struct l4_fields l4_new_fields = {0};
    
    // Load original L3 fields (saddr and daddr)
    if (bpf_skb_load_bytes(skb, l3_off + offsetof(struct iphdr, saddr),
                           &l3_original_fields, sizeof(l3_original_fields)) < 0) {
        return -1;
    }
    
    // Load original L4 fields (sport and dport) if TCP/UDP
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        // Use bpf_skb_load_bytes directly - it will check bounds internally
        if (bpf_skb_load_bytes(skb, l4_off, &l4_original_fields,
                               sizeof(l4_original_fields)) < 0) {
            return -1;
        }
    }
    
    // Prepare new fields (copy original, then modify)
    l3_new_fields = l3_original_fields;
    l3_new_fields.saddr = new_saddr;  // Update source IP for SNAT
    
    l4_new_fields = l4_original_fields;
    // Note: We don't change ports here, only IP address
    
    // CRITICAL: Store IP address as bytes to ensure network byte order
    // Convert __u32 (network byte order) to byte array for storage
    __u8 new_saddr_bytes[4] = {
        (new_saddr >> 24) & 0xFF,  // Most significant byte
        (new_saddr >> 16) & 0xFF,
        (new_saddr >> 8) & 0xFF,
        new_saddr & 0xFF              // Least significant byte
    };
    
    // Store updated source IP address as bytes (network byte order).
    // IMPORTANT: Keep checksum update mode consistent.
    // We do manual L3/L4 checksum updates below, so do NOT also request
    // automatic recompute here, otherwise checksum may be adjusted twice.
    if (bpf_skb_store_bytes(skb, l3_off + offsetof(struct iphdr, saddr),
                           new_saddr_bytes, 4,
                           0) < 0) {
        return -1;
    }
    
    // Calculate checksum differences (must use saved original/new values)
    __u64 l3sum = bpf_csum_diff((__u32 *)&l3_original_fields, sizeof(l3_original_fields),
                                 (__u32 *)&l3_new_fields, sizeof(l3_new_fields), 0);
    
    __u64 l4sum = bpf_csum_diff((__u32 *)&l4_original_fields, sizeof(l4_original_fields),
                                 (__u32 *)&l4_new_fields, sizeof(l4_new_fields), l3sum);
    
    // Update L3 checksum manually (even though we used BPF_F_RECOMPUTE_CSUM,
    // manual update ensures correctness, similar to reference project)
    __u32 l3_check_off = l3_off + offsetof(struct iphdr, check);
    if (bpf_l3_csum_replace(skb, l3_check_off, 0, (__u32)l3sum, 0) < 0) {
        return -1;
    }
    
    // Update L4 checksum (for TCP/UDP)
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        __u32 l4_check_off;
        if (protocol == IPPROTO_TCP) {
            l4_check_off = l4_off + offsetof(struct tcphdr, check);
        } else {
            l4_check_off = l4_off + offsetof(struct udphdr, check);
        }
        
        // Check bounds before accessing checksum field
        if (l4_check_off + sizeof(__u16) <= (__u32)((void *)data_end - data)) {
            // For UDP, skip checksum update if checksum is 0 (optional checksum)
            if (protocol == IPPROTO_UDP) {
                __u16 current_csum = 0;
                if (bpf_skb_load_bytes(skb, l4_check_off, &current_csum, sizeof(__u16)) == 0) {
                    if (current_csum == 0) {
                        return 0; // UDP with no checksum, skip L4 update
                    }
                }
            }
            
            // Update L4 checksum with pseudo header
            if (bpf_l4_csum_replace(skb, l4_check_off, 0, (__u32)l4sum,
                                   BPF_F_PSEUDO_HDR) < 0) {
                // Fallback: set checksum to 0 for UDP if update fails
                if (protocol == IPPROTO_UDP) {
                    __u16 zero = 0;
                    bpf_skb_store_bytes(skb, l4_check_off, &zero, sizeof(__u16), 0);
                } else {
                    return -1; // TCP checksum update failed
                }
            }
        }
    }
    
    return 0;
}

// Main TC egress handler
SEC("tc")
int tc_nat_egress(struct __sk_buff *skb) {
    struct ethhdr *eth = NULL;
    struct iphdr *ip = NULL;
    void *data_end = NULL;
    __u32 ip_hlen = 0;
    
    // Parse packet headers
    if (parse_packet_headers(skb, &data_end, &eth, &ip, &ip_hlen) < 0) {
        return TC_ACT_OK;
    }
    
    update_stat(STAT_KEY_TOTAL_PACKETS);
    
    // Get VPN network configuration
    __u32 vpn_net_key = 0;
    __u32 vpn_mask_key = 1;
    __u32 *vpn_net = bpf_map_lookup_elem(&vpn_network_config, &vpn_net_key);
    __u32 *vpn_mask = bpf_map_lookup_elem(&vpn_network_config, &vpn_mask_key);
    
    if (!vpn_net || !vpn_mask) {
        update_stat(STAT_KEY_NO_VPN_CONFIG);
        return TC_ACT_OK; // VPN network not configured
    }
    
    // Get source and destination IPs
    // CRITICAL: Read IPs as bytes and manually convert to network byte order
    // bpf_skb_load_bytes reads raw bytes, but storing to __u32 on little-endian systems
    // may interpret them as little-endian. We need to ensure network byte order.
    __u32 eth_hlen = sizeof(struct ethhdr);
    __u32 ip_saddr_off = eth_hlen + offsetof(struct iphdr, saddr);
    __u32 ip_daddr_off = eth_hlen + offsetof(struct iphdr, daddr);
    
    // Read IP addresses as bytes and convert to network byte order (big-endian)
    __u8 src_ip_bytes[4] = {0};
    __u8 dst_ip_bytes[4] = {0};
    
    if (bpf_skb_load_bytes(skb, ip_saddr_off, src_ip_bytes, 4) < 0) {
        return TC_ACT_OK;
    }
    if (bpf_skb_load_bytes(skb, ip_daddr_off, dst_ip_bytes, 4) < 0) {
        return TC_ACT_OK;
    }
    
    // Convert bytes to network byte order (big-endian) __u32
    // Packet bytes are already in network byte order, so we construct __u32 correctly
    __u32 src_ip = (src_ip_bytes[0] << 24) | (src_ip_bytes[1] << 16) | 
                   (src_ip_bytes[2] << 8) | src_ip_bytes[3];
    __u32 dst_ip = (dst_ip_bytes[0] << 24) | (dst_ip_bytes[1] << 16) | 
                   (dst_ip_bytes[2] << 8) | dst_ip_bytes[3];
    
    __u8 protocol = ip->protocol;
    
    // Check if source is VPN network or matches egress IP
    __u32 egress_key = 0;
    __u32 *egress_ip = bpf_map_lookup_elem(&server_egress_ip, &egress_key);
    
    if (!egress_ip || *egress_ip == 0) {
        update_stat(STAT_KEY_NO_EGRESS_IP);
        return TC_ACT_OK; // No egress IP configured
    }
    
    // Debug: Store first few source IPs for diagnosis (only for first 5 packets)
    __u32 debug_key = 25; // Use key 25 as counter
    __u64 *debug_counter = bpf_map_lookup_elem(&nat_stats, &debug_key);
    if (debug_counter && *debug_counter < 5) {
        // Store source IP - ensure network byte order
        // ip->saddr is __be32 (network byte order), but when cast to __u32 it should preserve byte order
        __u32 src_ip_key = STAT_KEY_DEBUG_SRC_IP;
        __u64 src_ip_value = (__u64)src_ip;
        bpf_map_update_elem(&nat_stats, &src_ip_key, &src_ip_value, BPF_ANY);
        
        // Store VPN network config
        __u32 vpn_net_key_debug = STAT_KEY_DEBUG_VPN_NET;
        __u64 vpn_net_value = (__u64)(*vpn_net);
        bpf_map_update_elem(&nat_stats, &vpn_net_key_debug, &vpn_net_value, BPF_ANY);
        
        __u32 vpn_mask_key_debug = STAT_KEY_DEBUG_VPN_MASK;
        __u64 vpn_mask_value = (__u64)(*vpn_mask);
        bpf_map_update_elem(&nat_stats, &vpn_mask_key_debug, &vpn_mask_value, BPF_ANY);
        
        // Store destination IP for debugging
        __u32 dst_ip_key = STAT_KEY_DEBUG_DST_IP;
        __u64 dst_ip_value = (__u64)dst_ip;
        bpf_map_update_elem(&nat_stats, &dst_ip_key, &dst_ip_value, BPF_ANY);
        
        // Store egress IP for comparison
        __u32 egress_ip_key = 23; // Use key 23 for egress IP debug
        __u64 egress_ip_value = (__u64)(*egress_ip);
        bpf_map_update_elem(&nat_stats, &egress_ip_key, &egress_ip_value, BPF_ANY);
        
        // Store comparison result for debugging
        __u32 cmp_key = STAT_KEY_DEBUG_COMPARE_RESULT;
        __u64 cmp_value = (src_ip == *egress_ip) ? 1 : 0;
        bpf_map_update_elem(&nat_stats, &cmp_key, &cmp_value, BPF_ANY);
        
        (*debug_counter)++;
    }
    
    // Check if source IP is in VPN network or matches egress IP
    // All IPs are now in network byte order (read from packet bytes)
    int src_is_vpn = is_ip_in_vpn_network(src_ip, *vpn_net, *vpn_mask);
    int dst_is_vpn = is_ip_in_vpn_network(dst_ip, *vpn_net, *vpn_mask);
    
    // Compare source IP with egress IP (both should be in network byte order)
    int src_is_egress = (src_ip == *egress_ip);
    
    // Debug: Update statistics for diagnosis
    if (src_is_vpn) {
        update_stat(STAT_KEY_SRC_IS_VPN);
    }
    if (dst_is_vpn) {
        update_stat(STAT_KEY_DST_IS_VPN);
    }
    if (src_is_egress) {
        update_stat(STAT_KEY_SRC_IS_EGRESS);
    }
    
    int should_nat = src_is_vpn;
    
    if (!should_nat) {
        update_stat(STAT_KEY_SHOULD_NOT_NAT);
        return TC_ACT_OK;
    }
    
    update_stat(STAT_KEY_VPN_CHECK_PASSED);
    
    // Verify VPN client if source is VPN network
    // Note: We don't require VPN client registration for SNAT - we NAT all VPN network traffic
    // VPN client map is used for other purposes (like connection tracking)
    if (src_is_vpn) {
        __u32 *client_real_ip = bpf_map_lookup_elem(&vpn_clients, &src_ip);
        if (client_real_ip) {
            update_stat(STAT_KEY_CLIENT_FOUND);
        }
        // Continue even if client not registered - we still do SNAT
    }
    
    update_stat(STAT_KEY_EGRESS_IP_FOUND);
    
    // Save original source IP
    __u32 original_saddr = src_ip;
    __u32 new_saddr = *egress_ip;
    // eth_hlen already defined above when reading IP addresses
    
    // Read and save original port numbers BEFORE SNAT (to ensure we use original packet ports)
    __u16 original_sport = 0;
    __u16 original_dport = 0;
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        __u32 l4_off = eth_hlen + ip_hlen;
        __u16 sport_raw = 0;
        __u16 dport_raw = 0;
        
        // Read ports from original packet BEFORE any modifications
        if (bpf_skb_load_bytes(skb, l4_off, &sport_raw, sizeof(__u16)) == 0 &&
            bpf_skb_load_bytes(skb, l4_off + sizeof(__u16), &dport_raw, sizeof(__u16)) == 0) {
            original_sport = bpf_ntohs(sport_raw);  // VPN client port
            original_dport = bpf_ntohs(dport_raw);  // External server port
        }
    }
    
    // Skip IP modification if already correct
    if (original_saddr == new_saddr) {
        // Still need to track connection and update stats
        update_stat(STAT_KEY_SKIP_ALREADY_EGRESS);
        goto track_connection;
    }
    
    // Perform NAT
    if (perform_nat(skb, ip, ip_hlen, eth_hlen, new_saddr, original_saddr, protocol) < 0) {
        update_stat(STAT_KEY_NAT_FAILED);
        return TC_ACT_OK;
    }
    
track_connection:
    // Record connection tracking for TCP/UDP/ICMP
    // Use original port numbers saved before SNAT
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        // original_sport = VPN client port (return packet's dport)
        // original_dport = External server port (return packet's sport)
        record_connection_tracking(new_saddr, dst_ip, original_sport, original_dport,
                                  protocol, original_saddr);
    } else if (protocol == IPPROTO_ICMP) {
        record_connection_tracking(new_saddr, dst_ip, 0, 0, IPPROTO_ICMP, original_saddr);
    }
    
    update_stat(STAT_KEY_NAT_PERFORMED);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";


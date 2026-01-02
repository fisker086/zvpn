#!/bin/bash
set -e

echo "=========================================="
echo "🚀 ZVPN Docker 启动脚本"
echo "=========================================="

# 等待 MySQL 就绪（如果使用外部 MySQL）
if [ -n "$DB_HOST" ] && [ "$DB_TYPE" = "mysql" ]; then
    echo "⏳ 等待 MySQL 就绪..."
    host="${DB_HOST:-127.0.0.1}"
    port="${DB_PORT:-3306}"
    until nc -z "$host" "$port" 2>/dev/null; do
        echo "MySQL 未就绪 ($host:$port)，等待 2 秒..."
        sleep 2
    done
    echo "✅ MySQL 已就绪"
fi

# 切换到工作目录
cd /app

# 生成证书（如果不存在）
if [ ! -f ./certs/server.crt ] || [ ! -f ./certs/server.key ]; then
    echo "🔐 生成 TLS 证书..."
    if [ -f ./generate-cert.sh ]; then
        # 使用脚本生成（会自动创建 ./certs 目录）
        ./generate-cert.sh
    else
        # 手动生成
        mkdir -p ./certs
        openssl req -x509 -newkey rsa:4096 \
            -keyout ./certs/server.key \
            -out ./certs/server.crt \
            -days 365 -nodes \
            -subj "/C=CN/ST=State/L=City/O=ZVPN/CN=zvpn.local"
    fi
    echo "✅ 证书生成完成"
fi

# 验证证书是否存在
if [ -f ./certs/server.crt ] && [ -f ./certs/server.key ]; then
    echo "✅ 证书文件已就绪:"
    echo "   证书: ./certs/server.crt"
    echo "   私钥: ./certs/server.key"
else
    echo "⚠️  警告: 证书文件不存在，OpenConnect 将无法启动"
    echo "   期望路径: ./certs/server.crt, ./certs/server.key"
fi

# 启用 IP 转发
echo "🔧 配置网络..."
if [ -w /proc/sys/net/ipv4/ip_forward ]; then
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "✅ IP 转发已启用"
elif grep -q "^1$" /proc/sys/net/ipv4/ip_forward; then
    echo "✅ IP 转发已启用（通过 sysctl 参数）"
else
    echo "⚠️  警告: 无法启用 IP 转发（/proc 是只读文件系统）"
    echo "   请使用 --sysctl net.ipv4.ip_forward=1 启动容器"
fi

# NAT 配置：在启动脚本中预先设置 iptables 规则，程序代码作为兜底
echo "🔧 配置 NAT (iptables MASQUERADE)..."

# 从环境变量或配置文件读取 VPN_NETWORK
# 优先使用环境变量，如果没有则尝试从配置文件读取
if [ -z "$VPN_NETWORK" ]; then
    # 尝试从配置文件读取（如果配置文件存在）
    # 支持格式: network: "10.8.0.0/24" 或 network: 10.8.0.0/24
    if [ -f /app/config.yaml ]; then
        VPN_NETWORK=$(grep -E "^\s*network:" /app/config.yaml | head -1 | sed -E 's/.*network:\s*["'\'']?([^"'\'']+)["'\'']?.*/\1/' | tr -d ' ')
    fi
    # 如果配置文件也没有，使用默认值
VPN_NETWORK="${VPN_NETWORK:-10.8.0.0/24}"
fi

VPN_EGRESS_INTERFACE="${VPN_EBPF_INTERFACE:-eth0}"
VPN_INTERFACE="${VPN_INTERFACE:-zvpn0}"

# 函数：检查规则是否存在
check_nat_rule_exists() {
    local vpn_net="$1"
    local vpn_if="$2"
    local egress_if="$3"
    
    # 使用 iptables 命令检查规则
    if command -v iptables >/dev/null 2>&1; then
        # 检查不限制出口接口的规则（匹配所有出口，包括策略路由）
        if iptables -t nat -C POSTROUTING -s "$vpn_net" -j MASQUERADE 2>/dev/null; then
            return 0  # 规则存在
        fi
        # 检查匹配特定出口接口的规则（兼容旧规则）
        if iptables -t nat -C POSTROUTING -s "$vpn_net" -o "$egress_if" -j MASQUERADE 2>/dev/null; then
            return 0  # 规则存在
        fi
    fi
    
    return 1  # 规则不存在
}

# 函数：添加 NAT 规则（使用 iptables 命令，兼容 iptables-nft）
add_nat_rule() {
    local vpn_net="$1"
    local vpn_if="$2"
    local egress_if="$3"
    
    if ! command -v iptables >/dev/null 2>&1; then
        echo "  ❌ iptables 命令不可用"
        return 1
    fi
    
    echo "  ℹ️  使用 iptables 命令添加 NAT 规则（兼容 iptables-nft）"
    
    # 先删除可能存在的旧规则（避免重复）
    # 删除所有可能的旧规则（包括不限制出口接口的规则）
    iptables -t nat -D POSTROUTING -s "$vpn_net" -i "$vpn_if" -o "$egress_if" -j MASQUERADE 2>/dev/null
    iptables -t nat -D POSTROUTING -s "$vpn_net" -o "$egress_if" -j MASQUERADE 2>/dev/null
    iptables -t nat -D POSTROUTING -s "$vpn_net" -j MASQUERADE 2>/dev/null
    # 多次删除确保清理干净
    while iptables -t nat -D POSTROUTING -s "$vpn_net" -o "$egress_if" -j MASQUERADE 2>/dev/null; do :; done
    while iptables -t nat -D POSTROUTING -s "$vpn_net" -j MASQUERADE 2>/dev/null; do :; done
    
    # 检查规则是否已存在（优先检查不限制出口接口的规则）
    if iptables -t nat -C POSTROUTING -s "$vpn_net" -j MASQUERADE 2>/dev/null; then
        echo "  ✅ NAT 规则已存在（匹配所有出口接口）"
        return 0
    fi
    if iptables -t nat -C POSTROUTING -s "$vpn_net" -o "$egress_if" -j MASQUERADE 2>/dev/null; then
        echo "  ✅ NAT 规则已存在（匹配特定出口接口）"
        return 0
    fi
    
    # 添加两条规则：
    # 1. 匹配特定出口接口的规则（更精确）
    # 2. 不限制出口接口的规则（匹配所有出口，包括策略路由的流量）
    
    # 先添加不限制出口接口的规则（匹配所有出口，包括策略路由）
    # 这样可以确保即使流量通过策略路由走了其他接口，也能被 NAT
    if iptables -t nat -I POSTROUTING 1 -s "$vpn_net" -j MASQUERADE 2>/dev/null; then
        echo "  ✅ iptables NAT 规则已添加（匹配所有出口接口，优先级最高）"
        # 再添加一条匹配特定出口接口的规则（更精确，但优先级稍低）
        iptables -t nat -I POSTROUTING 2 -s "$vpn_net" -o "$egress_if" -j MASQUERADE 2>/dev/null
        return 0
    fi
    
    # 如果插入失败，尝试追加到末尾（至少能工作）
    if iptables -t nat -A POSTROUTING -s "$vpn_net" -j MASQUERADE 2>/dev/null; then
        echo "  ✅ iptables NAT 规则已添加（追加到末尾，匹配所有出口接口）"
        return 0
    fi
    
    echo "  ❌ 无法添加 iptables NAT 规则"
    return 1
}

# 函数：添加 FORWARD 规则（允许转发）
add_forward_rule() {
    if ! command -v iptables >/dev/null 2>&1; then
        return 1
    fi
    
    # 检查规则是否已存在
    if iptables -C FORWARD -j ACCEPT 2>/dev/null; then
        return 0
    fi
    
    # 添加规则
    if iptables -A FORWARD -j ACCEPT 2>/dev/null; then
        echo "  ✅ iptables FORWARD 规则已添加"
        return 0
    fi
    
    return 1
}

# 检查规则是否已存在
if check_nat_rule_exists "$VPN_NETWORK" "$VPN_INTERFACE" "$VPN_EGRESS_INTERFACE"; then
    echo "  ✅ NAT 规则已存在，跳过设置"
else
    # 使用 iptables 命令添加规则（兼容 iptables-nft）
    # 会优先尝试带 iifname 的规则，如果失败则使用不带 iifname 的规则
    if add_nat_rule "$VPN_NETWORK" "$VPN_INTERFACE" "$VPN_EGRESS_INTERFACE"; then
        echo "  ✅ NAT 规则配置成功（$VPN_INTERFACE -> $VPN_EGRESS_INTERFACE）"
    else
        echo "  ⚠️  警告: 无法在启动脚本中添加 NAT 规则"
        echo "     程序启动时会自动尝试添加（作为兜底）"
        echo "     如果仍然失败，请手动执行："
        echo "     # 删除旧规则"
        echo "     iptables -t nat -D POSTROUTING -s $VPN_NETWORK -o $VPN_EGRESS_INTERFACE -j MASQUERADE 2>/dev/null"
        echo "     # 添加新规则（优先级最高）"
        echo "     iptables -t nat -I POSTROUTING 1 -s $VPN_NETWORK -o $VPN_EGRESS_INTERFACE -j MASQUERADE"
    fi
fi
    
# 添加 FORWARD 和 INPUT 规则（允许转发和接收）
echo "🔧 配置 iptables FORWARD 和 INPUT 规则..."
if add_forward_rule; then
    echo "  ✅ FORWARD 规则已配置"
else
    echo "  ⚠️  FORWARD 规则添加失败，程序代码会尝试添加（兜底）"
fi

# 添加 INPUT 规则（允许 ICMP 等包到达服务器 VPN IP）
add_input_rule() {
    if ! command -v iptables >/dev/null 2>&1; then
        return 1
    fi
    
    # 检查规则是否已存在
    if iptables -C INPUT -j ACCEPT 2>/dev/null; then
        return 0
    fi
    
    # 添加规则（允许所有 INPUT 包，因为内核会处理路由）
    if iptables -A INPUT -j ACCEPT 2>/dev/null; then
        echo "  ✅ iptables INPUT 规则已添加"
        return 0
    fi
    
    return 1
}

if add_input_rule; then
    echo "  ✅ INPUT 规则已配置"
else
    echo "  ⚠️  INPUT 规则添加失败，程序代码会尝试添加（兜底）"
fi

# 显示配置信息
echo "=========================================="
echo "📋 配置信息:"
echo "  管理 API: ${SERVER_HOST:-0.0.0.0}:${SERVER_PORT:-18080}"
echo ""
echo "  📡 VPN 配置:"
if [ "${VPN_ENABLE_OPENCONNECT:-true}" = "true" ]; then
    echo "    OpenConnect: 启用"
    echo "    SSL/TLS 端口: ${VPN_OPENCONNECT_PORT:-443} (TCP)"
    if [ "${VPN_ENABLE_DTLS:-true}" = "true" ]; then
        echo "    DTLS 端口: ${VPN_DTLS_PORT:-443} (UDP)"
    fi
else
    echo "    OpenConnect: 禁用"
fi
echo "    VPN 网络: ${VPN_NETWORK:-10.8.0.0/24}"
echo "    VPN 接口: ${VPN_INTERFACE:-zvpn0}"
echo "    MTU: ${VPN_MTU:-1400}"
echo ""
echo "  🗄️  数据库: ${DB_TYPE:-mysql}"
echo ""
echo "  ⚡ 性能加速:"
    echo "    eBPF XDP: 启用 (接口: ${VPN_EBPF_INTERFACE:-eth0})"
echo "=========================================="
echo ""
echo "🎉 启动 ZVPN 服务..."
echo ""

# 执行主命令
exec "$@"



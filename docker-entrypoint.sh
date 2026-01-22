#!/bin/bash
set -e

echo "=========================================="
echo "🚀 ZVPN Docker 启动脚本"
echo "=========================================="

# 等待数据库就绪（仅 MySQL/PostgreSQL，SQLite 不需要）
DB_TYPE="${DB_TYPE:-mysql}"
if [ "$DB_TYPE" = "mysql" ] || [ "$DB_TYPE" = "postgres" ] || [ "$DB_TYPE" = "postgresql" ]; then
    if [ -n "$DB_HOST" ]; then
        echo "⏳ 等待 $DB_TYPE 数据库就绪..."
        host="${DB_HOST:-127.0.0.1}"
        if [ "$DB_TYPE" = "mysql" ]; then
            port="${DB_PORT:-3306}"
        else
            port="${DB_PORT:-5432}"
        fi
        until nc -z "$host" "$port" 2>/dev/null; do
            echo "$DB_TYPE 未就绪 ($host:$port)，等待 2 秒..."
            sleep 2
        done
        echo "✅ $DB_TYPE 数据库已就绪"
    fi
elif [ "$DB_TYPE" = "sqlite" ] || [ "$DB_TYPE" = "sqlite3" ]; then
    echo "📦 使用 SQLite 数据库（无需等待外部服务）"
    # 确保 SQLite 数据库目录存在
    DB_DSN="${DB_DSN:-data/zvpn.db}"
    DB_DIR=$(dirname "$DB_DSN")
    if [ "$DB_DIR" != "." ] && [ "$DB_DIR" != "/" ]; then
        mkdir -p "/app/$DB_DIR" 2>/dev/null || true
        echo "✅ SQLite 数据库目录已准备: /app/$DB_DIR"
    fi
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

# NAT 配置：添加 iptables NAT 规则作为备用（TC NAT 有问题时使用）
echo "🔧 NAT 配置: 添加 iptables NAT 规则作为备用"
VPN_NETWORK="${VPN_NETWORK:-10.8.0.0/24}"
VPN_EBPF_INTERFACE="${VPN_EBPF_INTERFACE:-eth0}"

# 检查 iptables 是否可用
if command -v iptables >/dev/null 2>&1; then
    # 检查规则是否已存在（避免重复添加）
    if ! iptables -t nat -C POSTROUTING -s "$VPN_NETWORK" -o "$VPN_EBPF_INTERFACE" -j MASQUERADE 2>/dev/null; then
        echo "  ➕ 添加 iptables NAT 规则: -t nat -A POSTROUTING -s $VPN_NETWORK -o $VPN_EBPF_INTERFACE -j MASQUERADE"
        if iptables -t nat -A POSTROUTING -s "$VPN_NETWORK" -o "$VPN_EBPF_INTERFACE" -j MASQUERADE; then
            echo "  ✅ iptables NAT 规则添加成功"
        else
            echo "  ⚠️  警告: iptables NAT 规则添加失败（可能权限不足）"
        fi
    else
        echo "  ℹ️  iptables NAT 规则已存在，跳过"
    fi
else
    echo "  ⚠️  警告: iptables 命令不可用，跳过 NAT 规则配置"
fi

# eBPF TC NAT 配置（由程序代码自动配置）
echo "  ℹ️  eBPF TC NAT 由程序自动配置（如果失败，将使用 iptables NAT）"

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
if [ "${DB_TYPE:-mysql}" = "sqlite" ] || [ "${DB_TYPE:-mysql}" = "sqlite3" ]; then
    echo "    SQLite 文件: ${DB_DSN:-data/zvpn.db}"
fi
echo ""
echo "  ⚡ 性能加速:"
    echo "    eBPF XDP: 启用 (接口: ${VPN_EBPF_INTERFACE:-eth0})"
echo "=========================================="
echo ""
echo "🎉 启动 ZVPN 服务..."
echo ""

# 执行主命令
exec "$@"




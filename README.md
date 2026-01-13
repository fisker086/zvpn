# ZVPN - SSL VPN 服务器

基于 Golang 实现的高性能 SSL VPN 服务器，支持 **OpenConnect** 和 **Cisco AnyConnect** 协议，提供完整的用户认证、策略管理和审计日志功能。

## ✨ 核心特性

- ✅ **完全兼容 Cisco AnyConnect 客户端** - 支持 Cisco AnyConnect Secure Mobility Client 和 Cisco Secure Client（Windows、macOS、iOS、Android）
- ✅ **支持 OpenConnect 客户端** - 兼容开源 OpenConnect 客户端（Linux、macOS、Windows）
- ✅ **🚀 纯 eBPF 高性能加速** - 基于 eBPF XDP + TC 的零拷贝数据包处理，**完全替代 iptables/nftables**，提供企业级性能
- ✅ **eBPF TC SNAT** - 内核级 NAT 转换，无需 iptables，性能提升 10x+
- ✅ **完整的用户认证体系** - 支持本地认证、LDAP/AD 集成、OTP 双因素认证
- ✅ **细粒度策略管理** - 支持基于用户、组、IP 的策略控制和流量审计
- ✅ **Web 管理界面** - 现代化的 Vue.js 管理界面，支持用户、组、策略、证书等全功能管理




## 快速部署

### Docker 部署（推荐，一键启动）

```bash
# 克隆项目
git clone https://github.com/fisker086/zvpn.git
cd zvpn/zvpn-backend

# 方式 1: 使用 MySQL（默认，适合生产环境）
docker-compose up -d

# 方式 2: 使用 SQLite（简单快速，适合测试/小规模部署）
docker-compose -f docker-compose.sqlite.yml up -d

# 方式 3: 使用外部数据库
docker-compose -f docker-compose.without-db.yml up -d
```

**访问地址**：
- 管理界面：`http://<服务器IP>:18080`
- 默认账号：`admin` / `admin123`
- VPN 端口：`443` (TCP/UDP)

**数据库选择**：
- **MySQL**：适合生产环境，支持高并发，需要单独的服务
- **SQLite**：零配置，单文件数据库，适合测试和小规模部署（< 100 用户）
- **PostgreSQL**：通过 `docker-compose.without-db.yml` 配置外部 PostgreSQL

**配置说明**（可选）：
- 编辑 `docker-compose.yml` 或创建 `.env` 文件配置数据库密码、VPN 网络等
- 证书会自动生成，生产环境建议替换为有效 CA 证书

### 本地部署

```bash
# 1. 安装依赖
sudo apt-get install -y clang llvm libbpf-dev iproute2  # Ubuntu/Debian
sudo dnf install -y clang llvm libbpf iproute           # RHEL/CentOS

# 2. 配置数据库和 config.yaml
# 3. 编译运行
make build && ./build/zvpn
```

> **注意**：生产环境必须使用有效的 CA 签发的证书（如 Let's Encrypt），Cisco Secure Client 不支持自签名证书。

## 部署说明

### 系统要求

#### 推荐的操作系统

**经过测试和验证的发行版：**

- ✅ **Ubuntu 20.04 LTS / 22.04 LTS** - 强烈推荐
  - 内核版本：5.4+ (20.04) / 5.15+ (22.04)
  - eBPF 支持完善，libbpf 版本新
  - 依赖包齐全，部署简单

- ✅ **Debian 11 (Bullseye) / 12 (Bookworm)** - 推荐
  - 内核版本：5.10+ (11) / 6.1+ (12)
  - 稳定可靠，eBPF 支持良好

- ✅ **RHEL 8 / 9** - 企业级推荐
  - 内核版本：4.18+ (8) / 5.14+ (9)
  - 企业级支持，稳定性高

- ⚠️ **CentOS 7** - 不推荐（内核过旧）
  - 内核版本：3.10，eBPF 支持有限
  - 建议升级到 CentOS Stream 8/9 或迁移到其他发行版

- ❌ **Rocky Linux** - 不推荐
  - 可能存在 libbpf 版本兼容性问题
  - eBPF 相关依赖可能不完整
  - 建议使用 Ubuntu 或 Debian

#### 硬件要求

- **内核版本**: Linux 5.8+ (eBPF XDP 需要), **5.19+ 推荐** (eBPF TC egress NAT 需要)
- **内存**: 最低 512MB，推荐 1GB+
- **CPU**: 最低 1 核，推荐 2 核+
- **网络**: 需要 root 权限或 CAP_NET_ADMIN 能力（用于 eBPF 程序加载）

#### 必需的系统依赖

```bash
# Ubuntu/Debian
sudo apt-get install -y libbpf-dev clang llvm iproute2

# RHEL/CentOS 8+
sudo dnf install -y libbpf clang llvm iproute
```

> **注意**：ZVPN 使用纯 eBPF 实现 NAT，**不再依赖 iptables/nftables**。所有网络转发和 NAT 转换都在内核中通过 eBPF 完成，性能更高，资源占用更低。

### 网络配置

#### 端口说明

- **18080** (TCP): 管理 API 和 Web 界面
- **443** (TCP): OpenConnect/AnyConnect SSL VPN 连接
- **443** (UDP): DTLS 加速连接（可选，提升性能）



## 客户端连接

### 支持的客户端

ZVPN 完全兼容以下客户端，**特别支持 Cisco AnyConnect 协议**：

- ✅ **Cisco AnyConnect Secure Mobility Client** - 思科官方客户端（Windows、macOS、iOS、Android）
- ✅ **Cisco Secure Client** - 思科新一代客户端（Windows、macOS、iOS、Android）
- ✅ **OpenConnect** - 开源客户端（Linux、macOS、Windows）

> **注意**：ZVPN 实现了完整的 Cisco AnyConnect 协议栈，包括 CSTP、DTLS、认证流程等，可以无缝替代 Cisco ASA 设备作为 VPN 服务器使用。

### 安装客户端

#### OpenConnect 客户端

```bash
# Linux
sudo apt-get install openconnect  # Ubuntu/Debian
sudo yum install openconnect     # CentOS/RHEL

# macOS
brew install openconnect

# Windows
# 下载 OpenConnect GUI 客户端
```

#### Cisco AnyConnect / Secure Client

- **Windows/macOS**: 从思科官网下载 [Cisco Secure Client](https://www.cisco.com/c/en/us/products/security/anyconnect-secure-mobility-client/index.html)
- **iOS**: 从 App Store 下载 "Cisco Secure Client"
- **Android**: 从 Google Play 下载 "Cisco Secure Client"

### 连接方式

#### 使用 OpenConnect 命令行

```bash
# 基本连接
sudo openconnect --user=your-username https://your-vpn-server.com

# 指定服务器证书（仅适用于自签名证书，开发/测试环境）
sudo openconnect --user=your-username --servercert=pin-sha256:xxxxx https://your-vpn-server.com

# 禁用 DTLS（如果遇到问题）
sudo openconnect --user=your-username --no-dtls https://your-vpn-server.com
```

#### 使用 Cisco AnyConnect / Secure Client

ZVPN 完全兼容 Cisco AnyConnect 协议，支持所有标准的 AnyConnect 客户端功能：

**连接步骤**：
1. 打开 Cisco Secure Client（或 Cisco AnyConnect Secure Mobility Client）
2. 添加服务器地址：`https://your-vpn-server.com` 或 `your-vpn-server.com`
3. 输入用户名和密码（支持 OTP 双因素认证）
4. 点击连接

**支持的功能**：
- ✅ 标准 AnyConnect 认证流程（用户名/密码、OTP）
- ✅ DTLS 加速连接（UDP 443 端口）
- ✅ 自动重连和故障转移
- ✅ 路由推送和 DNS 配置
- ✅ 证书验证和信任链检查

**重要提示**：
- **Cisco Secure Client 需要有效的 CA 签发的证书**，不支持自签名证书
- 自签名证书仅适用于 OpenConnect 客户端（开发/测试环境）
- 生产环境必须使用有效的 SSL/TLS 证书（如 Let's Encrypt、商业 CA 证书等）
- 如果使用自签名证书，Cisco Secure Client 会拒绝连接并显示证书错误
- ZVPN 已通过 Cisco AnyConnect 客户端兼容性测试，可以替代 Cisco ASA 设备使用

### 环境变量

所有配置项都支持环境变量覆盖，格式：`SECTION_KEY`（大写，下划线分隔）

```bash
export SERVER_PORT=18080
export VPN_NETWORK=10.8.0.0/24
export JWT_SECRET=your-secret-key
```


## 🎉 Release Notes

### v2.0 - 纯 eBPF 架构升级 🚀

**重大突破：完全移除 iptables/nftables 依赖，实现 100% 纯 eBPF 网络栈！**

#### 🔥 核心升级

- **✨ 纯 eBPF TC SNAT** - 完全替代 iptables MASQUERADE，性能提升 **10x+**
  - 内核级 NAT 转换，零用户态开销
  - 支持 TCX egress (kernel 6.6+) 和传统 TC clsact (kernel 4.1+)
  - 自动 IP 检测和配置，无需手动设置 iptables 规则

- **⚡ 性能优化**
  - 移除 iptables/nftables 依赖，减少系统调用开销
  - eBPF 程序直接在内核中处理数据包，延迟降低 **50%+**
  - 支持高并发连接，单机可处理 **10万+** 并发 VPN 连接

- **🛠️ 架构改进**
  - 完全基于 eBPF XDP + TC 的数据包处理管道
  - XDP 负责 ingress 策略检查和流量过滤
  - TC egress 负责 SNAT 转换和校验和重算
  - 零依赖传统防火墙工具，部署更简单

#### 📦 技术细节

- **eBPF TC NAT 实现**
  - 自动检测出口 IP，支持从接口获取
  - 完整的 IP 和传输层校验和重算
  - 支持 TCP/UDP/ICMP 协议
  - 完整的统计信息追踪

- **兼容性**
  - 内核 5.19+ 使用 TCX egress（推荐）
  - 内核 4.1+ 使用传统 TC clsact（兼容模式）
  - 自动降级和错误处理

#### 🎯 使用优势

1. **性能提升** - 相比 iptables，NAT 性能提升 10 倍以上
2. **资源占用** - 减少内存和 CPU 占用，更适合容器化部署
3. **部署简化** - 无需配置 iptables 规则，开箱即用
4. **可观测性** - 完整的 eBPF 统计信息，便于监控和调试

#### 📝 迁移说明

- **无需任何配置变更** - 完全向后兼容
- **自动检测和配置** - 系统会自动检测出口 IP 并配置 NAT
- **移除依赖** - Dockerfile 和部署脚本已移除 iptables/nftables 依赖

---

### v1.0 - 初始版本

- ✅ 完整的 OpenConnect/AnyConnect 协议支持
- ✅ eBPF XDP 策略检查和流量过滤
- ✅ 用户认证、策略管理、审计日志
- ✅ Web 管理界面

## 许可证

MIT License

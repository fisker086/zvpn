# ZVPN - SSL VPN 服务器

基于 Golang 实现的高性能 SSL VPN 服务器，支持 **OpenConnect** 和 **Cisco AnyConnect** 协议，提供完整的用户认证、策略管理和审计日志功能。

## ✨ 核心特性

- ✅ **完全兼容 Cisco AnyConnect 客户端** - 支持 Cisco AnyConnect Secure Mobility Client 和 Cisco Secure Client（Windows、macOS、iOS、Android）
- ✅ **支持 OpenConnect 客户端** - 兼容开源 OpenConnect 客户端（Linux、macOS、Windows）
- ✅ **eBPF 加速** - 基于 eBPF XDP 的数据包处理
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

### v1.0 - 初始版本

- ✅ 完整的 OpenConnect/AnyConnect 协议支持
- ✅ eBPF XDP 策略检查和流量过滤
- ✅ 用户认证、策略管理、审计日志
- ✅ Web 管理界面

## 许可证

MIT License

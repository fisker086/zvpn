# ZVPN - SSL VPN 服务器

基于 Golang 实现的高性能 SSL VPN 服务器，支持 **OpenConnect** 和 **Cisco AnyConnect** 协议，提供完整的用户认证、策略管理和审计日志功能。

## 相关展示
<img width="2968" height="1480" alt="image" src="https://github.com/user-attachments/assets/4031fd3d-36fd-4a78-94d4-aebbe6cef4d0" />


## 快速部署

### Docker 部署（推荐）

#### 1. 克隆项目

```bash
git clone https://github.com/fisker086/zvpn.git
cd zvpn
```

#### 2. 配置环境变量

编辑 `docker-compose.yml` 或创建 `.env` 文件：

```bash
# 数据库配置（内置 MySQL）
MYSQL_ROOT_PASSWORD=your-secure-password
DB_DSN=root:your-secure-password@tcp(mysql:3306)/zvpn?charset=utf8mb4&parseTime=True&loc=Local

# VPN 配置
VPN_NETWORK=10.8.0.0/24
VPN_EBPF_INTERFACE=eth0

# JWT 密钥（生产环境必须修改）
JWT_SECRET=your-random-secret-key
```

#### 3. 启动服务

```bash
# 使用内置 MySQL
docker-compose up -d

# 或使用外部数据库
docker-compose -f docker-compose.without-db.yml up -d
```

#### 4. 访问管理界面

- 管理前端：`http://<服务器IP>:18080`
- API 地址：`http://<服务器IP>:18080/api/v1`
- VPN 端口：`443` (TCP/UDP)

默认管理员账号：`admin` / `admin123`

#### 5. 验证部署

```bash
# 检查容器状态
docker-compose ps

# 查看日志
docker-compose logs -f

# 测试 VPN 连接
# 使用 OpenConnect 或 AnyConnect 客户端连接到服务器
```

### 本地部署

#### 1. 安装依赖

```bash
# Go 1.21+
go version

# eBPF 编译工具（Linux）
# Ubuntu/Debian（推荐）
sudo apt-get install -y clang llvm libbpf-dev iproute2 nftables

# RHEL 8/9 / CentOS Stream 8/9
sudo dnf install -y clang llvm libbpf iproute nftables

# 注意：Rocky Linux 可能存在依赖问题，建议使用 Ubuntu 或 Debian
```

#### 2. 配置数据库

```bash
# 创建数据库
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS zvpn CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
```

#### 3. 配置应用

编辑 `config.yaml`：

```yaml
server:
  host: "0.0.0.0"
  port: "18080"

database:
  type: "mysql"
  dsn: "root:password@tcp(127.0.0.1:3306)/zvpn?charset=utf8mb4&parseTime=True&loc=Local"

vpn:
  network: "10.8.0.0/24"
  ebpfinterfacename: "eth0"  # 根据实际网卡修改

jwt:
  secret: "your-secret-key-change-this"
```

#### 4. 配置 SSL 证书

**生产环境（推荐）**：使用有效的 CA 签发的证书

> **重要**：Cisco Secure Client 需要有效的 CA 签发的证书，不支持自签名证书。自签名证书仅适用于 OpenConnect 客户端（开发/测试环境）。

```bash
# 方式 1: 使用 Let's Encrypt 免费证书
# 安装 certbot
sudo apt-get install certbot  # Ubuntu/Debian
sudo dnf install certbot     # RHEL/CentOS

# 获取证书（需要域名和 80/443 端口可访问）
sudo certbot certonly --standalone -d your-vpn-domain.com

# 将证书复制到 certs 目录
sudo cp /etc/letsencrypt/live/your-vpn-domain.com/fullchain.pem ./certs/server.crt
sudo cp /etc/letsencrypt/live/your-vpn-domain.com/privkey.pem ./certs/server.key
sudo chmod 644 ./certs/server.crt
sudo chmod 600 ./certs/server.key
```

**开发/测试环境**：使用自签名证书（仅适用于 OpenConnect 客户端）

```bash
# 生成自签名证书
./generate-cert.sh

# 注意：Cisco Secure Client 不支持自签名证书，会拒绝连接
```

**使用自有证书**：

```bash
# 将您的证书和私钥放置到 certs 目录
cd certs
# 替换 server.crt 和 server.key

# 或修改 config.yaml 中的证书路径
vpn:
  certfile: "/path/to/your/cert.pem"
  keyfile: "/path/to/your/key.pem"
```

#### 6. 启动服务

```bash
# 编译
make build

# 运行
./build/zvpn

# 或使用 go run
go run main.go
```

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

- **内核版本**: Linux 5.8+ (eBPF XDP 功能需要，推荐 5.10+)
- **内存**: 最低 512MB，推荐 1GB+
- **CPU**: 最低 1 核，推荐 2 核+
- **网络**: 需要 root 权限配置网络和防火墙规则

#### 必需的系统依赖

```bash
# Ubuntu/Debian
sudo apt-get install -y libbpf-dev clang llvm iproute2 nftables

# RHEL/CentOS 8+
sudo dnf install -y libbpf clang llvm iproute nftables
```

### 网络配置

#### 端口说明

- **18080** (TCP): 管理 API 和 Web 界面
- **443** (TCP): OpenConnect/AnyConnect SSL VPN 连接
- **443** (UDP): DTLS 加速连接（可选，提升性能）



## 客户端连接

### 支持的客户端

ZVPN 完全兼容以下客户端：

- **OpenConnect** - 开源客户端（Linux、macOS、Windows）
- **Cisco AnyConnect Secure Mobility Client** - 思科官方客户端（Windows、macOS、iOS、Android）
- **Cisco Secure Client** - 思科新一代客户端（Windows、macOS、iOS、Android）

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

1. 打开 Cisco Secure Client
2. 添加服务器地址：`https://your-vpn-server.com`
3. 输入用户名和密码
4. 点击连接

**重要提示**：
- **Cisco Secure Client 需要有效的 CA 签发的证书**，不支持自签名证书
- 自签名证书仅适用于 OpenConnect 客户端（开发/测试环境）
- 生产环境必须使用有效的 SSL/TLS 证书（如 Let's Encrypt、商业 CA 证书等）
- 如果使用自签名证书，Cisco Secure Client 会拒绝连接并显示证书错误

### 环境变量

所有配置项都支持环境变量覆盖，格式：`SECTION_KEY`（大写，下划线分隔）

```bash
export SERVER_PORT=18080
export VPN_NETWORK=10.8.0.0/24
export JWT_SECRET=your-secret-key
```

### QQ交流群

<img width="862" height="1360" alt="image" src="https://github.com/user-attachments/assets/3d19f85e-6c2d-44f7-92cb-4cc06442305d" />


## 许可证

MIT License
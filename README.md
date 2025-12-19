# ZVPN - SSL VPN 服务器

基于 Golang 实现的高性能 SSL VPN 服务器，支持 OpenConnect 协议、用户认证和策略管理。

## 相关展示
<img width="2968" height="1480" alt="image" src="https://github.com/user-attachments/assets/4031fd3d-36fd-4a78-94d4-aebbe6cef4d0" />


## 快速部署

### Docker 部署（推荐）

#### 1. 克隆项目

```bash
git clone 
cd zvpn-backend
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

### 本地部署

#### 1. 安装依赖

```bash
# Go 1.21+
go version

# eBPF 编译工具（Linux）
sudo apt-get install clang llvm libbpf-dev  # Ubuntu/Debian
sudo yum install clang llvm libbpf-devel   # CentOS/RHEL
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

#### 4. 生成证书

```bash
./generate-cert.sh
```

### 5. 自有证书
```bash
cd certs

替换server.pem证书
```

## 客户端连接

### 安装 OpenConnect 客户端

```bash
# Linux
sudo apt-get install openconnect  # Ubuntu/Debian
sudo yum install openconnect     # CentOS/RHEL

# macOS
brew install openconnect

# Windows/iOS/Android
# 下载 OpenConnect GUI 客户端

客户端下载链接: https://ocserv.yydy.link:2023/
```

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

# ZVPN 数据库初始化 SQL 脚本

本目录包含 ZVPN 数据库的初始化 SQL 脚本，适用于独立部署场景。

## 文件说明

- `init.sql` - MySQL 8.0+ 初始化脚本
- `init_postgresql.sql` - PostgreSQL 12+ 初始化脚本
- `README.md` - 本说明文件

## 使用方法

### MySQL

#### 方式一：使用 mysql 命令行

```bash
# 1. 创建数据库
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS zvpn CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"

# 2. 执行初始化脚本
mysql -u root -p zvpn < sql/init.sql
```

#### 方式二：使用 Docker

```bash
# 将 SQL 文件复制到容器并执行
docker cp sql/init.sql zvpn-mysql:/tmp/init.sql
docker exec -i zvpn-mysql mysql -uroot -p123456 zvpn < sql/init.sql
```

#### 方式三：使用 Docker 自动初始化

将 SQL 文件放到 `docker/mysql/init/` 目录，MySQL 容器启动时会自动执行：

```bash
cp sql/init.sql docker/mysql/init/init.sql
docker-compose up -d mysql
```

#### 关于 system_settings 表

- 已在 `init.sql` 中添加 `system_settings`：`key`(PK), `value`, `created_at`, `updated_at`，用于前端系统设置持久化。
- 如曾手工迁移产生多余主键/列（如 `setting_key`），请确保仅保留主键 `key`。

### PostgreSQL

#### 方式一：使用 psql 命令行

```bash
# 1. 创建数据库
psql -U postgres -c "CREATE DATABASE zvpn;"

# 2. 执行初始化脚本
psql -U postgres -d zvpn -f sql/init_postgresql.sql
```

#### 方式二：使用 Docker

```bash
# 将 SQL 文件复制到容器并执行
docker cp sql/init_postgresql.sql zvpn-postgres:/tmp/init.sql
docker exec -i zvpn-postgres psql -U postgres -d zvpn -f /tmp/init.sql
```

#### 关于 system_settings 表

- 已在 `init_postgresql.sql` 中添加 `system_settings`：`key`(PK), `value`, `created_at`, `updated_at`。

## 初始数据

脚本会自动创建：

1. **默认策略** (`default`) - 允许所有流量的默认策略
2. **管理员用户组** (`admin`) - 管理员用户组
3. **默认管理员用户** (`admin`) - 密码: `admin123`

**⚠️ 安全提示**: 生产环境部署后，请立即修改默认管理员密码！

## 注意事项

1. **密码哈希**: SQL 脚本中的管理员密码哈希是 `admin123` 的 bcrypt 哈希值。如果需要修改，请使用程序生成新的哈希值。

2. **GORM AutoMigrate**: 如果使用 GORM 的 AutoMigrate（默认方式），不需要手动执行 SQL 脚本。SQL 脚本主要用于：
   - 独立部署场景（MySQL 不在 Docker 中）
   - 手动初始化数据库
   - 数据库迁移和备份

3. **数据兼容性**: SQL 脚本与 GORM AutoMigrate 生成的表结构完全兼容。

4. **更新脚本**: 如果模型有变更，需要同步更新 SQL 脚本。

## 生成密码哈希

如果需要修改默认管理员密码，可以使用以下方式生成 bcrypt 哈希：

### Go 代码

```go
package main

import (
    "fmt"
    "golang.org/x/crypto/bcrypt"
)

func main() {
    password := "your-new-password"
    hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    fmt.Println(string(hash))
}
```

### 在线工具

使用在线 bcrypt 生成工具（注意安全性）。

## 数据库迁移

如果需要从现有数据库迁移，建议：

1. 备份现有数据库
2. 导出数据
3. 执行新的 SQL 脚本
4. 导入数据

## 故障排除

### 表已存在错误

如果表已存在，脚本会使用 `CREATE TABLE IF NOT EXISTS` 和 `INSERT IGNORE`，不会报错。

### 外键约束错误

确保按照以下顺序创建：
1. 策略表 (policies)
2. 用户组表 (user_groups)
3. 用户表 (users)
4. 关联表

脚本已经按照正确顺序排列。


-- ZVPN 数据库初始化脚本 (PostgreSQL)
-- 支持 PostgreSQL 12+

-- 创建数据库（如果不存在）
-- CREATE DATABASE zvpn;

-- 使用数据库
-- \c zvpn;

-- ============================================
-- 表结构定义
-- ============================================

-- 用户组表
CREATE TABLE IF NOT EXISTS user_groups (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    allow_lan BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP(3) NULL
);

CREATE INDEX IF NOT EXISTS idx_user_groups_deleted_at ON user_groups(deleted_at);

-- 策略表
CREATE TABLE IF NOT EXISTS policies (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP(3) NULL
);

CREATE INDEX IF NOT EXISTS idx_policies_deleted_at ON policies(deleted_at);

-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) DEFAULT NULL,
    email VARCHAR(255),
    is_admin BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    source VARCHAR(20) DEFAULT 'system',
    ldap_dn VARCHAR(512),
    full_name VARCHAR(255),
    ldap_attributes TEXT,
    vpn_ip VARCHAR(45),
    client_ip VARCHAR(45),
    connected BOOLEAN DEFAULT FALSE,
    last_seen TIMESTAMP(3) NULL,
    tunnel_mode VARCHAR(20) DEFAULT 'split',
    otp_secret VARCHAR(255) DEFAULT '',
    otp_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP(3) NULL
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_source ON users(source);
CREATE INDEX IF NOT EXISTS idx_users_vpn_ip ON users(vpn_ip);
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);

-- 用户组和策略关联表
CREATE TABLE IF NOT EXISTS user_group_policies (
    user_group_id BIGINT NOT NULL,
    policy_id BIGINT NOT NULL,
    PRIMARY KEY (user_group_id, policy_id),
    FOREIGN KEY (user_group_id) REFERENCES user_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE
);

-- 用户和用户组关联表
CREATE TABLE IF NOT EXISTS user_user_groups (
    user_id BIGINT NOT NULL,
    user_group_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, user_group_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (user_group_id) REFERENCES user_groups(id) ON DELETE CASCADE
);

-- 路由表
CREATE TABLE IF NOT EXISTS routes (
    id BIGSERIAL PRIMARY KEY,
    policy_id BIGINT NOT NULL,
    network VARCHAR(255) NOT NULL,
    gateway VARCHAR(45),
    metric INT DEFAULT 0,
    created_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP(3) NULL,
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_routes_policy_id ON routes(policy_id);
CREATE INDEX IF NOT EXISTS idx_routes_deleted_at ON routes(deleted_at);

-- 排除路由表（用于全局模式）
CREATE TABLE IF NOT EXISTS exclude_routes (
    id BIGSERIAL PRIMARY KEY,
    policy_id BIGINT NOT NULL,
    network VARCHAR(255) NOT NULL,
    created_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP(3) NULL,
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_exclude_routes_policy_id ON exclude_routes(policy_id);
CREATE INDEX IF NOT EXISTS idx_exclude_routes_deleted_at ON exclude_routes(deleted_at);

-- 允许的网络表
CREATE TABLE IF NOT EXISTS allowed_networks (
    id BIGSERIAL PRIMARY KEY,
    policy_id BIGINT NOT NULL,
    network VARCHAR(255) NOT NULL,
    created_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_allowed_networks_policy_id ON allowed_networks(policy_id);

-- 时间限制表
CREATE TABLE IF NOT EXISTS time_restrictions (
    id BIGSERIAL PRIMARY KEY,
    policy_id BIGINT NOT NULL,
    day_of_week INT NOT NULL,
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    created_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_time_restrictions_policy_id ON time_restrictions(policy_id);

-- Hook 表
CREATE TABLE IF NOT EXISTS hooks (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    hook_type VARCHAR(50) NOT NULL,
    priority INT DEFAULT 100,
    enabled BOOLEAN DEFAULT TRUE,
    config JSONB,
    created_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP(3) NULL
);

CREATE INDEX IF NOT EXISTS idx_hooks_hook_type ON hooks(hook_type);
CREATE INDEX IF NOT EXISTS idx_hooks_deleted_at ON hooks(deleted_at);

-- 会话表
CREATE TABLE IF NOT EXISTS sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    vpn_ip VARCHAR(45),
    connected_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_vpn_ip ON sessions(vpn_ip);

-- LDAP 配置表
CREATE TABLE IF NOT EXISTS ldap_configs (
    id BIGSERIAL PRIMARY KEY,
    enabled BOOLEAN DEFAULT FALSE,
    host VARCHAR(255),
    port INT DEFAULT 389,
    use_ssl BOOLEAN DEFAULT FALSE,
    bind_dn VARCHAR(255),
    bind_password VARCHAR(255),
    base_dn VARCHAR(255),
    user_filter VARCHAR(255),
    admin_group VARCHAR(255),
    skip_tls_verify BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP(3) NULL
);

CREATE INDEX IF NOT EXISTS idx_ldap_configs_deleted_at ON ldap_configs(deleted_at);

-- 审计日志表
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP(3) NULL,
    user_id BIGINT DEFAULT 0,
    username VARCHAR(255),
    type VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    source_port SMALLINT,
    destination_port SMALLINT,
    protocol VARCHAR(20),
    resource_type VARCHAR(100),
    resource_path TEXT,
    domain VARCHAR(255),
    hook_id VARCHAR(255),
    hook_name VARCHAR(255),
    policy_id BIGINT DEFAULT 0,
    policy_name VARCHAR(255),
    result VARCHAR(50),
    reason TEXT,
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_type ON audit_logs(type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_source_ip ON audit_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_audit_logs_destination_ip ON audit_logs(destination_ip);
CREATE INDEX IF NOT EXISTS idx_audit_logs_domain ON audit_logs(domain);
CREATE INDEX IF NOT EXISTS idx_audit_logs_hook_id ON audit_logs(hook_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_policy_id ON audit_logs(policy_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_deleted_at ON audit_logs(deleted_at);

-- 系统设置表（前端配置持久化）
CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT,
    created_at TIMESTAMP(3),
    updated_at TIMESTAMP(3)
);

-- ============================================
-- 初始数据
-- ============================================

-- 创建默认策略
INSERT INTO policies (id, name, description, created_at, updated_at) 
VALUES (1, 'default', 'Default policy allowing all traffic', NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- 创建管理员用户组
INSERT INTO user_groups (id, name, description, created_at, updated_at) 
VALUES (1, 'admin', '管理员用户组', NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- 关联管理员组和默认策略
INSERT INTO user_group_policies (user_group_id, policy_id) 
VALUES (1, 1)
ON CONFLICT DO NOTHING;

-- 创建默认管理员用户（密码: admin123，bcrypt哈希）
-- 注意：这里使用的是 bcrypt 哈希值，实际部署时应该使用程序生成
INSERT INTO users (id, username, password_hash, email, is_admin, is_active, source, created_at, updated_at) 
VALUES (1, 'admin', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'admin@zvpn.local', TRUE, TRUE, 'system', NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- 关联管理员用户和管理员组
INSERT INTO user_user_groups (user_id, user_group_id) 
VALUES (1, 1)
ON CONFLICT DO NOTHING;


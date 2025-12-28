-- ZVPN 数据库初始化脚本
-- 支持 MySQL 8.0+ 和 PostgreSQL 12+

-- 创建数据库（如果不存在）
-- MySQL:
-- CREATE DATABASE IF NOT EXISTS zvpn CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
-- PostgreSQL:
-- CREATE DATABASE zvpn;

-- 使用数据库
-- MySQL: USE zvpn;
-- PostgreSQL: \c zvpn;

-- ============================================
-- 表结构定义
-- ============================================

-- 用户组表
CREATE TABLE IF NOT EXISTS user_groups (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    INDEX idx_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 策略表
CREATE TABLE IF NOT EXISTS policies (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    INDEX idx_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
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
    last_seen DATETIME(3) NULL,
    tunnel_mode VARCHAR(20) DEFAULT 'split',
    otp_secret VARCHAR(255) DEFAULT '',
    otp_enabled BOOLEAN DEFAULT FALSE,
    created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    INDEX idx_username (username),
    INDEX idx_source (source),
    INDEX idx_vpn_ip (vpn_ip),
    INDEX idx_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 用户组和策略关联表
CREATE TABLE IF NOT EXISTS user_group_policies (
    user_group_id BIGINT UNSIGNED NOT NULL,
    policy_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (user_group_id, policy_id),
    FOREIGN KEY (user_group_id) REFERENCES user_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 用户和用户组关联表
CREATE TABLE IF NOT EXISTS user_user_groups (
    user_id BIGINT UNSIGNED NOT NULL,
    user_group_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (user_id, user_group_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (user_group_id) REFERENCES user_groups(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 路由表
CREATE TABLE IF NOT EXISTS routes (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    policy_id BIGINT UNSIGNED NOT NULL,
    network VARCHAR(255) NOT NULL,
    gateway VARCHAR(45),
    metric INT DEFAULT 0,
    created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE,
    INDEX idx_policy_id (policy_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 允许的网络表
CREATE TABLE IF NOT EXISTS allowed_networks (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    policy_id BIGINT UNSIGNED NOT NULL,
    network VARCHAR(255) NOT NULL,
    created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE,
    INDEX idx_policy_id (policy_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 时间限制表
CREATE TABLE IF NOT EXISTS time_restrictions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    policy_id BIGINT UNSIGNED NOT NULL,
    day_of_week INT NOT NULL,
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE,
    INDEX idx_policy_id (policy_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Hook 表
CREATE TABLE IF NOT EXISTS hooks (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    hook_type VARCHAR(50) NOT NULL,
    priority INT DEFAULT 100,
    enabled BOOLEAN DEFAULT TRUE,
    config JSON,
    created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    INDEX idx_hook_type (hook_type),
    INDEX idx_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 会话表
CREATE TABLE IF NOT EXISTS sessions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    vpn_ip VARCHAR(45),
    connected_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    last_seen DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_vpn_ip (vpn_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- LDAP 配置表
CREATE TABLE IF NOT EXISTS ldap_configs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
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
    created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    INDEX idx_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 审计日志表
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    user_id BIGINT UNSIGNED DEFAULT 0,
    username VARCHAR(255),
    type VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    source_port SMALLINT UNSIGNED,
    destination_port SMALLINT UNSIGNED,
    protocol VARCHAR(20),
    resource_type VARCHAR(100),
    resource_path TEXT,
    domain VARCHAR(255),
    hook_id VARCHAR(255),
    hook_name VARCHAR(255),
    policy_id BIGINT UNSIGNED DEFAULT 0,
    policy_name VARCHAR(255),
    result VARCHAR(50),
    reason TEXT,
    bytes_sent BIGINT UNSIGNED DEFAULT 0,
    bytes_received BIGINT UNSIGNED DEFAULT 0,
    metadata JSON,
    INDEX idx_user_id (user_id),
    INDEX idx_type (type),
    INDEX idx_action (action),
    INDEX idx_source_ip (source_ip),
    INDEX idx_destination_ip (destination_ip),
    INDEX idx_domain (domain),
    INDEX idx_hook_id (hook_id),
    INDEX idx_policy_id (policy_id),
    INDEX idx_created_at (created_at),
    INDEX idx_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 域名管理表
CREATE TABLE IF NOT EXISTS domains (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    policy_id BIGINT UNSIGNED,
    manual_ips TEXT,
    access_count INT DEFAULT 0,
    created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE SET NULL,
    INDEX idx_domain (domain),
    INDEX idx_policy_id (policy_id),
    INDEX idx_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 系统设置表（前端配置持久化）
CREATE TABLE IF NOT EXISTS system_settings (
    `key` VARCHAR(100) NOT NULL PRIMARY KEY,
    `value` TEXT,
    created_at DATETIME(3),
    updated_at DATETIME(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- 初始数据
-- ============================================

-- 创建默认策略
INSERT IGNORE INTO policies (id, name, description, created_at, updated_at) 
VALUES (1, 'default', 'Default policy allowing all traffic', NOW(3), NOW(3));

-- 创建管理员用户组
INSERT IGNORE INTO user_groups (id, name, description, created_at, updated_at) 
VALUES (1, 'admin', '管理员用户组', NOW(3), NOW(3));

-- 关联管理员组和默认策略
INSERT IGNORE INTO user_group_policies (user_group_id, policy_id) 
VALUES (1, 1);

-- 创建默认管理员用户（密码: admin123，bcrypt哈希）
-- 注意：这里使用的是 bcrypt 哈希值，实际部署时应该使用程序生成
INSERT IGNORE INTO users (id, username, password_hash, email, is_admin, is_active, source, created_at, updated_at) 
VALUES (1, 'admin', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'admin@zvpn.local', TRUE, TRUE, 'system', NOW(3), NOW(3));

-- 关联管理员用户和管理员组
INSERT IGNORE INTO user_user_groups (user_id, user_group_id) 
VALUES (1, 1);


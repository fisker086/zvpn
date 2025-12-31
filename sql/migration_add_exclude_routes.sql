-- 数据库迁移脚本：添加 exclude_routes 表
-- 用于支持全局模式下的自定义排除路由配置

-- MySQL
CREATE TABLE IF NOT EXISTS exclude_routes (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    policy_id BIGINT UNSIGNED NOT NULL,
    network VARCHAR(255) NOT NULL COMMENT 'CIDR格式，例如: 192.168.1.0/24',
    created_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    deleted_at DATETIME(3) NULL,
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE,
    INDEX idx_policy_id (policy_id),
    INDEX idx_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 为routes表添加deleted_at字段（如果不存在）
ALTER TABLE routes 
ADD COLUMN IF NOT EXISTS deleted_at DATETIME(3) NULL,
ADD INDEX IF NOT EXISTS idx_deleted_at (deleted_at);

-- PostgreSQL
-- CREATE TABLE IF NOT EXISTS exclude_routes (
--     id BIGSERIAL PRIMARY KEY,
--     policy_id BIGINT NOT NULL,
--     network VARCHAR(255) NOT NULL,
--     created_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
--     updated_at TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
--     deleted_at TIMESTAMP(3) NULL,
--     FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE
-- );
-- 
-- CREATE INDEX IF NOT EXISTS idx_exclude_routes_policy_id ON exclude_routes(policy_id);
-- CREATE INDEX IF NOT EXISTS idx_exclude_routes_deleted_at ON exclude_routes(deleted_at);
-- 
-- -- 为routes表添加deleted_at字段（如果不存在）
-- ALTER TABLE routes 
-- ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP(3) NULL;
-- 
-- CREATE INDEX IF NOT EXISTS idx_routes_deleted_at ON routes(deleted_at);


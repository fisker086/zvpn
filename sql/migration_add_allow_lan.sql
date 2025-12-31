-- 数据库迁移脚本：添加 allow_lan 字段到 user_groups 表
-- 用于支持 anylink 风格的本地网络访问控制

-- MySQL
ALTER TABLE user_groups 
ADD COLUMN IF NOT EXISTS allow_lan BOOLEAN DEFAULT FALSE 
COMMENT '允许本地网络访问（类似 anylink 的 allow_lan 配置）';

-- PostgreSQL
-- ALTER TABLE user_groups 
-- ADD COLUMN IF NOT EXISTS allow_lan BOOLEAN DEFAULT FALSE;


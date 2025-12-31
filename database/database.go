package database

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/fisker/zvpn/config"
	"github.com/fisker/zvpn/models"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// customLogger is a GORM logger that ignores ErrRecordNotFound errors
type customLogger struct {
	logger.Interface
}

// LogMode returns a logger with the specified log level
func (l *customLogger) LogMode(level logger.LogLevel) logger.Interface {
	return &customLogger{Interface: logger.Default.LogMode(level)}
}

// Info logs info messages, but ignores ErrRecordNotFound errors
func (l *customLogger) Info(ctx context.Context, msg string, data ...interface{}) {
	// Check if the message contains "record not found"
	// If so, don't log it as it's expected behavior
	if len(data) > 0 {
		if err, ok := data[len(data)-1].(error); ok {
			if err == gorm.ErrRecordNotFound {
				return // Don't log ErrRecordNotFound
			}
		}
	}
	l.Interface.Info(ctx, msg, data...)
}

// Warn logs warning messages
func (l *customLogger) Warn(ctx context.Context, msg string, data ...interface{}) {
	l.Interface.Warn(ctx, msg, data...)
}

// Error logs error messages, but ignores ErrRecordNotFound errors
func (l *customLogger) Error(ctx context.Context, msg string, data ...interface{}) {
	// Check if the message contains "record not found"
	// If so, don't log it as it's expected behavior
	if len(data) > 0 {
		if err, ok := data[len(data)-1].(error); ok {
			if err == gorm.ErrRecordNotFound {
				return // Don't log ErrRecordNotFound
			}
		}
	}
	l.Interface.Error(ctx, msg, data...)
}

// Trace logs trace messages, but ignores ErrRecordNotFound errors
func (l *customLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	// Don't log if error is ErrRecordNotFound
	if err == gorm.ErrRecordNotFound {
		return
	}
	l.Interface.Trace(ctx, begin, fc, err)
}

var DB *gorm.DB

func Init(cfg *config.Config) error {
	var err error
	var dialector gorm.Dialector

	switch cfg.Database.Type {
	case "mysql":
		dialector = mysql.Open(cfg.Database.DSN)
	case "postgres", "postgresql":
		dialector = postgres.Open(cfg.Database.DSN)
	default:
		return fmt.Errorf("unsupported database type: %s (supported: mysql, postgres)", cfg.Database.Type)
	}

	log.Printf("Connecting to %s database...", cfg.Database.Type)

	// Use custom logger that ignores ErrRecordNotFound errors
	customLog := &customLogger{Interface: logger.Default}
	DB, err = gorm.Open(dialector, &gorm.Config{
		Logger: customLog.LogMode(logger.Info),
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// 配置连接池
	sqlDB, err := DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// 设置最大打开连接数
	maxOpenConns := cfg.Database.MaxOpenConns
	if maxOpenConns <= 0 {
		maxOpenConns = 25 // 默认值
	}
	sqlDB.SetMaxOpenConns(maxOpenConns)
	log.Printf("Database connection pool: MaxOpenConns = %d", maxOpenConns)

	// 设置最大空闲连接数
	maxIdleConns := cfg.Database.MaxIdleConns
	if maxIdleConns <= 0 {
		maxIdleConns = 10 // 默认值
	}
	// 确保 MaxIdleConns 不超过 MaxOpenConns
	if maxIdleConns > maxOpenConns {
		maxIdleConns = maxOpenConns
	}
	sqlDB.SetMaxIdleConns(maxIdleConns)
	log.Printf("Database connection pool: MaxIdleConns = %d", maxIdleConns)

	// 设置连接最大生存时间
	connMaxLifetime := cfg.Database.ConnMaxLifetime
	if connMaxLifetime <= 0 {
		connMaxLifetime = 300 // 默认 5 分钟
	}
	sqlDB.SetConnMaxLifetime(time.Duration(connMaxLifetime) * time.Second)
	log.Printf("Database connection pool: ConnMaxLifetime = %ds", connMaxLifetime)

	// 设置连接最大空闲时间
	connMaxIdleTime := cfg.Database.ConnMaxIdleTime
	if connMaxIdleTime <= 0 {
		connMaxIdleTime = 60 // 默认 1 分钟
	}
	sqlDB.SetConnMaxIdleTime(time.Duration(connMaxIdleTime) * time.Second)
	log.Printf("Database connection pool: ConnMaxIdleTime = %ds", connMaxIdleTime)

	// 测试连接
	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}
	log.Println("Database connection pool configured successfully")

	// Auto migrate
	err = DB.AutoMigrate(
		&models.User{},
		&models.Policy{},
		&models.AllowedNetwork{},
		&models.Route{},
		&models.ExcludeRoute{},
		&models.TimeRestriction{},
		&models.Session{},
		&models.Hook{},
		&models.UserGroup{},
		&models.LDAPConfig{},
		&models.AuditLog{},
		&models.SystemSetting{},
	)
	if err != nil {
		return err
	}

	// 数据迁移：确保已存在的用户都有 Source 字段
	// 对于已部署的系统，AutoMigrate 会添加新字段，但已存在用户的 Source 可能为空
	// 这里将所有 Source 为空或 NULL 的用户设置为 'system'（系统账户）
	result := DB.Model(&models.User{}).
		Where("source IS NULL OR source = ''").
		Update("source", models.UserSourceSystem)
	if result.Error != nil {
		log.Printf("Warning: Failed to migrate user source field: %v", result.Error)
	} else if result.RowsAffected > 0 {
		log.Printf("Migrated %d existing users to source='system'", result.RowsAffected)
	}

	// 数据迁移：确保已存在的用户都有 tunnel_mode 字段
	// 对于已部署的系统，AutoMigrate 会添加新字段，但已存在用户的 tunnel_mode 可能为空
	// 这里将所有 tunnel_mode 为空或 NULL 的用户设置为 'split'（分隧道模式）
	// 注意：只更新空值，不会覆盖已有用户的设置（不会影响 'split' 或 'full' 的值）
	result = DB.Model(&models.User{}).
		Where("tunnel_mode IS NULL OR tunnel_mode = ''").
		Update("tunnel_mode", "split")
	if result.Error != nil {
		log.Printf("Warning: Failed to migrate user tunnel_mode field: %v", result.Error)
	} else if result.RowsAffected > 0 {
		log.Printf("Migrated %d existing users to tunnel_mode='split' (only NULL or empty values)", result.RowsAffected)
	} else {
		// 记录迁移结果，确认没有意外更新已有值
		var totalUsers, usersWithTunnelMode int64
		DB.Model(&models.User{}).Count(&totalUsers)
		DB.Model(&models.User{}).Where("tunnel_mode IN (?)", []string{"split", "full"}).Count(&usersWithTunnelMode)
		log.Printf("Tunnel mode migration: %d total users, %d users with tunnel_mode set (split/full)", totalUsers, usersWithTunnelMode)
	}

	// Create default policy if not exists (must be created before admin user due to foreign key)
	var defaultPolicy models.Policy
	var policyCount int64
	DB.Model(&models.Policy{}).Where("name = ?", "default").Count(&policyCount)
	if policyCount == 0 {
		defaultPolicy = models.Policy{
			Name:        "default",
			Description: "Default policy allowing all traffic",
		}
		if err := DB.Create(&defaultPolicy).Error; err != nil {
			log.Printf("Failed to create default policy: %v", err)
		} else {
			log.Println("Default policy created")
		}
	} else {
		// Get existing default policy
		if err := DB.Where("name = ?", "default").First(&defaultPolicy).Error; err != nil {
			log.Printf("Failed to get default policy: %v", err)
		}
	}

	// Create default admin user if not exists
	// 注意：只有当系统中没有任何管理员用户时才会创建默认admin用户
	// 如果admin用户已存在，不会重置其密码，确保用户修改的密码不会被覆盖
	var adminCount int64
	DB.Model(&models.User{}).Where("is_admin = ?", true).Count(&adminCount)
	if adminCount == 0 {
		log.Printf("No admin user found, creating default admin user")
		// 创建默认管理员用户组
		var adminGroup models.UserGroup
		var groupCount int64
		DB.Model(&models.UserGroup{}).Where("name = ?", "admin").Count(&groupCount)
		if groupCount == 0 {
			adminGroup = models.UserGroup{
				Name:        "admin",
				Description: "管理员用户组",
			}
			if err := DB.Create(&adminGroup).Error; err != nil {
				log.Printf("Failed to create admin group: %v", err)
			} else {
				log.Println("Default admin group created")
				// 给管理员组分配默认策略
				if defaultPolicy.ID > 0 {
					DB.Model(&adminGroup).Association("Policies").Append(&defaultPolicy)
				}
			}
		} else {
			DB.Where("name = ?", "admin").First(&adminGroup)
		}

		admin := &models.User{
			Username: "admin",
			Email:    "admin@zvpn.local",
			IsAdmin:  true,
			IsActive: true,
			Source:   models.UserSourceSystem, // 明确设置为系统账户
		}
		admin.SetPassword("admin123")
		if err := DB.Create(admin).Error; err != nil {
			log.Printf("Failed to create default admin: %v", err)
		} else {
			// 将管理员添加到管理员组
			if adminGroup.ID > 0 {
				DB.Model(admin).Association("Groups").Append(&adminGroup)
			}
			log.Println("Default admin user created: admin/admin123")
		}
	} else {
		log.Printf("Admin user already exists (%d admin users found), skipping default admin creation to preserve existing passwords", adminCount)
	}

	// Create default system settings if not exists
	initDefaultSystemSettings()

	log.Println("Database initialized successfully")
	return nil
}

// initDefaultSystemSettings creates default system settings records in the database
func initDefaultSystemSettings() {
	// Default performance settings
	perfSettings := map[string]interface{}{
		"enable_policy_cache": true,
		"cache_size":          1000,
	}
	createDefaultSystemSetting("performance_settings", perfSettings)

	// Default security settings
	securitySettings := map[string]interface{}{
		"enable_rate_limit":            false,
		"rate_limit_per_ip":            1000,
		"rate_limit_per_user":          10485760, // 10MB/s
		"allow_multi_client_login":     true,
		"enable_ddos_protection":       false,
		"ddos_threshold":               10000,
		"ddos_block_duration":          300,
		"enable_bruteforce_protection": true,
		"max_login_attempts":           5,
		"login_lockout_duration":       900,
		"login_attempt_window":         300,
	}
	createDefaultSystemSetting("security_settings", securitySettings)

	// Default distributed sync settings
	distributedSyncSettings := map[string]interface{}{
		"enable_distributed_sync": false,
		"sync_interval":           120, // seconds
		"change_check_interval":   10,  // seconds
	}
	createDefaultSystemSetting("distributed_sync_settings", distributedSyncSettings)

	// Default compression settings
	compressionSettings := map[string]interface{}{
		"enable_compression": false,
		"compression_type":   "lz4",
	}
	createDefaultSystemSetting("compression_settings", compressionSettings)
}

// createDefaultSystemSetting creates a default system setting if it doesn't exist
func createDefaultSystemSetting(key string, defaultValue map[string]interface{}) {
	var count int64
	DB.Model(&models.SystemSetting{}).Where("`key` = ?", key).Count(&count)
	if count == 0 {
		data, err := json.Marshal(defaultValue)
		if err != nil {
			log.Printf("Failed to marshal default %s: %v", key, err)
			return
		}
		setting := models.SystemSetting{
			Key:   key,
			Value: string(data),
		}
		if err := DB.Create(&setting).Error; err != nil {
			log.Printf("Failed to create default %s: %v", key, err)
		} else {
			log.Printf("Default %s created", key)
		}
	}
}

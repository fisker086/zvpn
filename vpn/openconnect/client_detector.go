package openconnect

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// ClientType 客户端类型
type ClientType string

const (
	ClientTypeOpenConnect ClientType = "openconnect"
	ClientTypeAnyConnect  ClientType = "anyconnect"
	ClientTypeCustom      ClientType = "custom" // 预留：自定义客户端
	ClientTypeUnknown     ClientType = "unknown"
)

// ClientDetector 客户端检测器接口
// 用于识别客户端类型，便于后续扩展支持自定义客户端
type ClientDetector interface {
	// Detect 检测客户端类型
	Detect(c *gin.Context) ClientType

	// GetClientName 获取客户端名称（用于日志和统计）
	GetClientName(clientType ClientType) string
}

// DefaultClientDetector 默认客户端检测器实现
// 通过 User-Agent 识别客户端类型
type DefaultClientDetector struct{}

// NewClientDetector 创建客户端检测器
func NewClientDetector() ClientDetector {
	return &DefaultClientDetector{}
}

// Detect 检测客户端类型
// 参考 anylink 的实现，通过多种方式识别客户端类型：
// 1. X-Aggregate-Auth 和 X-Transcend-Version 头部（AnyConnect 标准）
// 2. User-Agent 头部（兼容性检测）
func (d *DefaultClientDetector) Detect(c *gin.Context) ClientType {
	// 优先检查 AnyConnect 标准头部（最可靠的方法）
	xAggregateAuth := c.Request.Header.Get("X-Aggregate-Auth")
	xTranscendVersion := c.Request.Header.Get("X-Transcend-Version")
	
	// AnyConnect 客户端会发送 X-Aggregate-Auth: 1 和 X-Transcend-Version: 1
	// 这是 anylink 和 ocserv 都使用的标准检测方法
	if xAggregateAuth == "1" && xTranscendVersion == "1" {
		return ClientTypeAnyConnect
	}
	
	// 即使不是 "1"，只要有这些头部就可能是 AnyConnect 客户端（某些版本可能发送其他值）
	if xAggregateAuth != "" && xTranscendVersion != "" {
		return ClientTypeAnyConnect
	}

	// 回退到 User-Agent 检测（用于初始请求，此时可能还没有发送上述头部）
	userAgent := strings.ToLower(c.Request.UserAgent())
	
	// 检查 User-Agent 中的客户端标识
	if strings.Contains(userAgent, "anyconnect") || 
	   strings.Contains(userAgent, "cisco secure client") ||
	   strings.Contains(userAgent, "cisco anyconnect") {
		return ClientTypeAnyConnect
	} else if strings.Contains(userAgent, "openconnect") {
		return ClientTypeOpenConnect
	}

	// 如果都没有匹配，返回 Unknown
	return ClientTypeUnknown
}

// GetClientName 获取客户端名称
func (d *DefaultClientDetector) GetClientName(clientType ClientType) string {
	switch clientType {
	case ClientTypeOpenConnect:
		return "OpenConnect"
	case ClientTypeAnyConnect:
		return "AnyConnect"
	case ClientTypeCustom:
		return "Custom"
	default:
		return "Unknown"
	}
}

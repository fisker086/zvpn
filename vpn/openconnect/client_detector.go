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
// 通过检查 HTTP 请求的 User-Agent 头来识别客户端类型
func (d *DefaultClientDetector) Detect(c *gin.Context) ClientType {
	userAgent := strings.ToLower(c.Request.UserAgent())

	// 检查 User-Agent 中的客户端标识
	if strings.Contains(userAgent, "anyconnect") {
		return ClientTypeAnyConnect
	} else if strings.Contains(userAgent, "openconnect") {
		return ClientTypeOpenConnect
	}

	// 如果 User-Agent 中没有明确的客户端标识，返回 Unknown
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

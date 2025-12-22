/**
 * 常量定义
 */

// 压缩类型
export const COMPRESSION_TYPES = {
  NONE: 'none',
  LZ4: 'lz4',
  GZIP: 'gzip',
} as const

// 审计日志类型
export const AUDIT_LOG_TYPES = {
  ACCESS: 'access',
  POLICY: 'policy',
  AUTH: 'auth',
  CONFIG: 'config',
  HOOK: 'hook',
} as const

// 审计日志动作
export const AUDIT_LOG_ACTIONS = {
  ALLOW: 'allow',
  DENY: 'deny',
  LOG: 'log',
  CONNECT: 'connect',
  DISCONNECT: 'disconnect',
  LOGIN: 'login',
  LOGOUT: 'logout',
} as const

// 状态颜色映射
export const STATUS_COLORS = {
  success: 'green',
  error: 'red',
  warning: 'orange',
  info: 'blue',
  default: 'gray',
} as const

// 分页默认配置
export const DEFAULT_PAGINATION = {
  current: 1,
  pageSize: 10,
  showTotal: true,
  showPageSize: true,
} as const


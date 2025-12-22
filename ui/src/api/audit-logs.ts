import request from './request'

// 审计日志类型
export const AuditLogType = {
  Access: 'access',
  Policy: 'policy',
  Auth: 'auth',
  Config: 'config',
  Hook: 'hook',
} as const

export type AuditLogType = typeof AuditLogType[keyof typeof AuditLogType]

// 审计日志动作
export const AuditLogAction = {
  Allow: 'allow',
  Deny: 'deny',
  Log: 'log',
  Connect: 'connect',
  Disconnect: 'disconnect',
  Login: 'login',
  Logout: 'logout',
} as const

export type AuditLogAction = typeof AuditLogAction[keyof typeof AuditLogAction]

// 审计日志
export interface AuditLog {
  id: number
  created_at: string
  updated_at: string
  user_id: number
  username: string
  type: AuditLogType
  action: AuditLogAction
  source_ip: string
  destination_ip: string
  source_port: number
  destination_port: number
  protocol: string
  resource_type: string
  resource_path: string
  domain?: string
  hook_id?: string
  hook_name?: string
  policy_id?: number
  policy_name?: string
  result: string
  reason?: string
  bytes_sent?: number
  bytes_received?: number
  metadata?: Record<string, any>
}

// 审计日志查询参数
export interface AuditLogQuery {
  user_id?: number
  username?: string
  type?: AuditLogType
  action?: AuditLogAction
  source_ip?: string
  destination_ip?: string
  domain?: string
  start_time?: string
  end_time?: string
  result?: string
  page?: number
  page_size?: number
}

// 审计日志列表响应
export interface AuditLogListResponse {
  data: AuditLog[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

// 审计日志统计
export interface AuditLogStats {
  total_logs: number
  total_access: number
  total_blocked: number
  total_allowed: number
  total_by_type: Record<string, number>
  total_by_action: Record<string, number>
  top_users: Array<{
    user_id: number
    username: string
    count: number
  }>
  top_destinations: Array<{
    destination_ip: string
    count: number
  }>
}

export const auditLogsApi = {
  // 获取审计日志列表
  list: (query?: AuditLogQuery): Promise<AuditLogListResponse> =>
    request.get<AuditLogListResponse>('/audit-logs', { params: query }),

  // 获取审计日志详情
  get: (id: number): Promise<AuditLog> =>
    request.get<AuditLog>(`/audit-logs/${id}`),

  // 获取审计日志统计
  getStats: (startTime?: string, endTime?: string): Promise<AuditLogStats> =>
    request.get<AuditLogStats>('/audit-logs/stats', {
      params: { start_time: startTime, end_time: endTime },
    }),

  // 删除审计日志
  delete: (beforeDate?: string, type?: AuditLogType): Promise<{ message: string; count: number }> =>
    request.delete<{ message: string; count: number }>('/audit-logs', {
      data: { before_date: beforeDate, type },
    }),
}


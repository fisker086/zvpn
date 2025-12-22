import request from './request'

// Hook 点枚举
export const HookPoint = {
  PreRouting: 0,
  PostRouting: 1,
  Forward: 2,
  Input: 3,
  Output: 4,
} as const;

export type HookPoint = typeof HookPoint[keyof typeof HookPoint];

// 策略动作
export const PolicyAction = {
  Allow: 0,
  Deny: 1,
  Redirect: 2,
  Log: 3,
} as const;

export type PolicyAction = typeof PolicyAction[keyof typeof PolicyAction];

// Hook 类型
export const HookType = {
  ACL: 'acl',
  PortFilter: 'port_filter',
  UserPolicy: 'user_policy',
  TimeRestriction: 'time_restriction',
  Custom: 'custom',
} as const;

export type HookType = typeof HookType[keyof typeof HookType];

// Hook 策略
export interface Hook {
  id: string
  name: string
  hook_point: HookPoint
  priority: number
  type: HookType
  enabled: boolean
  description?: string
  rules: HookRule[]
  stats?: HookStats
  created_at?: string
  updated_at?: string
}

// Hook 规则
export interface HookRule {
  // IP 规则
  source_ips?: string[]
  destination_ips?: string[]
  source_networks?: string[]
  destination_networks?: string[]
  
  // 端口规则
  source_ports?: number[]
  destination_ports?: number[]
  port_ranges?: PortRange[]
  
  // 协议
  protocols?: string[]
  
  // 用户规则
  user_ids?: number[]
  
  // 时间规则
  time_ranges?: TimeRange[]
  
  // 动作
  action: PolicyAction
}

export interface PortRange {
  start: number
  end: number
}

export interface TimeRange {
  start_time: string // HH:MM
  end_time: string   // HH:MM
  weekdays?: number[] // 0-6
}

// Hook 统计
export interface HookStats {
  total_matches: number
  total_allows: number
  total_denies: number
  last_match_time?: string
}

// 创建 Hook 请求
export interface CreateHookRequest {
  name: string
  hook_point: HookPoint
  priority: number
  type: HookType
  description?: string
  rules: HookRule[]
  enabled?: boolean
}

// 更新 Hook 请求
export interface UpdateHookRequest {
  name?: string
  priority?: number
  description?: string
  rules?: HookRule[]
  enabled?: boolean
}

export const hooksApi = {
  // 获取 Hook 列表
  list: (): Promise<Hook[]> => 
    request.get<Hook[]>('/hooks'),

  // 获取 Hook 详情
  get: (id: string): Promise<Hook> => 
    request.get<Hook>(`/hooks/${id}`),

  // 创建 Hook
  create: (data: CreateHookRequest): Promise<Hook> => 
    request.post<Hook>('/hooks', data),

  // 更新 Hook
  update: (id: string, data: UpdateHookRequest): Promise<Hook> => 
    request.put<Hook>(`/hooks/${id}`, data),

  // 删除 Hook
  delete: (id: string): Promise<void> => 
    request.delete(`/hooks/${id}`),

  // 启用/禁用 Hook
  toggle: (id: string, enabled: boolean): Promise<void> => 
    request.put(`/hooks/${id}/toggle`, { enabled }),

  // 获取 Hook 统计
  getStats: (id: string): Promise<HookStats> => 
    request.get<HookStats>(`/hooks/${id}/stats`),

  // 测试 Hook
  test: (id: string, testData: any): Promise<void> => 
    request.post(`/hooks/${id}/test`, testData),

  // 同步特定 Hook
  sync: (id: string): Promise<{ message: string; hook_id: string; node_id?: string }> => 
    request.post(`/hooks/${id}/sync`),

  // 获取同步状态
  getSyncStatus: (): Promise<SyncStatus> => 
    request.get<SyncStatus>('/hooks/sync/status'),

  // 强制全量同步
  forceSync: (): Promise<{ message: string; node_id?: string }> => 
    request.post('/hooks/sync'),
}

// 同步状态
export interface SyncStatus {
  node_id: string
  running: boolean
  last_sync: string
  sync_interval?: string
  hook_count?: number
  sync_type?: string
}


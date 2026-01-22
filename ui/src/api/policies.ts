import request from './request'

export interface Route {
  id: number
  network: string
  gateway?: string
  metric: number
}

export interface ExcludeRoute {
  id: number
  network: string
}

export interface Policy {
  id: number
  name: string
  description?: string
  routes: Route[]
  exclude_routes?: ExcludeRoute[]
  max_bandwidth?: number
  dns_servers?: string[] // DNS服务器IP地址数组
  split_dns?: string[] // Split-DNS域名数组，例如: ["example.com", "*.example.com"]
  groups?: Array<{
    id: number
    name: string
  }>
  created_at?: string
  updated_at?: string
}

export interface CreatePolicyRequest {
  name: string
  description?: string
  max_bandwidth?: number
  dns_servers?: string[] // DNS服务器IP地址数组
  split_dns?: string[] // Split-DNS域名数组
  group_ids: number[] // 必须绑定至少一个用户组
}

export interface UpdatePolicyRequest {
  name?: string
  description?: string
  max_bandwidth?: number
  dns_servers?: string[] // DNS服务器IP地址数组
  split_dns?: string[] // Split-DNS域名数组
}

export interface AddRouteRequest {
  network: string
  gateway?: string
  metric?: number
}

export interface UpdateRouteRequest {
  network?: string
  gateway?: string
  metric?: number
}

export interface AddExcludeRouteRequest {
  network: string
}

export interface UpdateExcludeRouteRequest {
  network?: string
}

export const policiesApi = {
  // 获取策略列表
  list: (): Promise<Policy[]> => 
    request.get<Policy[]>('/policies'),

  // 获取策略详情
  get: (id: number): Promise<Policy> => 
    request.get<Policy>(`/policies/${id}`),

  // 创建策略
  create: (data: CreatePolicyRequest): Promise<Policy> => 
    request.post<Policy>('/policies', data),

  // 更新策略
  update: (id: number, data: UpdatePolicyRequest): Promise<Policy> => 
    request.put<Policy>(`/policies/${id}`, data),

  // 删除策略
  delete: (id: number): Promise<void> => 
    request.delete(`/policies/${id}`),

  // 添加路由
  addRoute: (id: number, data: AddRouteRequest): Promise<Route> => 
    request.post<Route>(`/policies/${id}/routes`, data),

  // 删除路由
  deleteRoute: (policyId: number, routeId: number): Promise<void> => 
    request.delete(`/policies/${policyId}/routes/${routeId}`),
  
  // 更新路由
  updateRoute: (policyId: number, routeId: number, data: UpdateRouteRequest): Promise<Route> => 
    request.put<Route>(`/policies/${policyId}/routes/${routeId}`, data),

  // 给策略分配用户组
  assignGroups: (id: number, data: { group_ids: number[] }): Promise<Policy> => 
    request.post<Policy>(`/policies/${id}/groups`, data),

  // 添加排除路由
  addExcludeRoute: (id: number, data: AddExcludeRouteRequest): Promise<ExcludeRoute> => 
    request.post<ExcludeRoute>(`/policies/${id}/exclude-routes`, data),

  // 删除排除路由
  deleteExcludeRoute: (policyId: number, excludeRouteId: number): Promise<void> => 
    request.delete(`/policies/${policyId}/exclude-routes/${excludeRouteId}`),
  
  // 更新排除路由
  updateExcludeRoute: (policyId: number, excludeRouteId: number, data: UpdateExcludeRouteRequest): Promise<ExcludeRoute> => 
    request.put<ExcludeRoute>(`/policies/${policyId}/exclude-routes/${excludeRouteId}`, data),
}



import request from './request'

export interface UserGroup {
  id: number
  name: string
  description?: string
  users?: Array<{
    id: number
    username: string
  }>
  policies?: Array<{
    id: number
    name: string
  }>
  created_at?: string
  updated_at?: string
}

export interface CreateGroupRequest {
  name: string
  description?: string
}

export interface UpdateGroupRequest {
  name?: string
  description?: string
}

export interface AssignUsersRequest {
  user_ids: number[]
}

export interface AssignPoliciesRequest {
  policy_ids: number[]
}

export const groupsApi = {
  // 获取用户组列表
  list: (): Promise<UserGroup[]> => 
    request.get<UserGroup[]>('/groups'),

  // 获取用户组详情
  get: (id: number): Promise<UserGroup> => 
    request.get<UserGroup>(`/groups/${id}`),

  // 创建用户组
  create: (data: CreateGroupRequest): Promise<UserGroup> => 
    request.post<UserGroup>('/groups', data),

  // 更新用户组
  update: (id: number, data: UpdateGroupRequest): Promise<UserGroup> => 
    request.put<UserGroup>(`/groups/${id}`, data),

  // 删除用户组
  delete: (id: number): Promise<void> => 
    request.delete(`/groups/${id}`),

  // 给用户组分配用户
  assignUsers: (id: number, data: AssignUsersRequest): Promise<UserGroup> => 
    request.post<UserGroup>(`/groups/${id}/users`, data),

  // 给用户组分配策略
  assignPolicies: (id: number, data: AssignPoliciesRequest): Promise<UserGroup> => 
    request.post<UserGroup>(`/groups/${id}/policies`, data),

  // 获取用户组的用户列表
  getUsers: (id: number): Promise<any> => 
    request.get(`/groups/${id}/users`),

  // 获取用户组的策略列表
  getPolicies: (id: number): Promise<any> => 
    request.get(`/groups/${id}/policies`),
}


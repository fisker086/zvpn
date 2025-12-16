import request from './request'

export interface User {
  id: number
  username: string
  email: string
  is_admin: boolean
  is_active: boolean
  vpn_ip?: string
  connected: boolean
  groups?: Array<{
    id: number
    name: string
  }>
  created_at?: string
  updated_at?: string
}

export interface CreateUserRequest {
  username: string
  password: string
  email?: string
  is_admin?: boolean
  group_ids: number[] // 必须指定用户组
}

export interface UpdateUserRequest {
  email?: string
  is_admin?: boolean
  is_active?: boolean
  group_ids?: number[] // 更新用户组（必须至少一个）
}

export const usersApi = {
  // 获取用户列表
  list: (): Promise<User[]> => 
    request.get<User[]>('/users'),

  // 获取用户详情
  get: (id: number): Promise<User> => 
    request.get<User>(`/users/${id}`),

  // 创建用户
  create: (data: CreateUserRequest): Promise<User> => 
    request.post<User>('/users', data),

  // 更新用户
  update: (id: number, data: UpdateUserRequest): Promise<User> => 
    request.put<User>(`/users/${id}`, data),

  // 删除用户
  delete: (id: number): Promise<void> => 
    request.delete(`/users/${id}`),

  // 修改密码
  changePassword: (id: number, password: string): Promise<void> => 
    request.put(`/users/${id}/password`, { password }),
}


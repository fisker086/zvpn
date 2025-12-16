import request from './request'

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  token: string
  user: {
    id: number
    username: string
    email: string
    is_admin: boolean
  }
}

export interface UserProfile {
  id: number
  username: string
  email: string
  is_admin: boolean
}

export const authApi = {
  // 登录
  login: (data: LoginRequest): Promise<LoginResponse> => 
    request.post<LoginResponse>('/auth/login', data),

  // 获取用户信息
  getProfile: (): Promise<UserProfile> => 
    request.get<UserProfile>('/auth/profile'),

  // 登出
  logout: (): Promise<void> => 
    request.post('/auth/logout'),
}


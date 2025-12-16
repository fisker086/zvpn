import request from './request'

export interface LDAPAttributeMapping {
  username?: string   // 用户名属性，例如: "uid", "sAMAccountName", "cn"
  email?: string      // 邮箱属性，例如: "mail", "email"
  full_name?: string  // 全名属性，例如: "displayName", "cn", "name"
  member_of?: string  // 组成员属性，例如: "memberOf", "groupMembership"
}

export interface LDAPConfig {
  id: number
  enabled: boolean
  host: string
  port: number
  use_ssl: boolean
  bind_dn: string
  base_dn: string
  user_filter: string
  admin_group: string
  skip_tls_verify: boolean
  attribute_mapping?: string  // JSON格式的属性映射
  created_at?: string
  updated_at?: string
}

export interface LDAPStatus {
  enabled: boolean
}

export interface LDAPTestResponse {
  success: boolean
  message?: string
  error?: string
}

export interface LDAPAuthTestRequest {
  username: string
  password: string
}

export interface LDAPAuthTestResponse {
  success: boolean
  message?: string
  error?: string
  user?: {
    dn: string
    username: string
    email: string
    full_name: string
    is_admin: boolean
  }
}

export interface LDAPSyncResponse {
  success: boolean
  message?: string
  error?: string
  total?: number
  created?: number
  updated?: number
  errors?: number
  error_details?: string[]
}

export interface UpdateLDAPConfigRequest {
  enabled: boolean
  host: string
  port: number
  use_ssl: boolean
  bind_dn: string
  bind_password?: string // 可选，只有修改时才传
  base_dn: string
  user_filter: string
  admin_group: string
  skip_tls_verify: boolean
  attribute_mapping?: string // JSON格式的属性映射，可选
}

export const ldapApi = {
  // 获取LDAP配置状态（公开接口）
  getStatus: (): Promise<LDAPStatus> => 
    request.get<LDAPStatus>('/ldap/status'),

  // 获取LDAP配置（需要管理员权限）
  getConfig: (): Promise<LDAPConfig> => 
    request.get<LDAPConfig>('/ldap/config'),

  // 更新LDAP配置（需要管理员权限）
  updateConfig: (data: UpdateLDAPConfigRequest): Promise<LDAPConfig> => 
    request.put<LDAPConfig>('/ldap/config', data),

  // 测试LDAP连接（需要管理员权限）
  testConnection: (): Promise<LDAPTestResponse> => 
    request.post<LDAPTestResponse>('/ldap/test'),

  // 测试LDAP用户认证（需要管理员权限）
  testAuth: (data: LDAPAuthTestRequest): Promise<LDAPAuthTestResponse> => 
    request.post<LDAPAuthTestResponse>('/ldap/test-auth', data),

  // 同步LDAP用户到本地数据库（需要管理员权限）
  syncUsers: (): Promise<LDAPSyncResponse> => 
    request.post<LDAPSyncResponse>('/ldap/sync-users'),
}


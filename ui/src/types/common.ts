/**
 * 通用类型定义
 */

// 分页响应
export interface PaginatedResponse<T> {
  data: T[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

// 分页查询参数
export interface PaginationQuery {
  page?: number
  page_size?: number
}

// 搜索查询参数
export interface SearchQuery extends PaginationQuery {
  search?: string
  keyword?: string
}

// 时间范围查询
export interface TimeRangeQuery {
  start_time?: string
  end_time?: string
}

// API响应
export interface ApiResponse<T = any> {
  data?: T
  message?: string
  error?: string
}

// 选项类型
export interface Option {
  label: string
  value: any
  disabled?: boolean
}

// 状态类型
export type Status = 'success' | 'error' | 'warning' | 'info' | 'default'

// 加载状态
export interface LoadingState {
  loading: boolean
  error?: string | null
}


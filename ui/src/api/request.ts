import axios from 'axios'
import type { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios'
import { Message } from '@arco-design/web-vue'

// 自定义 axios 实例类型，确保返回的是响应数据而不是完整的 AxiosResponse 类型
type CustomAxiosInstance = Omit<AxiosInstance, 'get' | 'post' | 'put' | 'delete' | 'patch' | 'head' | 'options'> & {
  <T = any>(config: AxiosRequestConfig): Promise<T>
  request<T = any>(config: AxiosRequestConfig): Promise<T>
  get<T = any>(url: string, config?: AxiosRequestConfig): Promise<T>
  delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<T>
  head<T = any>(url: string, config?: AxiosRequestConfig): Promise<T>
  post<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T>
  put<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T>
  patch<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T>
}

// 获取 API base URL
// 优先级：环境变量 > 开发环境默认值 > 生产环境相对路径
const getBaseURL = (): string => {
  // 如果设置了环境变量，优先使用
  if (import.meta.env.VITE_API_BASE_URL) {
    return import.meta.env.VITE_API_BASE_URL
  }
  
  // 开发环境使用 localhost
  if (import.meta.env.DEV) {
    return 'http://localhost:8080/api/v1'
  }
  
  // 生产环境使用相对路径，自动使用当前域名
  return '/api/v1'
}

// 创建 axios 实例
const service: CustomAxiosInstance = axios.create({
  baseURL: getBaseURL(),
  timeout: 10000,
})

// 请求拦截器
service.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// 响应拦截器
service.interceptors.response.use(
  (response: AxiosResponse) => {
    return response.data
  },
  (error) => {
    // 检查是否是登录请求（通过请求URL判断）
    const isLoginRequest = error.config?.url?.includes('/auth/login') || error.config?.url === '/auth/login'
    // 检查是否在登录页面
    const isLoginPage = window.location.pathname === '/login' || window.location.pathname === '/login/'
    
    if (error.response?.status === 401) {
      // 如果是登录请求失败，不要跳转，让登录页面自己处理错误
      if (isLoginRequest || isLoginPage) {
        // 登录失败，不显示错误（由登录页面处理），也不跳转
        return Promise.reject(error)
      }
      // Token 过期，跳转到登录页（非登录请求的401错误）
      localStorage.removeItem('token')
      // 使用 router 跳转而不是 window.location，避免页面刷新
      if (window.location.pathname !== '/login') {
        window.location.href = '/login'
        Message.error('登录已过期，请重新登录')
      }
    } else {
      // 非登录请求的错误才在这里显示（登录请求的错误由登录组件自己处理）
      if (!isLoginRequest && !isLoginPage) {
        const message = error.response?.data?.error || error.response?.data?.message || error.message || '请求失败'
        Message.error(message)
      }
    }
    return Promise.reject(error)
  }
)

export default service


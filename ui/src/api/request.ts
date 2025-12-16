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
    if (error.response?.status === 401) {
      // Token 过期，跳转到登录页
      localStorage.removeItem('token')
      window.location.href = '/login'
      Message.error('登录已过期，请重新登录')
    } else {
      const message = error.response?.data?.error || error.message || '请求失败'
      Message.error(message)
    }
    return Promise.reject(error)
  }
)

export default service


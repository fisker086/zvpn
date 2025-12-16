import request from './request'

export interface VPNStatus {
  connected_users: number
  total_users: number
  total_policies: number
  vpn_network: string
  vpn_port: number
  uptime: string
}

export interface ConnectedUser {
  id: number
  username: string
  full_name?: string  // 中文名/全名（LDAP用户有，系统账户可选）
  vpn_ip: string
  connected: boolean
  connected_at?: string
  user_agent?: string
  client_os?: string
  client_ver?: string
  groups?: Array<{
    id: number
    name: string
  }>
}

export interface EBPFStats {
  ebpf_enabled: boolean
  total_packets: number
  dropped_packets: number
  total_bytes: number
  dropped_bytes: number
  avg_packet_size: number
  filter_hits: number
  timestamp?: number // Optional timestamp for SSE stream updates
}

export const vpnApi = {
  // 获取服务器状态
  getStatus: (): Promise<VPNStatus> => 
    request.get<VPNStatus>('/vpn/admin/status'),

  // 获取已连接用户列表
  getConnectedUsers: (): Promise<ConnectedUser[]> => 
    request.get<ConnectedUser[]>('/vpn/admin/connected'),

  // 获取eBPF统计信息
  getEBPFStats: (): Promise<EBPFStats> => 
    request.get<EBPFStats>('/vpn/admin/ebpf/stats'),

  // 创建 eBPF 统计 SSE 连接
  createEBPFStatsStream: (onMessage: (data: EBPFStats) => void, onError?: (error: Event) => void): EventSource => {

    // 获取 baseURL，确保正确处理相对路径和绝对路径
    let baseURL = (request.defaults.baseURL as string) || '/api/v1'
    
    // 如果是相对路径，需要拼接当前域名
    if (baseURL.startsWith('/')) {
      baseURL = window.location.origin + baseURL
    }
    const token = localStorage.getItem('token')
    
    // EventSource 不支持自定义 headers，所以通过 URL 参数传递 token
    // 注意：后端需要支持从 query 参数读取 token
    // 确保路径正确：baseURL 已经包含 /api/v1，所以只需要 /vpn/admin/ebpf/stats/stream
    const url = `${baseURL}/vpn/admin/ebpf/stats/stream${token ? `?token=${encodeURIComponent(token)}` : ''}`
    
    console.log('Connecting to SSE stream:', url)
    
    const eventSource = new EventSource(url)
    
    eventSource.addEventListener('open', () => {
      console.log('SSE connection opened')
    })
    
    eventSource.addEventListener('connected', (event: MessageEvent) => {
      console.log('SSE connected to eBPF stats stream:', event.data)
    })
    
    eventSource.addEventListener('stats', (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data) as EBPFStats & { timestamp?: number }
        onMessage(data)
      } catch (error) {
        console.error('Failed to parse SSE message:', error, event.data)
      }
    })
    
    eventSource.addEventListener('error', (error) => {
      console.error('SSE error:', error)
      // 检查连接状态
      if (eventSource.readyState === EventSource.CONNECTING) {
        console.log('SSE connecting...')
      } else if (eventSource.readyState === EventSource.OPEN) {
        console.log('SSE connection is open')
      } else if (eventSource.readyState === EventSource.CLOSED) {
        console.log('SSE connection closed')
      }
      if (onError) {
        onError(error)
      }
    })
    
    return eventSource
  },
}


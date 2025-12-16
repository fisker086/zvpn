import request from './request'

export interface SystemMetrics {
  uptime_seconds: number
  load1: number
  load5: number
  load15: number
  mem_total_bytes: number
  mem_used_bytes: number
  mem_free_bytes: number
  swap_total_bytes: number
  swap_used_bytes: number
  tx_bytes: number
  rx_bytes: number
  interface: string
  interface_ok: boolean
  timestamp: number
  interval_sec: number
}

export const systemApi = {
  getMetrics: (): Promise<SystemMetrics> => request.get<SystemMetrics>('/system/metrics'),
}


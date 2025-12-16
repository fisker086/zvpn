/**
 * 数据格式化工具函数
 */

// 格式化日期时间
export function formatDateTime(dateString: string | Date | undefined | null): string {
  if (!dateString) return '-'
  const date = typeof dateString === 'string' ? new Date(dateString) : dateString
  if (isNaN(date.getTime())) return '-'
  
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

// 格式化日期
export function formatDate(dateString: string | Date | undefined | null): string {
  if (!dateString) return '-'
  const date = typeof dateString === 'string' ? new Date(dateString) : dateString
  if (isNaN(date.getTime())) return '-'
  
  return date.toLocaleDateString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  })
}

// 格式化时间
export function formatTime(dateString: string | Date | undefined | null): string {
  if (!dateString) return '-'
  const date = typeof dateString === 'string' ? new Date(dateString) : dateString
  if (isNaN(date.getTime())) return '-'
  
  return date.toLocaleTimeString('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

// 格式化相对时间
export function formatRelativeTime(dateString: string | Date | undefined | null): string {
  if (!dateString) return '-'
  const date = typeof dateString === 'string' ? new Date(dateString) : dateString
  if (isNaN(date.getTime())) return '-'
  
  const now = new Date()
  const diff = now.getTime() - date.getTime()
  const seconds = Math.floor(diff / 1000)
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)
  const days = Math.floor(hours / 24)

  if (days > 0) {
    return `${days}天前`
  } else if (hours > 0) {
    return `${hours}小时前`
  } else if (minutes > 0) {
    return `${minutes}分钟前`
  } else {
    return '刚刚'
  }
}

// 格式化文件大小
export function formatFileSize(bytes: number | undefined | null): string {
  if (bytes === undefined || bytes === null || isNaN(Number(bytes))) {
    return '-'
  }
  const numBytes = Number(bytes)
  if (numBytes === 0) {
    return '0 B'
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  let size = numBytes
  let unitIndex = 0
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024
    unitIndex++
  }
  return `${size.toFixed(2)} ${units[unitIndex]}`
}

// 格式化带宽
export function formatBandwidth(bytes: number | undefined | null): string {
  return formatFileSize(bytes) + '/s'
}

// 格式化数字
export function formatNumber(num: number | undefined | null): string {
  if (num === undefined || num === null || isNaN(Number(num))) {
    return '-'
  }
  return Number(num).toLocaleString('zh-CN')
}

// 格式化百分比
export function formatPercent(value: number, total: number): string {
  if (total === 0) return '0%'
  return `${((value / total) * 100).toFixed(2)}%`
}

// 格式化持续时间
export function formatDuration(seconds: number): string {
  if (seconds < 60) {
    return `${seconds}秒`
  } else if (seconds < 3600) {
    const minutes = Math.floor(seconds / 60)
    const secs = seconds % 60
    return secs > 0 ? `${minutes}分${secs}秒` : `${minutes}分钟`
  } else if (seconds < 86400) {
    const hours = Math.floor(seconds / 3600)
    const mins = Math.floor((seconds % 3600) / 60)
    return mins > 0 ? `${hours}小时${mins}分钟` : `${hours}小时`
  } else {
    const days = Math.floor(seconds / 86400)
    const hours = Math.floor((seconds % 86400) / 3600)
    return hours > 0 ? `${days}天${hours}小时` : `${days}天`
  }
}


/**
 * 表单验证工具函数
 */

// 验证邮箱
export function validateEmail(email: string): boolean {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return re.test(email)
}

// 验证IP地址
export function validateIP(ip: string): boolean {
  const re = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
  return re.test(ip)
}

// 验证CIDR
export function validateCIDR(cidr: string): boolean {
  const re = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/
  return re.test(cidr)
}

// 验证域名
export function validateDomain(domain: string): boolean {
  const re = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/
  return re.test(domain)
}

// 验证端口
export function validatePort(port: number): boolean {
  return port >= 1 && port <= 65535
}

// 验证URL
export function validateURL(url: string): boolean {
  try {
    new URL(url)
    return true
  } catch {
    return false
  }
}

// 验证密码强度
export function validatePasswordStrength(password: string): {
  valid: boolean
  strength: 'weak' | 'medium' | 'strong'
  message: string
} {
  if (password.length < 8) {
    return {
      valid: false,
      strength: 'weak',
      message: '密码长度至少8位',
    }
  }

  let strength = 0
  if (/[a-z]/.test(password)) strength++
  if (/[A-Z]/.test(password)) strength++
  if (/[0-9]/.test(password)) strength++
  if (/[^a-zA-Z0-9]/.test(password)) strength++

  if (strength < 2) {
    return {
      valid: false,
      strength: 'weak',
      message: '密码强度较弱，建议包含大小写字母、数字和特殊字符',
    }
  }

  if (strength === 2) {
    return {
      valid: true,
      strength: 'medium',
      message: '密码强度中等',
    }
  }

  return {
    valid: true,
    strength: 'strong',
    message: '密码强度强',
  }
}


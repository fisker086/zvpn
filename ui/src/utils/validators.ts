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
  const hasLower = /[a-z]/.test(password)
  const hasUpper = /[A-Z]/.test(password)
  const hasNumber = /[0-9]/.test(password)
  const hasSpecial = /[^a-zA-Z0-9]/.test(password)
  
  if (hasLower) strength++
  if (hasUpper) strength++
  if (hasNumber) strength++
  if (hasSpecial) strength++

  // 需要至少包含3种类型的字符（大小写、数字、特殊字符）
  if (strength < 3) {
    const missing: string[] = []
    if (!hasLower) missing.push('小写字母')
    if (!hasUpper) missing.push('大写字母')
    if (!hasNumber) missing.push('数字')
    if (!hasSpecial) missing.push('特殊字符（如 !@#$%^&*）')
    
    return {
      valid: false,
      strength: 'weak',
      message: `密码复杂度不足，需要包含大小写字母、数字和特殊字符。当前缺少：${missing.join('、')}`,
    }
  }

  if (strength === 3) {
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



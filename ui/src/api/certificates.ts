import request from './request'

export interface CertInfo {
  sni: string
  common_name: string
  dns_names: string[]
  issuer: string
  not_before: string
  not_after: string
  days_remaining: number
  is_expired: boolean
  is_default: boolean
}

export interface CertificateListResponse {
  default_cert: CertInfo | null
  sni_certs: Record<string, CertInfo>
  total: number
}

// 获取所有证书列表
export function getCertificates(): Promise<CertificateListResponse> {
  return request.get('/certificates')
}

// 添加 SNI 证书（文件上传）
export function addSNICertificate(formData: FormData): Promise<void> {
  return request.post('/certificates/sni', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  })
}

// 添加 SNI 证书（JSON）
export function addSNICertificateJSON(data: {
  sni: string
  cert_data?: string
  key_data?: string
  cert_file?: string
  key_file?: string
}): Promise<void> {
  return request.post('/certificates/sni', data)
}

// 删除 SNI 证书
export function removeSNICertificate(sni: string): Promise<void> {
  return request.delete(`/certificates/sni/${encodeURIComponent(sni)}`)
}

// 更新默认证书（文件上传）
export function updateDefaultCertificate(formData: FormData): Promise<void> {
  return request.put('/certificates/default', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  })
}

// 更新默认证书（JSON）
export function updateDefaultCertificateJSON(data: {
  cert_data?: string
  key_data?: string
  cert_file?: string
  key_file?: string
}): Promise<void> {
  return request.put('/certificates/default', data)
}



import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { authApi, type LoginRequest, type UserProfile } from '@/api/auth'

export const useAuthStore = defineStore('auth', () => {
  const token = ref(localStorage.getItem('token') || '')
  const user = ref<UserProfile | null>(null)

  const isAuthenticated = computed(() => !!token.value)
  const isAdmin = computed(() => user.value?.is_admin || false)

  // 登录
  async function login(data: LoginRequest) {
    const response = await authApi.login(data)
    token.value = response.token
    user.value = response.user
    localStorage.setItem('token', response.token)
    return response
  }

  // 登出
  async function logout() {
    try {
      await authApi.logout()
    } finally {
      token.value = ''
      user.value = null
      localStorage.removeItem('token')
    }
  }

  // 获取用户信息
  async function fetchProfile() {
    const profile = await authApi.getProfile()
    user.value = profile
    return profile
  }

  return {
    token,
    user,
    isAuthenticated,
    isAdmin,
    login,
    logout,
    fetchProfile,
  }
})


<template>
  <div class="login-container">
    <div class="login-box">
      <div class="login-header">
        <icon-robot-add :size="48" />
        <h1>ZVPN 管理后台</h1>
        <p>欢迎登录 ZVPN 管理系统</p>
      </div>

      <a-form
        v-if="!statusLoading"
        :model="formData"
        layout="vertical"
        @submit="handleSubmit"
      >
        <a-form-item
          field="username"
          label="用户名"
          :rules="[{ required: true, message: '请输入用户名' }]"
        >
          <a-input
            v-model="formData.username"
            :placeholder="ldapEnabled ? '请输入 LDAP 用户名' : '请输入用户名'"
            size="large"
            allow-clear
            autocomplete="username"
          >
            <template #prefix>
              <icon-user />
            </template>
          </a-input>
          <template v-if="ldapEnabled" #extra>
            <a-typography-text type="secondary" style="font-size: 12px">
              LDAP用户请输入uid（英文账户名），系统账户请输入账户名。系统会自动识别账户类型。
            </a-typography-text>
          </template>
        </a-form-item>

        <a-form-item
          field="password"
          label="密码"
          :rules="[{ required: true, message: '请输入密码' }]"
        >
          <a-input-password
            v-model="formData.password"
            :placeholder="ldapEnabled ? '请输入 LDAP 密码或系统账户密码' : '请输入密码'"
            size="large"
            allow-clear
            autocomplete="current-password"
            @press-enter="handleSubmit"
          >
            <template #prefix>
              <icon-lock />
            </template>
          </a-input-password>
        </a-form-item>

        <a-form-item>
          <a-button
            type="primary"
            html-type="submit"
            long
            size="large"
            :loading="loading"
          >
            {{ ldapEnabled ? 'LDAP 登录' : '登录' }}
          </a-button>
        </a-form-item>
      </a-form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { Message } from '@arco-design/web-vue'
import { IconUser, IconLock, IconRobotAdd } from '@arco-design/web-vue/es/icon'
import { ldapApi } from '@/api/ldap'

const router = useRouter()
const authStore = useAuthStore()

const formData = reactive({
  username: '',
  password: '',
})

const loading = ref(false)
const ldapEnabled = ref(false)
const statusLoading = ref(true) // 正在加载LDAP状态

const checkLDAPStatus = async () => {
  statusLoading.value = true
  try {
    const status = await ldapApi.getStatus()
    // 完全根据后端返回的值来设置
    ldapEnabled.value = status.enabled || false
  } catch (error) {
    // 如果获取失败，默认使用本地认证
    ldapEnabled.value = false
  } finally {
    statusLoading.value = false
  }
}

const handleSubmit = async (data?: any, e?: Event | any) => {
  // Arco Design 表单提交时，第一个参数是验证后的表单数据，第二个参数可能是事件对象
  // 阻止表单默认提交行为，避免页面刷新
  if (e && typeof e.preventDefault === 'function') {
    e.preventDefault()
  }
  
  // 如果第一个参数是事件对象（某些情况下），也尝试阻止默认行为
  if (data && typeof data.preventDefault === 'function') {
    data.preventDefault()
  }
  
  if (!formData.username || !formData.password) {
    Message.warning('请输入用户名和密码')
    return false
  }

  loading.value = true
  try {
    await authStore.login(formData)
    Message.success('登录成功')
    // 使用 nextTick 确保消息显示后再跳转
    setTimeout(() => {
      router.push('/')
    }, 300)
  } catch (error: any) {
    // 详细错误处理，确保用户能看到具体的错误信息
    console.error('Login error details:', {
      error,
      response: error?.response,
      status: error?.response?.status,
      data: error?.response?.data,
      message: error?.message,
      config: error?.config,
    })
    
    let errorMessage = '登录失败，请检查用户名和密码'
    
    // 优先从响应数据中获取错误信息
    if (error?.response?.data) {
      const data = error.response.data
      const status = error.response.status
      
      // 尝试多种可能的错误信息字段
      if (typeof data === 'string') {
        errorMessage = data
      } else if (data.error) {
        errorMessage = String(data.error)
        
        // 如果是401错误且包含剩余尝试次数，补充显示
        if (status === 401 && data.remaining_attempts !== undefined) {
          errorMessage += `，还剩${data.remaining_attempts}次尝试机会`
        }
      } else if (data.message) {
        errorMessage = String(data.message)
      } else if (data.msg) {
        errorMessage = String(data.msg)
      } else if (data.detail) {
        errorMessage = String(data.detail)
      } else {
        // 如果都没有，根据状态码显示友好的错误信息
        switch (status) {
          case 400:
            errorMessage = '请求参数错误，请检查用户名和密码格式'
            break
          case 401:
            if (data.remaining_attempts !== undefined) {
              errorMessage = `用户名或密码错误，请重试，还剩${data.remaining_attempts}次尝试机会`
            } else {
              errorMessage = '用户名或密码错误，请重试'
            }
            break
          case 403:
            errorMessage = '账户已被禁用，请联系管理员'
            break
          case 404:
            errorMessage = '用户不存在'
            break
          case 429:
            // 使用后端返回的具体封禁信息，如果没有则使用默认信息
            if (data.error) {
              errorMessage = data.error
            } else {
              errorMessage = '登录尝试次数过多，请稍后再试'
            }
            break
          case 500:
          case 502:
          case 503:
            errorMessage = '服务器错误，请稍后重试'
            break
          default:
            errorMessage = `登录失败 (错误代码: ${status})`
        }
      }
    } else if (error?.message) {
      // 网络错误或其他错误
      if (error.message.includes('timeout')) {
        errorMessage = '请求超时，请检查网络连接或稍后重试'
      } else if (error.message.includes('Network Error')) {
        errorMessage = '网络连接失败，请检查网络设置'
      } else {
        errorMessage = `登录失败: ${error.message}`
      }
    } else if (typeof error === 'string') {
      errorMessage = error
    }
    
    // 确保错误消息一定会显示（使用 setTimeout 确保在下一个事件循环中显示）
    setTimeout(() => {
      Message.error({
        content: errorMessage,
        duration: 5000, // 显示5秒，让用户有足够时间看到
      })
    }, 100)
    
    // 确保不会刷新页面
    return false
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  checkLDAPStatus()
})
</script>

<style scoped>
.login-container {
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(180deg, #f5f7fa 0%, #e8ecf1 100%);
}

.login-box {
  width: 420px;
  padding: 48px;
  background: #ffffff;
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  border: 1px solid rgba(0, 0, 0, 0.06);
}

.login-header {
  text-align: center;
  margin-bottom: 40px;
}

.login-header :deep(.arco-icon) {
  color: rgb(var(--primary-6));
  margin-bottom: 20px;
  opacity: 0.9;
}

.login-header h1 {
  margin: 0 0 8px;
  font-size: 26px;
  font-weight: 500;
  color: var(--color-text-1);
  letter-spacing: -0.5px;
}

.login-header p {
  margin: 0;
  font-size: 14px;
  color: var(--color-text-3);
  font-weight: 400;
}

:deep(.arco-form-item) {
  margin-bottom: 24px;
}

:deep(.arco-form-item-label) {
  font-weight: 500;
  color: var(--color-text-2);
  margin-bottom: 8px;
}

:deep(.arco-input-wrapper) {
  border-color: rgba(0, 0, 0, 0.1);
  transition: all 0.2s;
}

:deep(.arco-input-wrapper:hover) {
  border-color: rgba(0, 0, 0, 0.2);
}

:deep(.arco-input-wrapper.arco-input-focus) {
  border-color: rgb(var(--primary-6));
  box-shadow: 0 0 0 2px rgba(var(--primary-6), 0.1);
}

:deep(.arco-btn-primary) {
  height: 44px;
  font-size: 15px;
  font-weight: 500;
  border-radius: 6px;
  transition: all 0.2s;
}

:deep(.arco-btn-primary:hover) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(var(--primary-6), 0.3);
}

:deep(.arco-alert) {
  border-radius: 6px;
  border: 1px solid rgba(0, 0, 0, 0.06);
  background: rgba(var(--primary-1), 0.5);
}
</style>


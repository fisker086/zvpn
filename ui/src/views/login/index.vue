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

const handleSubmit = async () => {
  if (!formData.username || !formData.password) {
    Message.warning('请输入用户名和密码')
    return
  }

  loading.value = true
  try {
    await authStore.login(formData)
    Message.success('登录成功')
    router.push('/')
  } catch (error: any) {
    Message.error(error.response?.data?.error || '登录失败')
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


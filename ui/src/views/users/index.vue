<template>
  <div class="users-page">
    <a-space direction="vertical" :size="20" fill>
      <a-card :bordered="false">
        <template #title>
          <div class="card-header">
            <div class="header-left">
              <h3>用户管理</h3>
              <p class="description-text">管理系统用户和权限。用户必须属于至少一个用户组，策略通过用户组管理。</p>
            </div>
            <div class="header-right" v-if="canCreate">
              <a-button type="primary" @click="showCreateModal">
                <template #icon>
                  <icon-plus />
                </template>
                创建用户
              </a-button>
            </div>
          </div>
        </template>

        <div class="table-wrapper">
        <a-table
          :columns="columns"
          :data="users"
          :loading="loading"
          :pagination="pagination"
          :scroll="{ x: 'max-content' }"
          @page-change="handlePageChange"
        >
          <template #username="{ record }">
            <a-space>
              <a-avatar :size="32">
                <icon-user />
              </a-avatar>
              <div class="user-info">
                <div class="user-name">
                  {{ record.full_name || record.username }}
                </div>
                <div v-if="record.full_name" class="user-username">
                  {{ record.username }}
                </div>
              </div>
            </a-space>
          </template>

          <template #email="{ record }">
            <span class="text-secondary">{{ record.email || '-' }}</span>
          </template>

          <template #is_admin="{ record }">
            <a-tag v-if="record.is_admin" color="red">管理员</a-tag>
            <a-tag v-else color="blue">普通用户</a-tag>
          </template>

          <template #is_active="{ record }">
            <a-badge
              :status="record.is_active ? 'success' : 'default'"
              :text="record.is_active ? '激活' : '禁用'"
            />
          </template>

          <template #connected="{ record }">
            <a-badge
              :status="record.connected ? 'success' : 'default'"
              :text="record.connected ? '在线' : '离线'"
            />
          </template>

          <template #source="{ record }">
            <a-tag v-if="record.source === 'ldap'" color="purple">LDAP</a-tag>
            <a-tag v-else-if="record.source === 'system'" color="blue">系统</a-tag>
            <a-tag v-else color="gray">{{ record.source || '系统' }}</a-tag>
          </template>

          <template #groups="{ record }">
            <a-space wrap>
              <a-tag
                v-for="group in record.groups"
                :key="group.id"
                color="green"
                size="small"
              >
                {{ group.name }}
              </a-tag>
              <span v-if="!record.groups || record.groups.length === 0" class="text-secondary">
                未分配用户组
              </span>
            </a-space>
          </template>

          <template #actions="{ record }">
            <!-- 管理员：可以操作所有用户 -->
            <a-space v-if="authStore.isAdmin">
              <a-button size="small" type="text" @click="handleEdit(record)">
                编辑
              </a-button>
              <a-button size="small" type="text" @click="handleManageOTP(record)">
                双因素
              </a-button>
              <a-button
                size="small"
                type="text"
                status="danger"
                @click="handleDelete(record)"
              >
                删除
              </a-button>
            </a-space>
            <!-- 用户本人（非管理员）：只能管理自己的OTP -->
            <a-space v-else-if="authStore.user && authStore.user.id === record.id">
              <a-button size="small" type="text" @click="handleManageOTP(record)">
                双因素
              </a-button>
            </a-space>
            <!-- 其他用户：只读 -->
            <span v-else class="text-secondary">只读</span>
          </template>
        </a-table>
        </div>
      </a-card>
    </a-space>

    <!-- 创建/编辑用户对话框 -->
    <a-modal
      v-model:visible="modalVisible"
      :title="isEdit ? '编辑用户' : '创建用户'"
      @ok="handleSubmit"
      @cancel="handleCancel"
      :ok-loading="submitLoading"
      width="500px"
    >
      <a-form :model="formData" layout="vertical">
        <a-form-item label="用户名" :required="!isEdit">
          <a-input
            v-model="formData.username"
            placeholder="请输入用户名"
            :disabled="isEdit"
          />
        </a-form-item>

        <a-form-item label="密码" :required="!isEdit">
          <a-input-password
            v-model="formData.password"
            :placeholder="isEdit ? '留空则不修改密码' : '请输入密码'"
            :disabled="isEdit && currentUser?.source === 'ldap'"
          />
          <template #extra v-if="isEdit && currentUser?.source === 'ldap'">
            <a-typography-text type="secondary" style="font-size: 12px">
              LDAP用户的密码由LDAP服务器管理，无法在此修改
            </a-typography-text>
          </template>
          <template #extra v-else-if="isEdit">
            <a-typography-text type="secondary" style="font-size: 12px">
              留空则不修改密码，填写新密码将更新用户密码
            </a-typography-text>
          </template>
          <template #extra v-else>
            <a-alert
              type="info"
              :closable="false"
              style="margin-top: 8px"
            >
              <template #icon>
                <icon-info-circle />
              </template>
              <div style="font-size: 12px">
                <div style="margin-bottom: 4px"><strong>密码要求：</strong></div>
                <div>• 长度至少 8 位</div>
                <div>• 包含大小写字母、数字和特殊字符（如 !@#$%^&*）</div>
                <div style="margin-top: 4px; color: var(--color-text-3)">
                  示例：MyP@ssw0rd
                </div>
              </div>
            </a-alert>
          </template>
        </a-form-item>

        <a-form-item label="邮箱">
          <a-input
            v-model="formData.email"
            placeholder="请输入邮箱"
          />
        </a-form-item>

        <a-form-item label="中文名">
          <a-input
            v-model="formData.full_name"
            placeholder="请输入中文名（可选）"
          />
          <template #extra>
            <a-typography-text type="secondary" style="font-size: 12px">
              可选，用于显示用户的中文名称。LDAP用户会自动同步此字段。
            </a-typography-text>
          </template>
        </a-form-item>

        <a-form-item 
          label="用户组" 
          required
          :validate-status="(!isEdit && (!formData.group_ids || formData.group_ids.length === 0)) ? 'error' : ''"
          :help="(!isEdit && (!formData.group_ids || formData.group_ids.length === 0)) ? '请至少选择一个用户组' : ''"
        >
          <a-select
            v-model="formData.group_ids"
            placeholder="请选择用户组（必选）"
            multiple
            :loading="groupsLoading"
            :status="(!isEdit && (!formData.group_ids || formData.group_ids.length === 0)) ? 'error' : ''"
          >
            <a-option
              v-for="group in groups"
              :key="group.id"
              :value="group.id"
            >
              {{ group.name }}
              <template v-if="group.description">
                - {{ group.description }}
              </template>
            </a-option>
          </a-select>
          <template #extra>
            <a-alert
              type="warning"
              :closable="false"
              style="margin-top: 8px"
            >
              <template #icon>
                <icon-exclamation-circle-fill />
              </template>
              <div style="font-size: 12px">
                <div><strong>⚠️ 必选项：</strong>用户必须属于至少一个用户组</div>
                <div style="margin-top: 4px">策略通过用户组自动分配，用户无法直接绑定策略。</div>
              </div>
            </a-alert>
          </template>
        </a-form-item>

        <a-form-item label="管理员">
          <a-switch v-model="formData.is_admin" />
        </a-form-item>

        <a-form-item label="激活状态" v-if="isEdit">
          <a-switch v-model="formData.is_active" />
        </a-form-item>

        <a-form-item label="隧道模式">
          <a-select v-model="formData.tunnel_mode" placeholder="选择隧道模式">
            <a-option value="split">分离隧道（默认）</a-option>
            <a-option value="full">全局模式</a-option>
          </a-select>
          <template #extra>
            <div class="tunnel-mode-help">
              <div class="mode-card mode-card-recommended">
                <div class="mode-header">
                  <icon-check-circle-fill class="mode-icon mode-icon-success" />
                  <span class="mode-title">分离隧道（推荐）</span>
                </div>
                <div class="mode-content">
                  <div class="mode-desc">
                    <strong>只有策略中配置的特定网段走 VPN</strong>，其他所有流量（包括未配置的公网和本地网络）都走本地网络。
                  </div>
                  <div class="mode-tip mode-tip-success" style="margin-top: 8px;">
                    ✓ 例如：策略配置了公司服务器网段 203.0.113.0/24，只有访问该网段的流量走 VPN，访问 baidu.com、本地网络等都走本地
                  </div>
                </div>
              </div>
              
              <div class="mode-card">
                <div class="mode-header">
                  <icon-computer class="mode-icon mode-icon-primary" />
                  <span class="mode-title">全局模式</span>
                </div>
                <div class="mode-content">
                  <div class="mode-desc">
                    <strong>所有公网流量走 VPN</strong>，只有本地网络（私有IP）被排除，走本地网络。
                  </div>
                  <div class="mode-tip mode-tip-success" style="margin-top: 8px;">
                    ✓ 例如：访问 baidu.com、google.com 等公网走 VPN，访问 192.168.x.x、10.x.x.x 等本地网络走本地
                  </div>
                </div>
              </div>
            </div>
          </template>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- OTP认证管理对话框 -->
    <a-modal
      v-model:visible="otpModalVisible"
      title="OTP双因素认证"
      :footer="false"
      width="600px"
    >
      <a-space direction="vertical" :size="16" fill v-if="currentOTPUser">
        <a-alert type="info" :closable="false">
          <template #icon><icon-info-circle /></template>
          为用户 <strong>{{ currentOTPUser.username }}</strong> 配置OTP双因素认证
        </a-alert>

        <a-card v-if="otpSecret" :bordered="true">
          <template #title>OTP密钥已生成</template>
          <a-space direction="vertical" :size="12" fill>
            <div>
              <a-typography-text strong>请使用以下方式之一配置OTP：</a-typography-text>
            </div>
            <div>
              <a-typography-text>1. 扫描二维码：</a-typography-text>
              <div style="margin-top: 8px; text-align: center">
                <img :src="otpQRCode" alt="OTP QR Code" style="max-width: 200px" />
              </div>
            </div>
            <div>
              <a-typography-text>2. 手动输入密钥：</a-typography-text>
              <a-input
                :value="otpSecret"
                readonly
                style="margin-top: 8px"
              >
                <template #suffix>
                  <a-button type="text" size="small" @click="copyToClipboard(otpSecret)">
                    <template #icon><icon-copy /></template>
                  </a-button>
                </template>
              </a-input>
            </div>
            <a-alert type="warning" :closable="false">
              请妥善保管此密钥，丢失后需要重新生成
            </a-alert>
          </a-space>
        </a-card>

        <!-- OTP状态提示 -->
        <a-alert v-if="otpEnabled && !otpSecret" type="success" :closable="false">
          <template #icon><icon-check-circle /></template>
          该用户已启用OTP认证。如需重新生成密钥，请点击"生成OTP密钥"按钮。
        </a-alert>

        <a-space>
          <a-button type="primary" @click="handleGenerateOTP" :loading="otpLoading" v-if="!otpSecret">
            生成OTP密钥
          </a-button>
          <a-button type="primary" @click="handleGenerateOTP" :loading="otpLoading" v-else>
            重新生成OTP密钥
          </a-button>
          <a-button @click="handleDisableOTP" :loading="otpLoading" v-if="otpEnabled" danger>
            禁用OTP
          </a-button>
          <a-button @click="otpModalVisible = false">关闭</a-button>
        </a-space>
      </a-space>
    </a-modal>

  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { usersApi, type User, type CreateUserRequest, type UpdateUserRequest } from '@/api/users'
import { groupsApi, type UserGroup } from '@/api/groups'
import { Message, Modal } from '@arco-design/web-vue'
import { 
  IconPlus, 
  IconUser, 
  IconInfoCircle, 
  IconCopy,
  IconCheckCircle,
  IconCheckCircleFill,
  IconComputer,
  IconExclamationCircleFill
} from '@arco-design/web-vue/es/icon'
import request from '@/api/request'
import { useClipboard } from '@/composables/useClipboard'
import { useConfirm } from '@/composables/useConfirm'
import { usePermission } from '@/composables/usePermission'
import { useAuthStore } from '@/stores/auth'
import { validateEmail, validatePasswordStrength } from '@/utils/validators'

const { canCreate, canEdit } = usePermission()
const authStore = useAuthStore()

const loading = ref(false)
const submitLoading = ref(false)
const groupsLoading = ref(false)
const users = ref<User[]>([])
const groups = ref<UserGroup[]>([])
const modalVisible = ref(false)
const isEdit = ref(false)
const currentUser = ref<User | null>(null)

// OTP认证相关
const otpModalVisible = ref(false)
const otpLoading = ref(false)
const currentOTPUser = ref<User | null>(null)
const otpSecret = ref('')
const otpQRCode = ref('')
const otpEnabled = ref(false) // 用户是否已启用OTP


const pagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0,
})

const formData = reactive<CreateUserRequest & UpdateUserRequest & { group_ids?: number[] }>({
  username: '',
  password: '',
  email: '',
  full_name: '',
  is_admin: false,
  is_active: true,
  group_ids: [],
  tunnel_mode: 'split', // 默认分离隧道模式
})

const columns = [
  {
    title: '用户',
    slotName: 'username',
    width: 200,
    align: 'center',
  },
  {
    title: '邮箱',
    slotName: 'email',
    width: 220,
    align: 'center',
  },
  {
    title: '角色',
    slotName: 'is_admin',
    width: 100,
    align: 'center',
  },
  {
    title: '状态',
    slotName: 'is_active',
    width: 100,
    align: 'center',
  },
  {
    title: '连接',
    slotName: 'connected',
    width: 100,
    align: 'center',
  },
  {
    title: '来源',
    slotName: 'source',
    width: 100,
    align: 'center',
    tooltip: '用户来源：系统账户或LDAP用户',
  },
  {
    title: '用户组',
    slotName: 'groups',
    width: 200,
    align: 'center',
    tooltip: '用户所属的用户组，策略通过用户组分配',
  },
  {
    title: '操作',
    slotName: 'actions',
    width: 150,
    align: 'center',
    fixed: 'right',
  },
]

const fetchUsers = async () => {
  loading.value = true
  try {
    const data = await usersApi.list()
    users.value = data
    pagination.total = data.length
  } catch (error) {
    Message.error('获取用户列表失败')
  } finally {
    loading.value = false
  }
}


const fetchGroups = async () => {
  groupsLoading.value = true
  try {
    const data = await groupsApi.list()
    groups.value = data
  } catch (error) {
    Message.error('获取用户组列表失败')
  } finally {
    groupsLoading.value = false
  }
}

const showCreateModal = () => {
  isEdit.value = false
  currentUser.value = null
  resetForm()
  modalVisible.value = true
}

const handleEdit = async (record: User) => {
  isEdit.value = true
  currentUser.value = record
  formData.username = record.username
  formData.email = record.email || ''
  formData.full_name = record.full_name || ''
  formData.is_admin = record.is_admin
  formData.is_active = record.is_active
  // 修复：确保正确加载 tunnel_mode，如果数据库中是 'full'，应该保持 'full'
  // 只有当 record.tunnel_mode 是 undefined、null 或空字符串时，才使用默认值 'split'
  formData.tunnel_mode = (record.tunnel_mode === 'full' || record.tunnel_mode === 'split') 
    ? record.tunnel_mode 
    : 'split'
  formData.password = '' // 编辑时清空密码字段，如果用户需要修改密码，需要填写新密码
  formData.group_ids = record.groups?.map(g => g.id) || []
  if (formData.group_ids.length === 0) {
    Message.warning('该用户未分配用户组，请先分配用户组')
  }
  modalVisible.value = true
}

const handleDelete = (record: User) => {
  confirmDelete(record.username, async () => {
    try {
      await usersApi.delete(record.id)
      Message.success('删除成功')
      fetchUsers()
    } catch (error) {
      Message.error('删除失败')
    }
  })
}

const handleSubmit = async () => {
  // 验证必填项
  if (!formData.username || (!isEdit.value && !formData.password)) {
    Message.warning('请填写必填项（用户名和密码）')
    return
  }

  // 验证邮箱格式
  if (formData.email && !validateEmail(formData.email)) {
    Message.warning('请输入有效的邮箱地址')
    return
  }

  // 验证密码强度（创建用户时）
  if (!isEdit.value && formData.password) {
    const passwordCheck = validatePasswordStrength(formData.password)
    if (!passwordCheck.valid) {
      Message.warning(passwordCheck.message)
      return
    }
  }

  // 验证用户组（创建用户时必选）
  if (!isEdit.value && (!formData.group_ids || formData.group_ids.length === 0)) {
    Message.warning('请至少选择一个用户组，用户必须属于至少一个用户组')
    return
  }

  submitLoading.value = true
  try {
    if (isEdit.value && currentUser.value) {
      // 如果填写了密码，验证密码强度
      if (formData.password && formData.password.trim() !== '' && currentUser.value.source !== 'ldap') {
        const passwordCheck = validatePasswordStrength(formData.password)
        if (!passwordCheck.valid) {
          Message.warning(passwordCheck.message)
          submitLoading.value = false
          return
        }
      }
      
      // 更新用户信息（包括密码，如果提供了）
      const updateData: UpdateUserRequest = {
        email: formData.email,
        full_name: formData.full_name || undefined,
        is_admin: formData.is_admin,
        is_active: formData.is_active,
        group_ids: formData.group_ids,
        // 确保 tunnel_mode 总是被发送
        // 注意：如果 formData.tunnel_mode 是 'full'，应该发送 'full'，不应该被替换成 'split'
        // 只有当 formData.tunnel_mode 是 undefined、null 或空字符串时，才使用默认值 'split'
        // 使用明确的检查，避免 'full' 被错误替换
        tunnel_mode: formData.tunnel_mode === 'full' || formData.tunnel_mode === 'split' 
          ? formData.tunnel_mode 
          : 'split',
      }
      
      // 如果填写了密码，且不是LDAP用户，则添加到更新数据中
      if (formData.password && formData.password.trim() !== '' && currentUser.value.source !== 'ldap') {
        updateData.password = formData.password
      }
      
      await usersApi.update(currentUser.value.id, updateData)
      Message.success(updateData.password ? '用户信息和密码已更新' : '更新成功')
      // 只有成功时才关闭模态框
      modalVisible.value = false
      fetchUsers()
    } else {
      // 创建用户（必须指定用户组）
      await usersApi.create({
        username: formData.username,
        password: formData.password,
        email: formData.email,
        full_name: formData.full_name || undefined,
        is_admin: formData.is_admin,
        group_ids: formData.group_ids,
        tunnel_mode: (formData.tunnel_mode && formData.tunnel_mode.trim()) ? formData.tunnel_mode : 'split',
      })
      
      Message.success('创建成功')
      // 只有成功时才关闭模态框
      modalVisible.value = false
      fetchUsers()
    }
  } catch (error: any) {
    // 失败时不关闭模态框，让用户可以看到错误信息并修改
    Message.error(error.response?.data?.error || '操作失败')
  } finally {
    submitLoading.value = false
  }
}

const handleCancel = () => {
  modalVisible.value = false
  resetForm()
}

const resetForm = () => {
  Object.assign(formData, {
    username: '',
    password: '',
    email: '',
    full_name: '',
    is_admin: false,
    is_active: true,
    group_ids: [],
    tunnel_mode: 'split',
  })
}

const handlePageChange = (page: number) => {
  pagination.current = page
}

// OTP认证管理
const handleManageOTP = (user: User) => {
  currentOTPUser.value = user
  otpSecret.value = ''
  otpQRCode.value = ''
  otpEnabled.value = false
  otpModalVisible.value = true
  // 检查用户是否已有OTP配置
  checkOTPStatus(user.id)
}

const checkOTPStatus = async (userId: number) => {
  try {
    // 响应拦截器已经返回了 response.data，所以直接使用 response
    const response = await request.get(`/users/${userId}/otp`)
    if (response && response.enabled) {
      otpEnabled.value = true
      // 用户已启用OTP，但不显示密钥（安全考虑）
    } else {
      otpEnabled.value = false
    }
  } catch (error) {
    // 用户未配置OTP，设置为未启用
    otpEnabled.value = false
  }
}

const handleGenerateOTP = async () => {
  if (!currentOTPUser.value) return
  
  otpLoading.value = true
  try {
    // 响应拦截器已经返回了 response.data，所以直接使用 response
    const response = await request.post(`/users/${currentOTPUser.value.id}/otp/generate`)
    otpSecret.value = response.secret
    otpQRCode.value = response.qr_code
    otpEnabled.value = true // 生成后自动启用
    Message.success(response.message || 'OTP密钥生成成功，请妥善保管。用户登录时需要输入"密码+OTP代码"')
  } catch (error: any) {
    Message.error(error.response?.data?.error || error.message || '生成OTP密钥失败')
  } finally {
    otpLoading.value = false
  }
}

const handleDisableOTP = async () => {
  if (!currentOTPUser.value) return
  
  const username = currentOTPUser.value.username
  
  // 确认对话框
  const confirmed = await new Promise<boolean>((resolve) => {
    // 使用 Arco Design 的 Modal.confirm
    Modal.confirm({
      title: '确认禁用OTP',
      content: `确定要为用户 ${username} 禁用OTP双因素认证吗？禁用后用户将不再需要输入OTP代码即可登录。`,
      onOk: () => resolve(true),
      onCancel: () => resolve(false),
    })
  })
  
  if (!confirmed) return
  
  otpLoading.value = true
  try {
    await request.delete(`/users/${currentOTPUser.value.id}/otp`)
    otpSecret.value = ''
    otpQRCode.value = ''
    otpEnabled.value = false
    Message.success('OTP认证已禁用')
  } catch (error: any) {
    Message.error(error.response?.data?.error || '禁用OTP失败')
  } finally {
    otpLoading.value = false
  }
}


// 使用 composables
const { copyToClipboard } = useClipboard()
const { confirmDelete } = useConfirm()

onMounted(() => {
  fetchUsers()
  fetchGroups()
})
</script>

<style scoped>
.users-page {
  padding: 24px;
  background: #f7f8fa;
  min-height: calc(100vh - 64px - 48px);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  width: 100%;
  gap: 16px;
}

.header-left {
  flex: 1;
  min-width: 0;
}

.header-right {
  flex-shrink: 0;
}

.card-header h3 {
  margin: 0;
  margin-bottom: 0;
  font-size: 18px;
  font-weight: 600;
  color: var(--color-text-1);
}

.description-text {
  margin: 4px 0 0;
  margin-bottom: 0;
  margin-left: 0;
  padding-left: 0;
  padding-bottom: 0;
  font-size: 12px;
  color: var(--color-text-3);
  line-height: 1.5;
}

.table-wrapper {
  margin-top: 24px;
  padding-top: 0;
}

.user-info {
  display: flex;
  flex-direction: column;
}

.user-name {
  font-weight: 500;
  color: var(--color-text-1);
}

.user-username {
  font-size: 12px;
  color: var(--color-text-3);
  margin-top: 2px;
}

.text-secondary {
  color: var(--color-text-3);
}

:deep(.arco-card) {
  border-radius: 4px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
}

:deep(.arco-card-header) {
  min-height: auto !important;
  height: auto !important;
  padding-bottom: 16px;
}

:deep(.arco-card-header-wrapper) {
  min-height: auto !important;
  height: auto !important;
}

/* 隧道模式帮助样式 */
.tunnel-mode-help {
  margin-top: 12px;
}

.mode-card {
  background: var(--color-bg-2);
  border: 1px solid var(--color-border-2);
  border-radius: 6px;
  padding: 12px;
  margin-bottom: 12px;
  transition: all 0.2s;
}

.mode-card:hover {
  border-color: var(--color-border-3);
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.04);
}

.mode-card-recommended {
  background: linear-gradient(135deg, rgba(0, 180, 42, 0.05) 0%, rgba(0, 180, 42, 0.02) 100%);
  border-color: rgba(0, 180, 42, 0.2);
}

.mode-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.mode-icon {
  font-size: 16px;
  flex-shrink: 0;
}

.mode-icon-success {
  color: rgb(var(--green-6));
}

.mode-icon-primary {
  color: rgb(var(--arcoblue-6));
}

.mode-title {
  font-weight: 600;
  font-size: 13px;
  color: var(--color-text-1);
}

.mode-content {
  font-size: 12px;
  line-height: 1.6;
  color: var(--color-text-2);
}

.mode-desc {
  margin-bottom: 10px;
}

.mode-warning {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  padding: 8px 10px;
  background: rgba(var(--orange-1), 0.5);
  border-left: 3px solid rgb(var(--orange-6));
  border-radius: 4px;
  margin-top: 8px;
  font-size: 12px;
  line-height: 1.5;
  color: rgb(var(--orange-7));
}

.warning-icon {
  font-size: 14px;
  color: rgb(var(--orange-6));
  flex-shrink: 0;
  margin-top: 2px;
}

.mode-tip {
  margin-top: 8px;
  padding: 6px 10px;
  background: rgba(var(--arcoblue-1), 0.5);
  border-radius: 4px;
  font-size: 11px;
  color: rgb(var(--arcoblue-7));
  line-height: 1.5;
}
</style>


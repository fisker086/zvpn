<template>
  <div class="groups-page">
    <a-space direction="vertical" :size="20" fill>
      <a-card :bordered="false">
        <template #title>
          <div class="card-header">
            <div>
              <h3>用户组管理</h3>
              <p>管理用户组，批量授权策略。策略只能绑定用户组，用户通过所属用户组获取策略。</p>
            </div>
              <a-button v-if="canCreate" type="primary" @click="showCreateModal">
                <template #icon>
                  <icon-plus />
                </template>
                创建用户组
              </a-button>
          </div>
        </template>

        <a-table
          :columns="columns"
          :data="groups"
          :loading="loading"
          :pagination="pagination"
          @page-change="handlePageChange"
        >
          <template #name="{ record }">
            <a-space>
              <icon-user-group :size="18" />
              <span class="group-name">{{ record.name }}</span>
            </a-space>
          </template>

          <template #description="{ record }">
            <span class="text-secondary">{{ record.description || '-' }}</span>
          </template>


          <template #users="{ record }">
            <a-space wrap>
              <a-tag
                v-for="user in record.users?.slice(0, 3)"
                :key="user.id"
                color="arcoblue"
                size="small"
              >
                {{ user.username }}
              </a-tag>
              <a-tag v-if="(record.users?.length || 0) > 3" size="small">
                +{{ (record.users?.length || 0) - 3 }}
              </a-tag>
              <span v-if="!record.users || record.users.length === 0" class="text-secondary">
                无用户
              </span>
            </a-space>
          </template>

          <template #policies="{ record }">
            <a-space wrap>
              <a-tag
                v-for="policy in record.policies?.slice(0, 3)"
                :key="policy.id"
                color="purple"
                size="small"
              >
                {{ policy.name }}
              </a-tag>
              <a-tag v-if="(record.policies?.length || 0) > 3" size="small">
                +{{ (record.policies?.length || 0) - 3 }}
              </a-tag>
              <span v-if="!record.policies || record.policies.length === 0" class="text-secondary">
                无策略
              </span>
            </a-space>
          </template>

          <template #actions="{ record }">
            <a-space v-if="canEdit">
              <a-button size="small" type="text" @click="handleEdit(record)">
                编辑
              </a-button>
              <a-button size="small" type="text" @click="handleAssignUsers(record)">
                用户
              </a-button>
              <a-button size="small" type="text" @click="handleAssignPolicies(record)">
                策略
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
            <span v-else class="text-secondary">只读</span>
          </template>
        </a-table>
      </a-card>
    </a-space>

    <!-- 创建/编辑用户组对话框 -->
    <a-modal
      v-model:visible="modalVisible"
      :title="isEdit ? '编辑用户组' : '创建用户组'"
      @ok="handleSubmit"
      @cancel="handleCancel"
      :ok-loading="submitLoading"
      width="500px"
    >
      <a-form :model="formData" layout="vertical">
        <a-form-item label="用户组名称" required>
          <a-input
            v-model="formData.name"
            placeholder="请输入用户组名称"
          />
        </a-form-item>

        <a-form-item label="描述">
          <a-textarea
            v-model="formData.description"
            placeholder="请输入描述"
            :auto-size="{ minRows: 3, maxRows: 5 }"
          />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 分配用户对话框 -->
    <a-modal
      v-model:visible="assignUsersModalVisible"
      title="分配用户"
      @ok="handleAssignUsersSubmit"
      @cancel="assignUsersModalVisible = false"
      :ok-loading="submitLoading"
      width="600px"
    >
      <a-form layout="vertical">
        <a-form-item label="选择用户">
          <a-select
            v-model="selectedUserIds"
            placeholder="请选择用户"
            multiple
            :loading="usersLoading"
            style="width: 100%"
          >
            <a-option
              v-for="user in users"
              :key="user.id"
              :value="user.id"
            >
              {{ user.username }}
              <template v-if="user.email">
                ({{ user.email }})
              </template>
            </a-option>
          </a-select>
        </a-form-item>
        <a-alert
          type="info"
          show-icon
          style="margin-top: 16px"
        >
          <div>
            <div style="margin-bottom: 4px">选择用户后，用户将自动继承用户组的所有策略。</div>
            <div style="font-size: 12px; color: var(--color-text-3)">
              注意：用户必须通过用户组获取策略，不能直接绑定策略。
            </div>
          </div>
        </a-alert>
      </a-form>
    </a-modal>

    <!-- 分配策略对话框 -->
    <a-modal
      v-model:visible="assignPoliciesModalVisible"
      title="分配策略"
      @ok="handleAssignPoliciesSubmit"
      @cancel="assignPoliciesModalVisible = false"
      :ok-loading="submitLoading"
      width="600px"
    >
      <a-form layout="vertical">
        <a-form-item label="选择策略">
          <a-select
            v-model="selectedPolicyIds"
            placeholder="请选择策略"
            multiple
            :loading="policiesLoading"
            style="width: 100%"
          >
            <a-option
              v-for="policy in policies"
              :key="policy.id"
              :value="policy.id"
            >
              {{ policy.name }}
              <template v-if="policy.description">
                - {{ policy.description }}
              </template>
            </a-option>
          </a-select>
        </a-form-item>
        <a-alert
          type="info"
          show-icon
          style="margin-top: 16px"
        >
          <div>
            <div style="margin-bottom: 4px">选择策略后，组内所有用户将自动应用第一个策略。</div>
            <div style="font-size: 12px; color: var(--color-text-3)">
              策略只能通过用户组分配给用户，这是唯一的策略分配方式。
            </div>
          </div>
        </a-alert>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { usePermission } from '@/composables/usePermission'

const { canCreate, canEdit } = usePermission()
import {
  groupsApi,
  type UserGroup,
  type CreateGroupRequest,
  type UpdateGroupRequest,
} from '@/api/groups'
import { usersApi, type User } from '@/api/users'
import { policiesApi, type Policy } from '@/api/policies'
import { Message, Modal } from '@arco-design/web-vue'
import { IconPlus, IconUserGroup, IconInfoCircle, IconCheckCircleFill, IconExclamationCircleFill, IconLink } from '@arco-design/web-vue/es/icon'

const loading = ref(false)
const submitLoading = ref(false)
const usersLoading = ref(false)
const policiesLoading = ref(false)
const groups = ref<UserGroup[]>([])
const users = ref<User[]>([])
const policies = ref<Policy[]>([])
const modalVisible = ref(false)
const assignUsersModalVisible = ref(false)
const assignPoliciesModalVisible = ref(false)
const isEdit = ref(false)
const currentGroup = ref<UserGroup | null>(null)
const selectedUserIds = ref<number[]>([])
const selectedPolicyIds = ref<number[]>([])

const pagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0,
})

const formData = reactive<CreateGroupRequest & UpdateGroupRequest>({
  name: '',
  description: '',
  allow_lan: false,
})

const columns = [
  {
    title: '用户组名称',
    slotName: 'name',
    width: 200,
    align: 'center',
  },
  {
    title: '描述',
    slotName: 'description',
    align: 'center',
  },
  {
    title: '用户',
    slotName: 'users',
    width: 250,
    align: 'center',
  },
  {
    title: '策略',
    slotName: 'policies',
    width: 250,
    align: 'center',
  },
  {
    title: '操作',
    slotName: 'actions',
    width: 250,
    align: 'center',
  },
]

const fetchGroups = async () => {
  loading.value = true
  try {
    const data = await groupsApi.list()
    groups.value = data
    pagination.total = data.length
  } catch (error) {
    Message.error('获取用户组列表失败')
  } finally {
    loading.value = false
  }
}

const fetchUsers = async () => {
  usersLoading.value = true
  try {
    const data = await usersApi.list()
    users.value = data
  } catch (error) {
    Message.error('获取用户列表失败')
  } finally {
    usersLoading.value = false
  }
}

const fetchPolicies = async () => {
  policiesLoading.value = true
  try {
    const data = await policiesApi.list()
    policies.value = data
  } catch (error) {
    Message.error('获取策略列表失败')
  } finally {
    policiesLoading.value = false
  }
}

const showCreateModal = () => {
  isEdit.value = false
  currentGroup.value = null
  resetForm()
  modalVisible.value = true
}

const handleEdit = (record: UserGroup) => {
  isEdit.value = true
  currentGroup.value = record
  formData.name = record.name
  formData.description = record.description || ''
  formData.allow_lan = record.allow_lan || false
  modalVisible.value = true
}

const handleAssignUsers = async (record: UserGroup) => {
  currentGroup.value = record
  await fetchUsers()
  selectedUserIds.value = record.users?.map(u => u.id) || []
  assignUsersModalVisible.value = true
}

const handleAssignPolicies = async (record: UserGroup) => {
  currentGroup.value = record
  await fetchPolicies()
  selectedPolicyIds.value = record.policies?.map(p => p.id) || []
  assignPoliciesModalVisible.value = true
}

const handleDelete = (record: UserGroup) => {
  Modal.confirm({
    title: '确认删除',
    content: `确定要删除用户组 "${record.name}" 吗？`,
    onOk: async () => {
      try {
        await groupsApi.delete(record.id)
        Message.success('删除成功')
        fetchGroups()
      } catch (error) {
        Message.error('删除失败')
      }
    },
  })
}

const handleSubmit = async () => {
  if (!formData.name) {
    Message.warning('请填写用户组名称')
    return
  }

  submitLoading.value = true
  try {
    if (isEdit.value && currentGroup.value) {
      await groupsApi.update(currentGroup.value.id, {
        name: formData.name,
        description: formData.description,
        allow_lan: formData.allow_lan,
      })
      Message.success('更新成功')
    } else {
      await groupsApi.create({
        name: formData.name,
        description: formData.description,
        allow_lan: formData.allow_lan,
      })
      Message.success('创建成功')
    }
    modalVisible.value = false
    fetchGroups()
  } catch (error: any) {
    Message.error(error.response?.data?.error || '操作失败')
  } finally {
    submitLoading.value = false
  }
}

const handleAssignUsersSubmit = async () => {
  if (!currentGroup.value) {
    return
  }

  submitLoading.value = true
  try {
    await groupsApi.assignUsers(currentGroup.value.id, {
      user_ids: selectedUserIds.value,
    })
    Message.success('分配成功')
    assignUsersModalVisible.value = false
    fetchGroups()
  } catch (error: any) {
    Message.error(error.response?.data?.error || '分配失败')
  } finally {
    submitLoading.value = false
  }
}

const handleAssignPoliciesSubmit = async () => {
  if (!currentGroup.value) {
    return
  }

  submitLoading.value = true
  try {
    await groupsApi.assignPolicies(currentGroup.value.id, {
      policy_ids: selectedPolicyIds.value,
    })
    Message.success('分配成功')
    assignPoliciesModalVisible.value = false
    fetchGroups()
  } catch (error: any) {
    Message.error(error.response?.data?.error || '分配失败')
  } finally {
    submitLoading.value = false
  }
}

const handleCancel = () => {
  modalVisible.value = false
  resetForm()
}

const resetForm = () => {
  formData.name = ''
  formData.description = ''
  formData.allow_lan = false
}

const handlePageChange = (page: number) => {
  pagination.current = page
}

onMounted(() => {
  fetchGroups()
})
</script>

<style scoped>
.groups-page {
  padding: 24px;
  background: #f7f8fa;
  min-height: calc(100vh - 64px - 48px);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-header h3 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: var(--color-text-1);
}

.card-header p {
  margin: 4px 0 0;
  font-size: 14px;
  color: var(--color-text-3);
}

.group-name {
  font-weight: 500;
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

/* 排除本地网络帮助样式 */
.allow-lan-help {
  margin-top: 12px;
}

.help-card {
  background: var(--color-bg-2);
  border: 1px solid var(--color-border-2);
  border-radius: 6px;
  padding: 12px;
  margin-bottom: 12px;
  transition: all 0.2s;
}

.help-card:hover {
  border-color: var(--color-border-3);
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.04);
}

.help-card-info {
  background: linear-gradient(135deg, rgba(var(--arcoblue-1), 0.3) 0%, rgba(var(--arcoblue-1), 0.1) 100%);
  border-left: 3px solid rgb(var(--arcoblue-6));
}

.help-card-notice {
  background: linear-gradient(135deg, rgba(var(--orange-1), 0.3) 0%, rgba(var(--orange-1), 0.1) 100%);
  border-left: 3px solid rgb(var(--orange-6));
  margin-bottom: 12px;
}

.help-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 10px;
}

.help-icon {
  font-size: 16px;
  flex-shrink: 0;
  color: rgb(var(--arcoblue-6));
}

.help-icon-success {
  color: rgb(var(--green-6));
}

.help-icon-info {
  color: rgb(var(--arcoblue-6));
}

.help-title {
  font-weight: 600;
  font-size: 13px;
  color: var(--color-text-1);
}

.help-content {
  font-size: 12px;
  line-height: 1.6;
  color: var(--color-text-2);
}

.help-desc {
  margin-bottom: 10px;
}

.help-warning {
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

.help-item {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin-bottom: 8px;
  padding: 6px 0;
}

.help-item:last-child {
  margin-bottom: 0;
}

.help-badge {
  display: inline-block;
  padding: 2px 8px;
  background: rgb(var(--arcoblue-1));
  color: rgb(var(--arcoblue-7));
  border-radius: 4px;
  font-size: 11px;
  font-weight: 500;
  flex-shrink: 0;
  min-width: 70px;
  text-align: center;
}

.help-badge-auto {
  background: rgb(var(--green-1));
  color: rgb(var(--green-7));
}
</style>



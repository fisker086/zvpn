<template>
  <div class="domains-page">
    <a-space direction="vertical" :size="20" fill>
      <a-card :bordered="false">
        <template #title>
          <div class="card-header">
            <div class="header-left">
              <h3>域名动态拆分隧道</h3>
              <p class="description-text">配置域名列表，系统将自动解析域名并动态添加路由规则。</p>
            </div>
            <div class="header-right">
              <a-space>
                <a-button v-if="canCreate" type="primary" @click="addModal.show()">
                  <template #icon>
                    <icon-plus />
                  </template>
                  添加域名
                </a-button>
                <a-button @click="handleRefresh">
                  <template #icon>
                    <icon-refresh />
                  </template>
                  刷新
                </a-button>
              </a-space>
            </div>
          </div>
        </template>

        <div class="table-wrapper">
          <a-table
            :columns="columns"
            :data="domains"
            :loading="loading"
            :pagination="pagination"
            @page-change="handlePageChange"
            @page-size-change="handlePageSizeChange"
          >
        <template #domain="{ record }">
          <a-tag color="blue">{{ record.domain }}</a-tag>
        </template>

        <template #ips="{ record }">
          <a-space wrap>
            <a-tag 
              v-for="ip in record.ips" 
              :key="ip" 
              color="green"
              size="small"
            >
              {{ ip }}
            </a-tag>
            <span v-if="!record.ips || record.ips.length === 0" class="text-secondary">
              未解析
            </span>
          </a-space>
        </template>

        <template #policy="{ record }">
          <a-tag v-if="record.policy_name" color="blue">
            {{ record.policy_name }}
          </a-tag>
          <span v-else class="text-secondary">未关联</span>
        </template>

        <template #status="{ record }">
          <a-badge
            :status="record.resolved ? 'success' : 'default'"
            :text="record.resolved ? '已解析' : '未解析'"
          />
        </template>

        <template #last_used="{ record }">
          <span v-if="record.last_used">{{ formatLastUsed(record.last_used) }}</span>
          <span v-else class="text-secondary">从未使用</span>
        </template>

        <template #actions="{ record }">
          <a-space>
            <a-button type="text" size="small" @click="handleViewRoutes(record)">
              查看路由
            </a-button>
            <template v-if="canEdit">
              <a-button type="text" size="small" @click="handleEdit(record)">
                编辑
              </a-button>
              <a-popconfirm
                content="确定要删除这个域名吗？"
                @ok="handleDelete(record.id)"
              >
                <a-button type="text" size="small" status="danger">
                  删除
                </a-button>
              </a-popconfirm>
            </template>
          </a-space>
        </template>
          </a-table>
        </div>
      </a-card>
    </a-space>

    <!-- 添加/编辑域名对话框 -->
    <a-modal
      v-model:visible="addModalVisible"
      :title="isEditMode ? '编辑域名' : '添加域名'"
      @ok="handleSubmit"
      @cancel="resetAddForm"
      :ok-loading="addLoading"
    >
      <a-form :model="addForm" layout="vertical">
        <a-form-item label="域名" required>
          <a-input
            v-model="addForm.domain"
            placeholder="例如: example.com"
          />
          <template #extra>
            <a-typography-text type="secondary" style="font-size: 12px">
              支持通配符，如 *.example.com
            </a-typography-text>
          </template>
        </a-form-item>

        <a-form-item label="关联策略">
          <a-select
            v-model="addForm.policy_id"
            placeholder="选择策略（可选）"
            allow-clear
            :loading="policies.length === 0"
          >
            <a-option
              v-for="policy in policies"
              :key="policy.id"
              :value="policy.id"
            >
              {{ policy.name }}
            </a-option>
          </a-select>
          <template #extra>
            <a-typography-text type="secondary" style="font-size: 12px">
              关联策略后，使用该策略的用户登录时会自动应用此域名的路由。可用于按策略分组管理域名。
            </a-typography-text>
          </template>
        </a-form-item>

        <a-form-item label="手动配置IP（可选）">
          <a-textarea
            v-model="addForm.manual_ips_text"
            placeholder="每行一个IP地址，例如：&#10;192.168.1.100&#10;10.0.0.50"
            :auto-size="{ minRows: 3, maxRows: 6 }"
          />
          <template #extra>
            <a-typography-text type="secondary" style="font-size: 12px">
              手动配置IP地址（类似hosts文件），用于内网域名等场景。配置后，该域名的DNS查询将直接返回这些IP，无需DNS解析。每行一个IP地址。
            </a-typography-text>
          </template>
        </a-form-item>

        <a-form-item label="自动解析">
          <a-switch v-model="addForm.auto_resolve" />
          <template #extra>
            <a-typography-text type="secondary" style="font-size: 12px">
              启用后，系统将自动解析域名并添加路由。如果已配置手动IP，将优先使用手动IP。
            </a-typography-text>
          </template>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 路由查看对话框 -->
    <a-modal
      v-model:visible="routesModalVisible"
      title="域名路由信息"
      :footer="false"
    >
      <a-descriptions :data="routeInfo" :column="1" bordered />
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, computed } from 'vue'
import { usePermission } from '@/composables/usePermission'

const { canCreate, canEdit } = usePermission()
import { Message } from '@arco-design/web-vue'
import { IconPlus, IconRefresh } from '@arco-design/web-vue/es/icon'
import request from '@/api/request'
import { useTable } from '@/composables/useTable'
import { useModal } from '@/composables/useModal'
import { useConfirm } from '@/composables/useConfirm'
import { validateDomain } from '@/utils/validators'
import { formatRelativeTime } from '@/utils/formatters'

interface Domain {
  id: number
  domain: string
  ips: string[]
  manual_ips?: string[]
  resolved: boolean
  resolved_at?: string
  policy_id?: number
  policy_name?: string
  auto_resolve?: boolean
  routes?: Array<{
    cidr: string
    gateway?: string
  }>
  access_count: number
  last_used?: string
}

// 使用 composables
const {
  loading,
  data: domains,
  pagination,
  fetchData: fetchDomains,
  handlePageChange,
  handlePageSizeChange,
  refresh: handleRefresh,
} = useTable<Domain>(
  async (params) => {
    const response = await request.get('/vpn/admin/domains', { params })
    return {
      data: response.domains || [],
      total: response.total || 0,
    }
  },
  { pageSize: 10, immediate: false }
)

const addModal = useModal()
const routesModal = useModal()
const { confirmDelete } = useConfirm()

// 状态管理
const policies = ref<Array<{ id: number; name: string }>>([])
const routeInfo = ref<Array<{ label: string; value: string }>>([])
const isEditMode = ref(false)
const editingDomainId = ref<number | null>(null)
const addLoading = ref(false)

// 计算属性来解包 ref，供模板使用
const addModalVisible = computed({
  get: () => addModal.visible.value,
  set: (val: boolean) => {
    addModal.visible.value = val
  }
})

const routesModalVisible = computed({
  get: () => routesModal.visible.value,
  set: (val: boolean) => {
    routesModal.visible.value = val
  }
})

const addForm = reactive({
  domain: '',
  policy_id: undefined as number | undefined,
  auto_resolve: true,
  manual_ips_text: '', // 手动IP文本（多行）
})

const columns = [
  {
    title: '域名',
    dataIndex: 'domain',
    slotName: 'domain',
    align: 'center',
  },
  {
    title: '解析IP',
    dataIndex: 'ips',
    slotName: 'ips',
    align: 'center',
  },
  {
    title: '状态',
    dataIndex: 'status',
    slotName: 'status',
    align: 'center',
  },
  {
    title: '关联策略',
    dataIndex: 'policy_name',
    slotName: 'policy',
    align: 'center',
  },
  {
    title: '访问次数',
    dataIndex: 'access_count',
    align: 'center',
  },
  {
    title: '最后使用',
    dataIndex: 'last_used',
    slotName: 'last_used',
    align: 'center',
  },
  {
    title: '操作',
    slotName: 'actions',
    width: 200,
    fixed: 'right',
    align: 'center',
  },
]

// fetchDomains 已由 useTable 提供

// 获取策略列表
const fetchPolicies = async () => {
  try {
    // 响应拦截器已经返回了 response.data，所以这里直接使用 response
    const response = await request.get('/policies')
    policies.value = Array.isArray(response) ? response : []
  } catch (error) {
    // 静默失败，不影响主功能
    console.error('获取策略列表失败:', error)
    policies.value = []
  }
}

// 处理提交（添加或更新）
const handleSubmit = async () => {
  if (isEditMode.value) {
    await handleUpdate()
  } else {
    await handleAdd()
  }
}

// 添加域名
const handleAdd = async () => {
  if (!addForm.domain || !addForm.domain.trim()) {
    Message.warning('请输入域名')
    return
  }

  // 去除首尾空格
  const domain = addForm.domain.trim()

  if (!validateDomain(domain) && !domain.includes('*')) {
    Message.warning('请输入有效的域名或通配符域名（如 *.example.com）')
    return
  }

  // 处理手动IP地址
  let manualIPs: string[] = []
  if (addForm.manual_ips_text.trim()) {
    const lines = addForm.manual_ips_text.trim().split('\n')
    manualIPs = lines
      .map(line => line.trim())
      .filter(line => line.length > 0)
      .filter(ip => {
        // 简单的IP地址验证
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/
        if (!ipRegex.test(ip)) {
          Message.warning(`无效的IP地址: ${ip}`)
          return false
        }
        // 验证每个数字段
        const parts = ip.split('.')
        for (const part of parts) {
          const num = parseInt(part, 10)
          if (num < 0 || num > 255) {
            Message.warning(`无效的IP地址: ${ip}`)
            return false
          }
        }
        return true
      })
  }

  addLoading.value = true
  try {
    const payload: any = {
      domain: domain,
      policy_id: addForm.policy_id,
      auto_resolve: addForm.auto_resolve,
    }
    if (manualIPs.length > 0) {
      payload.manual_ips = manualIPs
    }
    
    await request.post('/vpn/admin/domains', payload)
    Message.success('域名添加成功')
    addModal.hide()
    resetAddForm()
    await fetchDomains()
  } catch (error: any) {
    const errorMsg = error.response?.data?.error || error.message || '添加域名失败'
    Message.error(errorMsg)
    console.error('添加域名失败:', error)
  } finally {
    addLoading.value = false
  }
}

// 重置添加表单
const resetAddForm = () => {
  addForm.domain = ''
  addForm.policy_id = undefined
  addForm.auto_resolve = true
  addForm.manual_ips_text = ''
  isEditMode.value = false
  editingDomainId.value = null
}

// 编辑域名
const handleEdit = (domain: Domain) => {
  isEditMode.value = true
  editingDomainId.value = domain.id
  addForm.domain = domain.domain
  addForm.policy_id = domain.policy_id
  addForm.auto_resolve = domain.auto_resolve !== undefined ? domain.auto_resolve : true
  // 显示手动配置的IP，如果没有手动IP则显示所有IP（包括自动解析的）
  if (domain.manual_ips && domain.manual_ips.length > 0) {
    addForm.manual_ips_text = domain.manual_ips.join('\n')
  } else if (domain.ips && domain.ips.length > 0) {
    // 如果没有手动IP，显示所有IP（让用户可以将其转换为手动IP）
    addForm.manual_ips_text = domain.ips.join('\n')
  } else {
    addForm.manual_ips_text = ''
  }
  addModal.show()
}

// 更新域名
const handleUpdate = async () => {
  if (!addForm.domain || !addForm.domain.trim()) {
    Message.warning('请输入域名')
    return
  }

  // 去除首尾空格
  const domain = addForm.domain.trim()

  if (!validateDomain(domain) && !domain.includes('*')) {
    Message.warning('请输入有效的域名或通配符域名（如 *.example.com）')
    return
  }

  if (!editingDomainId.value) {
    Message.error('编辑域名ID不存在')
    return
  }

  // 处理手动IP地址
  let manualIPs: string[] = []
  if (addForm.manual_ips_text.trim()) {
    const lines = addForm.manual_ips_text.trim().split('\n')
    manualIPs = lines
      .map(line => line.trim())
      .filter(line => line.length > 0)
      .filter(ip => {
        // 简单的IP地址验证
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/
        if (!ipRegex.test(ip)) {
          Message.warning(`无效的IP地址: ${ip}`)
          return false
        }
        // 验证每个数字段
        const parts = ip.split('.')
        for (const part of parts) {
          const num = parseInt(part, 10)
          if (num < 0 || num > 255) {
            Message.warning(`无效的IP地址: ${ip}`)
            return false
          }
        }
        return true
      })
  }

  addLoading.value = true
  try {
    const payload: any = {
      domain: domain,
      policy_id: addForm.policy_id,
      auto_resolve: addForm.auto_resolve,
    }
    if (manualIPs.length > 0) {
      payload.manual_ips = manualIPs
    }
    
    await request.put(`/vpn/admin/domains/${editingDomainId.value}`, payload)
    Message.success('域名更新成功')
    addModal.hide()
    resetAddForm()
    await fetchDomains()
  } catch (error: any) {
    const errorMsg = error.response?.data?.error || error.message || '更新域名失败'
    Message.error(errorMsg)
    console.error('更新域名失败:', error)
  } finally {
    addLoading.value = false
  }
}

// 查看路由
const handleViewRoutes = (domain: Domain) => {
  routeInfo.value = [
    { label: '域名', value: domain.domain },
    { label: '解析IP', value: domain.ips.join(', ') },
    { label: '状态', value: domain.resolved ? '已解析' : '未解析' },
    { label: '策略', value: domain.policy_name || '无' },
    { label: '访问次数', value: domain.access_count.toString() },
    { label: '最后使用', value: domain.last_used ? formatLastUsed(domain.last_used) : '从未使用' },
  ]
  if (domain.routes && domain.routes.length > 0) {
    routeInfo.value.push({
      label: '路由',
      value: domain.routes.map(r => r.cidr).join(', '),
    })
  }
  routesModal.show()
}

// 格式化最后使用时间
const formatLastUsed = (dateString: string) => {
  if (!dateString) return '从未使用'
  // 使用相对时间格式，更友好
  return formatRelativeTime(dateString)
}

// 删除域名
const handleDelete = (id: number) => {
  const domain = domains.value.find(d => d.id === id)
  confirmDelete(domain?.domain || '该域名', async () => {
    try {
      await request.delete(`/vpn/admin/domains/${id}`)
      Message.success('域名删除成功')
      await fetchDomains()
    } catch (error: any) {
      Message.error(error.response?.data?.error || '删除域名失败')
    }
  })
}

onMounted(() => {
  fetchDomains()
  fetchPolicies()
})
</script>

<style scoped>
.domains-page {
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
</style>


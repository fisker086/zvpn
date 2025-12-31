<template>
  <div class="policies-page">
    <a-space direction="vertical" :size="20" fill>
      <a-card :bordered="false">
        <template #title>
          <div class="card-header">
            <div>
              <h3>策略管理</h3>
              <p>管理用户访问策略和路由规则。策略必须绑定用户组，用户通过所属用户组获取策略。</p>
            </div>
            <a-button v-if="canCreate" type="primary" @click="showCreateModal">
              <template #icon>
                <icon-plus />
              </template>
              创建策略
            </a-button>
          </div>
        </template>

        <a-table
          :columns="columns"
          :data="policies"
          :loading="loading"
          :pagination="pagination"
          :scroll="{ x: 'max-content' }"
          @page-change="handlePageChange"
        >
          <template #name="{ record }">
            <a-space>
              <icon-settings :size="18" />
              <span class="policy-name">{{ record.name }}</span>
            </a-space>
          </template>

          <template #description="{ record }">
            <a-tooltip v-if="record.description" :content="record.description">
              <div
                style="
                  padding: 0 8px;
                  max-width: 300px;
                  overflow: hidden;
                  text-overflow: ellipsis;
                  white-space: nowrap;
                  color: var(--color-text-2);
                "
              >
                {{ record.description }}
              </div>
            </a-tooltip>
            <span v-else class="text-secondary">-</span>
          </template>

          <template #routes="{ record }">
            <div class="routes-container">
              <a-tag
                v-for="route in record.routes.slice(0, 3)"
                :key="route.id"
                color="arcoblue"
                size="small"
              >
                {{ route.network }}
              </a-tag>
              <a-tag v-if="record.routes.length > 3" size="small">
                +{{ record.routes.length - 3 }}
              </a-tag>
              <span v-if="record.routes.length === 0" class="text-secondary">
                无路由
              </span>
            </div>
          </template>

          <template #groups="{ record }">
            <div class="groups-container">
              <a-tag
                v-for="group in record.groups?.slice(0, 2)"
                :key="group.id"
                color="green"
                size="small"
              >
                {{ group.name }}
              </a-tag>
              <a-tag v-if="(record.groups?.length || 0) > 2" size="small">
                +{{ (record.groups?.length || 0) - 2 }}
              </a-tag>
              <span v-if="!record.groups || record.groups.length === 0" class="text-secondary">
                未绑定用户组
              </span>
            </div>
          </template>

          <template #max_bandwidth="{ record }">
            <span class="text-secondary">
              {{ formatBandwidth(record.max_bandwidth) }}
            </span>
          </template>

          <template #dns_servers="{ record }">
            <div class="dns-container">
              <a-tag
                v-for="(dns, index) in (record.dns_servers || []).slice(0, 2)"
                :key="index"
                color="purple"
                size="small"
              >
                {{ dns }}
              </a-tag>
              <a-tag v-if="(record.dns_servers?.length || 0) > 2" size="small">
                +{{ (record.dns_servers?.length || 0) - 2 }}
              </a-tag>
              <span v-if="!record.dns_servers || record.dns_servers.length === 0" class="text-secondary">
                系统默认
              </span>
            </div>
          </template>

          <template #actions="{ record }">
            <div v-if="canEdit" style="display: flex; justify-content: center;">
              <a-button size="small" type="text" @click="handleEdit(record)">
                编辑
              </a-button>
              <a-button size="small" type="text" @click="handleEditRoutes(record)">
                路由
              </a-button>
              <a-button size="small" type="text" @click="handleEditExcludeRoutes(record)">
                排除路由
              </a-button>
              <a-button size="small" type="text" @click="handleAssignGroups(record)">
                用户组
              </a-button>
              <a-button
                size="small"
                type="text"
                status="danger"
                @click="handleDelete(record)"
              >
                删除
              </a-button>
            </div>
            <span v-else class="text-secondary">只读</span>
          </template>
        </a-table>
      </a-card>
    </a-space>

    <!-- 创建/编辑策略对话框 -->
    <a-modal
      v-model:visible="modalVisible"
      :title="isEdit ? '编辑策略' : '创建策略'"
      @ok="handleSubmit"
      @cancel="handleCancel"
      :ok-loading="submitLoading"
      width="600px"
    >
      <a-form :model="formData" layout="vertical">
        <a-form-item label="策略名称" required>
          <a-input
            v-model="formData.name"
            placeholder="请输入策略名称"
          />
        </a-form-item>

        <a-form-item label="描述">
          <a-textarea
            v-model="formData.description"
            placeholder="请输入描述"
            :auto-size="{ minRows: 3, maxRows: 5 }"
          />
        </a-form-item>

        <a-form-item label="最大带宽 (bytes/s)">
          <a-input-number
            v-model="formData.max_bandwidth"
            placeholder="不限制"
            :min="0"
            style="width: 100%"
          />
        </a-form-item>

        <a-form-item label="DNS服务器">
          <a-space direction="vertical" :size="8" fill>
            <div
              v-for="(_, index) in formData.dns_servers || []"
              :key="index"
              style="display: flex; gap: 8px; align-items: center"
            >
              <a-input
                v-model="(formData.dns_servers || [])[index]"
                placeholder="例如: 8.8.8.8"
                style="flex: 1"
              />
              <a-button
                v-if="canEdit"
                type="text"
                status="danger"
                @click="removeDNSServer(index)"
              >
                删除
              </a-button>
            </div>
            <a-button
              v-if="canEdit"
              type="dashed"
              long
              @click="addDNSServer"
            >
              <template #icon>
                <icon-plus />
              </template>
              添加DNS服务器
            </a-button>
          </a-space>
          <template #extra>
            <a-typography-text type="secondary" style="font-size: 12px">
              为空时使用系统默认DNS（8.8.8.8, 8.8.4.4）
            </a-typography-text>
          </template>
        </a-form-item>

        <a-form-item 
          v-if="!isEdit" 
          label="用户组" 
          required
        >
          <a-select
            v-model="formData.group_ids"
            placeholder="请选择用户组（必选）"
            multiple
            :loading="groupsLoading"
            style="width: 100%"
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
            <a-typography-text type="secondary" style="font-size: 12px">
              策略必须绑定至少一个用户组，组内用户将自动应用此策略
            </a-typography-text>
          </template>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 路由管理对话框 -->
    <a-modal
      v-model:visible="routesModalVisible"
      title="路由管理"
      width="700px"
      :footer="false"
    >
      <a-space direction="vertical" :size="16" fill>
        <a-button v-if="canEdit" type="primary" size="small" @click="showAddRouteModal">
          <template #icon>
            <icon-plus />
          </template>
          添加路由
        </a-button>

        <a-table
          :columns="routeColumns"
          :data="currentRoutes"
          :pagination="false"
          row-key="id"
        >
          <template #network="{ record }">
            <a-tag color="arcoblue">{{ record.network }}</a-tag>
          </template>

          <template #gateway="{ record }">
            <span class="text-secondary">{{ record.gateway || '-' }}</span>
          </template>

          <template #actions="{ record }">
            <div v-if="canEdit" style="display: flex; gap: 8px;">
              <a-button
                size="small"
                type="text"
                @click="handleEditRoute(record)"
              >
                编辑
              </a-button>
              <a-button
                size="small"
                type="text"
                status="danger"
                @click="handleDeleteRoute(record)"
              >
                删除
              </a-button>
            </div>
            <span v-else class="text-secondary">只读</span>
          </template>
        </a-table>
      </a-space>
    </a-modal>

    <!-- 添加/编辑路由对话框 -->
    <a-modal
      v-model:visible="addRouteModalVisible"
      :title="isEditRoute ? '编辑路由' : '添加路由'"
      @ok="handleRouteSubmit"
      @cancel="addRouteModalVisible = false"
      :ok-loading="submitLoading"
      width="500px"
    >
      <a-form :model="routeFormData" layout="vertical">
        <a-form-item label="网络 CIDR" required>
          <a-input
            v-model="routeFormData.network"
            placeholder="例如: 192.168.1.0/24"
          />
        </a-form-item>

        <a-form-item label="网关">
          <a-input
            v-model="routeFormData.gateway"
            placeholder="例如: 192.168.1.1"
          />
        </a-form-item>

        <a-form-item label="优先级">
          <a-input-number
            v-model="routeFormData.metric"
            :min="1"
            :max="1000"
            :default-value="100"
            style="width: 100%"
          />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 排除路由管理对话框 -->
    <a-modal
      v-model:visible="excludeRoutesModalVisible"
      title="排除路由管理"
      width="700px"
      :footer="false"
    >
      <a-space direction="vertical" :size="16" fill>
        <a-alert
          type="info"
          show-icon
          style="margin-bottom: 8px"
        >
          <div>
            <div style="margin-bottom: 4px">
              <strong>排除路由用于全局模式</strong>：配置的网段将不走 VPN 隧道，直接走本地网络。
            </div>
            <div style="font-size: 12px; color: var(--color-text-3)">
              <div style="margin-bottom: 4px">
                注意：如果系统配置了 <code>allow_lan=true</code>，会添加 <code>0.0.0.0/255.255.255.255</code> 排除规则（需要客户端开启"Allow Local Lan"选项）。
              </div>
              <div>
                排除路由用于排除其他特定的网段（如私有IP段、公司内网的其他网段、特定的公网IP段等），根据实际需求配置。
              </div>
            </div>
          </div>
        </a-alert>
        <a-button v-if="canEdit" type="primary" size="small" @click="showAddExcludeRouteModal">
          <template #icon>
            <icon-plus />
          </template>
          添加排除路由
        </a-button>

        <a-table
          :columns="excludeRouteColumns"
          :data="currentExcludeRoutes"
          :pagination="false"
          row-key="id"
        >
          <template #network="{ record }">
            <a-tag color="orange">{{ record.network }}</a-tag>
          </template>

          <template #actions="{ record }">
            <div v-if="canEdit" style="display: flex; gap: 8px;">
              <a-button
                size="small"
                type="text"
                @click="handleEditExcludeRoute(record)"
              >
                编辑
              </a-button>
              <a-button
                size="small"
                type="text"
                status="danger"
                @click="handleDeleteExcludeRoute(record)"
              >
                删除
              </a-button>
            </div>
            <span v-else class="text-secondary">只读</span>
          </template>
        </a-table>
      </a-space>
    </a-modal>

    <!-- 添加/编辑排除路由对话框 -->
    <a-modal
      v-model:visible="addExcludeRouteModalVisible"
      :title="isEditExcludeRoute ? '编辑排除路由' : '添加排除路由'"
      @ok="handleExcludeRouteSubmit"
      @cancel="addExcludeRouteModalVisible = false"
      :ok-loading="submitLoading"
      width="500px"
    >
      <a-form :model="excludeRouteFormData" layout="vertical">
        <a-form-item label="网络 CIDR" required>
          <a-input
            v-model="excludeRouteFormData.network"
            placeholder="例如: 203.0.113.0/24"
          />
          <template #extra>
            <a-typography-text type="secondary" style="font-size: 12px">
              <div style="margin-bottom: 4px">
                配置的网段在全局模式下将不走 VPN，直接走本地网络。
              </div>
              <div>
                提示：如果系统配置了 <code>allow_lan=true</code>，会添加 <code>0.0.0.0/255.255.255.255</code> 规则（需要客户端开启"Allow Local Lan"选项）。这里可以配置其他需要排除的网段（如私有IP段、公司内网等）。
              </div>
            </a-typography-text>
          </template>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 分配用户组对话框 -->
    <a-modal
      v-model:visible="assignGroupsModalVisible"
      title="分配用户组"
      @ok="handleAssignGroupsSubmit"
      @cancel="assignGroupsModalVisible = false"
      :ok-loading="submitLoading"
      width="600px"
    >
      <a-form layout="vertical">
        <a-form-item label="选择用户组">
          <a-select
            v-model="selectedGroupIds"
            placeholder="请选择用户组"
            multiple
            :loading="groupsLoading"
            style="width: 100%"
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
        </a-form-item>
        <a-alert
          type="info"
          show-icon
          style="margin-top: 16px"
        >
          <div>
            <div style="margin-bottom: 4px">选择用户组后，该策略将自动应用到组内所有用户。</div>
            <div style="font-size: 12px; color: var(--color-text-3)">
              注意：策略只能绑定用户组，不能直接绑定用户。用户必须通过所属用户组获取策略。
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
  policiesApi,
  type Policy,
  type CreatePolicyRequest,
  type UpdatePolicyRequest,
  type Route,
  type AddRouteRequest,
  type ExcludeRoute,
  type AddExcludeRouteRequest,
} from '@/api/policies'
import { groupsApi, type UserGroup } from '@/api/groups'
import { Message, Modal } from '@arco-design/web-vue'
import { IconPlus, IconSettings } from '@arco-design/web-vue/es/icon'
import { formatBandwidth } from '@/utils'

const loading = ref(false)
const submitLoading = ref(false)
const groupsLoading = ref(false)
const policies = ref<Policy[]>([])
const groups = ref<UserGroup[]>([])
const modalVisible = ref(false)
const routesModalVisible = ref(false)
const excludeRoutesModalVisible = ref(false)
const addRouteModalVisible = ref(false)
const addExcludeRouteModalVisible = ref(false)
const assignGroupsModalVisible = ref(false)
const isEdit = ref(false)
const isEditRoute = ref(false)
const isEditExcludeRoute = ref(false)
const currentPolicy = ref<Policy | null>(null)
const currentRoutes = ref<Route[]>([])
const currentExcludeRoutes = ref<ExcludeRoute[]>([])
const currentRouteId = ref<number | null>(null)
const currentExcludeRouteId = ref<number | null>(null)
const selectedGroupIds = ref<number[]>([])

const pagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0,
})

const formData = reactive<CreatePolicyRequest & UpdatePolicyRequest & { group_ids?: number[] }>({
  name: '',
  description: '',
  max_bandwidth: undefined,
  dns_servers: [],
  group_ids: [],
})

const routeFormData = reactive<AddRouteRequest>({
  network: '',
  gateway: '',
  metric: 100,
})

const excludeRouteFormData = reactive<AddExcludeRouteRequest>({
  network: '',
})

const columns = [
  {
    title: '策略名称',
    slotName: 'name',
    width: 160,
    align: 'center',
  },
  {
    title: '描述',
    slotName: 'description',
    width: 200,
    align: 'center',
    ellipsis: {
      tooltip: true,
    },
  },
  {
    title: '路由规则',
    slotName: 'routes',
    width: 220,
    align: 'center',
  },
  {
    title: '绑定用户组',
    slotName: 'groups',
    width: 160,
    align: 'center',
    tooltip: '策略必须绑定至少一个用户组',
  },
  {
    title: '最大带宽',
    slotName: 'max_bandwidth',
    width: 120,
    align: 'center',
  },
  {
    title: 'DNS服务器',
    slotName: 'dns_servers',
    width: 180,
    align: 'center',
  },
  {
    title: '操作',
    slotName: 'actions',
    width: 160,
    align: 'center',
    fixed: 'right',
  },
]

const routeColumns = [
  {
    title: '网络',
    slotName: 'network',
    align: 'center',
  },
  {
    title: '网关',
    slotName: 'gateway',
    align: 'center',
  },
  {
    title: '优先级',
    dataIndex: 'metric',
    align: 'center',
  },
  {
    title: '操作',
    slotName: 'actions',
    width: 80,
    align: 'center',
  },
]

const excludeRouteColumns = [
  {
    title: '网络',
    slotName: 'network',
    align: 'center',
  },
  {
    title: '操作',
    slotName: 'actions',
    width: 80,
    align: 'center',
  },
]

const fetchPolicies = async () => {
  loading.value = true
  try {
    const data = await policiesApi.list()
    policies.value = data
    pagination.total = data.length
  } catch (error) {
    Message.error('获取策略列表失败')
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
  currentPolicy.value = null
  resetForm()
  modalVisible.value = true
}

const handleEdit = (record: Policy) => {
  isEdit.value = true
  currentPolicy.value = record
  formData.name = record.name
  formData.description = record.description || ''
  formData.max_bandwidth = record.max_bandwidth
  formData.dns_servers = record.dns_servers ? [...record.dns_servers] : []
  formData.group_ids = [] // 编辑时不显示用户组选择，通过"用户组"按钮单独管理
  modalVisible.value = true
}

const handleEditRoutes = (record: Policy) => {
  currentPolicy.value = record
  currentRoutes.value = record.routes || []
  routesModalVisible.value = true
}

const handleEditExcludeRoutes = async (record: Policy) => {
  currentPolicy.value = record
  try {
    // 重新获取策略详情，确保包含最新的排除路由数据
    const policy = await policiesApi.get(record.id)
    currentExcludeRoutes.value = policy.exclude_routes || []
    excludeRoutesModalVisible.value = true
  } catch (error: any) {
    Message.error(error.response?.data?.error || '获取策略详情失败')
  }
}

const handleDelete = (record: Policy) => {
  Modal.confirm({
    title: '确认删除',
    content: `确定要删除策略 "${record.name}" 吗？`,
    onOk: async () => {
      try {
        await policiesApi.delete(record.id)
        Message.success('删除成功')
        fetchPolicies()
      } catch (error) {
        Message.error('删除失败')
      }
    },
  })
}

const handleSubmit = async () => {
  if (!formData.name) {
    Message.warning('请填写策略名称')
    return
  }

  // 创建策略时必须选择用户组
  if (!isEdit.value && (!formData.group_ids || formData.group_ids.length === 0)) {
    Message.warning('策略必须绑定至少一个用户组')
    return
  }

  submitLoading.value = true
  try {
    // 处理DNS服务器：过滤空值，如果为空数组则发送空数组（后端会处理为使用默认DNS）
    const dnsServers = formData.dns_servers?.filter(dns => dns && dns.trim() !== '') || []
    
    if (isEdit.value && currentPolicy.value) {
      await policiesApi.update(currentPolicy.value.id, {
        name: formData.name,
        description: formData.description,
        max_bandwidth: formData.max_bandwidth,
        dns_servers: dnsServers.length > 0 ? dnsServers : [],
      })
      Message.success('更新成功')
    } else {
      await policiesApi.create({
        name: formData.name,
        description: formData.description,
        max_bandwidth: formData.max_bandwidth,
        dns_servers: dnsServers.length > 0 ? dnsServers : [],
        group_ids: formData.group_ids!,
      })
      Message.success('创建成功')
    }
    modalVisible.value = false
    fetchPolicies()
  } catch (error: any) {
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
  formData.name = ''
  formData.description = ''
  formData.max_bandwidth = undefined
  formData.dns_servers = []
  formData.group_ids = []
}

const addDNSServer = () => {
  if (!formData.dns_servers) {
    formData.dns_servers = []
  }
  formData.dns_servers.push('')
}

const removeDNSServer = (index: number) => {
  if (formData.dns_servers) {
    formData.dns_servers.splice(index, 1)
  }
}

const showAddRouteModal = () => {
  resetRouteForm()
  addRouteModalVisible.value = true
}

const showAddExcludeRouteModal = () => {
  resetExcludeRouteForm()
  addExcludeRouteModalVisible.value = true
}

const handleRouteSubmit = async () => {
  if (!routeFormData.network) {
    Message.warning('请填写网络 CIDR')
    return
  }

  if (!currentPolicy.value) {
    return
  }

  submitLoading.value = true
  try {
    if (isEditRoute.value && currentRouteId.value) {
      // 修改路由
      await policiesApi.updateRoute(currentPolicy.value.id, currentRouteId.value, {
        network: routeFormData.network,
        gateway: routeFormData.gateway,
        metric: routeFormData.metric || 100,
      })
      Message.success('更新成功')
    } else {
      // 添加路由
      await policiesApi.addRoute(currentPolicy.value.id, {
        network: routeFormData.network,
        gateway: routeFormData.gateway,
        metric: routeFormData.metric || 100,
      })
      Message.success('添加成功')
    }
    addRouteModalVisible.value = false
    
    const policy = await policiesApi.get(currentPolicy.value.id)
    currentRoutes.value = policy.routes || []
    fetchPolicies()
  } catch (error: any) {
    Message.error(error.response?.data?.error || '操作失败')
  } finally {
    submitLoading.value = false
  }
}

const handleDeleteRoute = (record: Route) => {
  if (!currentPolicy.value) {
    return
  }

  Modal.confirm({
    title: '确认删除',
    content: `确定要删除路由 "${record.network}" 吗？`,
    onOk: async () => {
      try {
        await policiesApi.deleteRoute(currentPolicy.value!.id, record.id)
        Message.success('删除成功')
        currentRoutes.value = currentRoutes.value.filter((r) => r.id !== record.id)
        fetchPolicies()
      } catch (error) {
        Message.error('删除失败')
      }
    },
  })
}

const resetRouteForm = () => {
  routeFormData.network = ''
  routeFormData.gateway = ''
  routeFormData.metric = 100
  isEditRoute.value = false
  currentRouteId.value = null
}

const handleEditRoute = (record: Route) => {
  isEditRoute.value = true
  currentRouteId.value = record.id
  routeFormData.network = record.network
  routeFormData.gateway = record.gateway || ''
  routeFormData.metric = record.metric
  addRouteModalVisible.value = true
}

const handlePageChange = (page: number) => {
  pagination.current = page
}

const handleAssignGroups = (record: Policy) => {
  currentPolicy.value = record
  selectedGroupIds.value = record.groups?.map(g => g.id) || []
  assignGroupsModalVisible.value = true
}

const handleAssignGroupsSubmit = async () => {
  if (!currentPolicy.value) {
    return
  }

  submitLoading.value = true
  try {
    await policiesApi.assignGroups(currentPolicy.value.id, {
      group_ids: selectedGroupIds.value,
    })
    Message.success('分配成功')
    assignGroupsModalVisible.value = false
    fetchPolicies()
  } catch (error: any) {
    Message.error(error.response?.data?.error || '分配失败')
  } finally {
    submitLoading.value = false
  }
}

const handleExcludeRouteSubmit = async () => {
  if (!excludeRouteFormData.network) {
    Message.warning('请填写网络 CIDR')
    return
  }

  if (!currentPolicy.value) {
    return
  }

  submitLoading.value = true
  try {
    if (isEditExcludeRoute.value && currentExcludeRouteId.value) {
      // 修改排除路由
      await policiesApi.updateExcludeRoute(currentPolicy.value.id, currentExcludeRouteId.value, {
        network: excludeRouteFormData.network,
      })
      Message.success('更新成功')
    } else {
      // 添加排除路由
      await policiesApi.addExcludeRoute(currentPolicy.value.id, {
        network: excludeRouteFormData.network,
      })
      Message.success('添加成功')
    }
    addExcludeRouteModalVisible.value = false
    
    const policy = await policiesApi.get(currentPolicy.value.id)
    currentExcludeRoutes.value = policy.exclude_routes || []
    fetchPolicies()
  } catch (error: any) {
    Message.error(error.response?.data?.error || '操作失败')
  } finally {
    submitLoading.value = false
  }
}

const handleDeleteExcludeRoute = (record: ExcludeRoute) => {
  if (!currentPolicy.value) {
    return
  }

  Modal.confirm({
    title: '确认删除',
    content: `确定要删除排除路由 "${record.network}" 吗？`,
    onOk: async () => {
      try {
        await policiesApi.deleteExcludeRoute(currentPolicy.value!.id, record.id)
        Message.success('删除成功')
        currentExcludeRoutes.value = currentExcludeRoutes.value.filter((r) => r.id !== record.id)
        fetchPolicies()
      } catch (error) {
        Message.error('删除失败')
      }
    },
  })
}

const resetExcludeRouteForm = () => {
  excludeRouteFormData.network = ''
  isEditExcludeRoute.value = false
  currentExcludeRouteId.value = null
}

const handleEditExcludeRoute = (record: ExcludeRoute) => {
  isEditExcludeRoute.value = true
  currentExcludeRouteId.value = record.id
  excludeRouteFormData.network = record.network
  addExcludeRouteModalVisible.value = true
}

onMounted(() => {
  fetchPolicies()
  fetchGroups()
})
</script>

<style scoped>
.policies-page {
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

.policy-name {
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

/* 减少操作列的左右留白 */
:deep(.arco-table-th:last-child),
:deep(.arco-table-td:last-child) {
  padding-left: 8px !important;
  padding-right: 8px !important;
}

/* 减少路由规则和绑定用户组列之间的间距 */
:deep(.arco-table-th:nth-child(3)),
:deep(.arco-table-td:nth-child(3)) {
  padding-right: 8px !important;
}

:deep(.arco-table-th:nth-child(4)),
:deep(.arco-table-td:nth-child(4)) {
  padding-left: 8px !important;
}

/* 优化路由和用户组标签容器，防止换行 */
.routes-container,
.groups-container,
.dns-container {
  display: flex;
  flex-wrap: nowrap;
  align-items: center;
  gap: 4px;
  overflow: hidden;
}

.routes-container .arco-tag,
.groups-container .arco-tag,
.dns-container .arco-tag {
  flex-shrink: 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 100px;
}

/* 确保表格单元格内容不溢出 */
:deep(.arco-table-td) {
  overflow: hidden;
}

:deep(.arco-table-cell) {
  overflow: hidden;
}
</style>

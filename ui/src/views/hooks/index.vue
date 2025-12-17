<template>
  <div class="hooks-page">
    <a-card :bordered="false">
      <template #title>
        <div class="card-header">
          <div>
            <h3>Hook 策略管理</h3>
            <div class="sync-status" v-if="syncStatus && syncStatus.running">
              <a-tag color="green" size="small">
                <template #icon>
                  <icon-check />
                </template>
                同步中
              </a-tag>
              <span class="sync-info" v-if="syncStatus.node_id">
                节点: {{ syncStatus.node_id }}
              </span>
              <span class="sync-info" v-if="syncStatus.last_sync">
                最后同步: {{ formatTime(syncStatus.last_sync) }}
              </span>
            </div>
          </div>
          <a-space>
            <a-button v-if="showSyncActions" @click="handleForceSync" :loading="syncLoading">
              <template #icon>
                <icon-refresh />
              </template>
              强制同步
            </a-button>
            <a-button v-if="canCreate" type="primary" @click="showCreateModal">
              <template #icon>
                <icon-plus />
              </template>
              创建 Hook
            </a-button>
          </a-space>
        </div>
      </template>

      <div class="content-wrapper">
        <a-tabs :default-active-key="String(currentHookPoint)" @change="handleTabChange">
          <a-tab-pane
            v-for="point in hookPoints"
            :key="String(point.value)"
          >
            <template #title>
              <a-tooltip 
                position="bottom" 
                :content-style="{ 
                  maxWidth: '400px', 
                  whiteSpace: 'pre-line',
                  backgroundColor: 'var(--color-bg-popup)',
                  color: 'var(--color-text-1)',
                  border: '1px solid var(--color-border-2)',
                  borderRadius: '4px',
                  boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
                  padding: '12px 16px'
                }"
              >
                <template #content>
                  <div class="hook-tooltip-content">
                    <div class="tooltip-desc">{{ point.description }}</div>
                    <div class="tooltip-scenarios">
                      <div class="tooltip-scenarios-title">适用场景：</div>
                      <ul class="tooltip-scenarios-list">
                        <li v-for="scenario in point.scenarios" :key="scenario">{{ scenario }}</li>
                      </ul>
                    </div>
                  </div>
                </template>
                <div class="hook-tab-title">
                  <div class="hook-tab-name">{{ point.label }}</div>
                  <div class="hook-tab-desc">{{ point.description }}</div>
                </div>
              </a-tooltip>
            </template>
            <a-table
              :columns="columns"
              :data="filteredHooks"
              :loading="loading"
              :pagination="false"
            >
              <template #name="{ record }">
                <a-space>
                  <icon-code :size="18" />
                  <span class="hook-name">{{ record.name }}</span>
                </a-space>
              </template>

              <template #type="{ record }">
                <a-tag :color="getTypeColor(record.type)">
                  {{ getTypeLabel(record.type) }}
                </a-tag>
              </template>

              <template #priority="{ record }">
                <a-tag>优先级 {{ record.priority }}</a-tag>
              </template>

              <template #enabled="{ record }">
                <a-switch
                  v-if="canEdit"
                  v-model="record.enabled"
                  @change="handleToggle(record)"
                  :loading="toggleLoading[record.id]"
                />
                <a-tag v-else :color="record.enabled ? 'green' : 'gray'">
                  {{ record.enabled ? '已启用' : '已禁用' }}
                </a-tag>
              </template>

              <template #stats="{ record }">
                <div v-if="record.stats" class="stats-info">
                  <a-space :size="8">
                    <a-tag color="green">
                      <template #icon>
                        <icon-check />
                      </template>
                      {{ record.stats.total_allows }}
                    </a-tag>
                    <a-tag color="red">
                      <template #icon>
                        <icon-close />
                      </template>
                      {{ record.stats.total_denies }}
                    </a-tag>
                  </a-space>
                </div>
                <span v-else class="text-secondary">-</span>
              </template>

              <template #actions="{ record }">
                <a-space>
                  <a-button size="small" type="text" @click="handleViewRules(record)">
                    规则
                  </a-button>
                  <template v-if="canEdit">
                    <a-button size="small" type="text" @click="handleEdit(record)">
                      编辑
                    </a-button>
                    <a-button
                      size="small"
                      type="text"
                      status="danger"
                      @click="handleDelete(record)"
                    >
                      删除
                    </a-button>
                  </template>
                </a-space>
              </template>
            </a-table>
          </a-tab-pane>
        </a-tabs>
      </div>
    </a-card>

    <!-- 创建/编辑 Hook 对话框 -->
    <a-modal
      v-model:visible="modalVisible"
      :title="isEdit ? '编辑 Hook' : '创建 Hook'"
      width="700px"
      @ok="handleSubmit"
      @cancel="handleCancel"
      :ok-loading="submitLoading"
    >
      <a-form :model="formData" layout="vertical">
        <a-form-item label="Hook 名称" required>
          <a-input
            v-model="formData.name"
            placeholder="请输入 Hook 名称"
          />
        </a-form-item>

        <a-row :gutter="16">
          <a-col :span="12">
            <a-form-item label="Hook 点" required>
              <a-select v-model="formData.hook_point" placeholder="选择 Hook 点">
                <a-option
                  v-for="point in hookPoints"
                  :key="point.value"
                  :value="point.value"
                >
                  <div class="hook-option">
                    <div class="hook-option-name">{{ point.label }}</div>
                    <div class="hook-option-desc">{{ point.description }}</div>
                  </div>
                </a-option>
              </a-select>
            </a-form-item>
            
            <!-- Hook 点场景说明 -->
            <a-alert
              v-if="formData.hook_point"
              type="info"
              :show-icon="true"
              style="margin-bottom: 16px"
            >
              <template #title>
                <div class="hook-scenarios-title">
                  {{ getCurrentHookPoint()?.label }} 适用场景：
                </div>
              </template>
              <ul class="hook-scenarios-list">
                <li v-for="scenario in getCurrentHookScenarios()" :key="scenario">
                  {{ scenario }}
                </li>
              </ul>
            </a-alert>
          </a-col>
          <a-col :span="12">
            <a-form-item label="优先级" required>
              <a-input-number
                v-model="formData.priority"
                :min="1"
                :max="100"
                placeholder="1-100"
                style="width: 100%"
              />
            </a-form-item>
          </a-col>
        </a-row>

        <a-form-item label="类型" required>
          <a-select v-model="formData.type" placeholder="选择 Hook 类型">
            <a-option
              v-for="type in hookTypes"
              :key="type.value"
              :value="type.value"
            >
              {{ type.label }}
            </a-option>
          </a-select>
        </a-form-item>

        <a-form-item label="描述">
          <a-textarea
            v-model="formData.description"
            placeholder="请输入描述"
            :auto-size="{ minRows: 2, maxRows: 4 }"
          />
        </a-form-item>

        <a-form-item label="规则">
          <a-button @click="showRulesEditor" long>
            配置规则 ({{ formData.rules.length }} 条)
          </a-button>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 规则编辑器对话框 -->
    <a-modal
      v-model:visible="rulesModalVisible"
      title="编辑规则"
      width="800px"
      :footer="false"
    >
      <a-space direction="vertical" :size="16" fill>
        <a-button v-if="canEdit" type="primary" size="small" @click="addRule">
          <template #icon>
            <icon-plus />
          </template>
          添加规则
        </a-button>

        <a-collapse
          v-if="formData.rules.length > 0"
          :default-active-key="[0]"
        >
          <a-collapse-item
            v-for="(rule, index) in formData.rules"
            :key="index"
            :header="`规则 ${index + 1}`"
          >
            <template #extra>
              <a-button
                v-if="canEdit"
                size="mini"
                type="text"
                status="danger"
                @click.stop="deleteRule(index)"
              >
                删除
              </a-button>
            </template>

            <a-form layout="vertical">
              <a-form-item label="动作">
                <a-select v-model="rule.action" placeholder="选择动作">
                  <a-option :value="0">允许 (ALLOW)</a-option>
                  <a-option :value="1">拒绝 (DENY)</a-option>
                  <a-option :value="3">记录 (LOG)</a-option>
                </a-select>
                <template #extra>
                  <div style="font-size: 12px; color: var(--color-text-3); margin-top: 4px;">
                    <div><strong>允许：</strong>数据包正常通过，不进行任何拦截</div>
                    <div><strong>拒绝：</strong>数据包被丢弃，访问被阻止</div>
                    <div><strong>记录：</strong>记录到日志文件（./logs/hook_policy.log），然后允许通过。用于审计和监控</div>
                  </div>
                </template>
              </a-form-item>

              <!-- ACL 策略：显示 IP 和网段字段 -->
              <template v-if="formData.type === HookType.ACL">
                <a-form-item label="源 IP">
                  <a-input
                    v-model="rule.source_ips_text"
                    placeholder="多个 IP 用逗号分隔，如：192.168.1.1,10.0.0.1"
                  />
                </a-form-item>

                <a-form-item label="目标 IP">
                  <a-input
                    v-model="rule.destination_ips_text"
                    placeholder="多个 IP 用逗号分隔"
                  />
                </a-form-item>

                <a-form-item label="源网段">
                  <a-input
                    v-model="rule.source_networks_text"
                    placeholder="多个网段用逗号分隔，如：192.168.1.0/24,10.0.0.0/8"
                  />
                </a-form-item>

                <a-form-item label="目标网段">
                  <a-input
                    v-model="rule.destination_networks_text"
                    placeholder="多个网段用逗号分隔"
                  />
                </a-form-item>
              </template>

              <!-- 端口过滤：显示端口字段 -->
              <template v-if="formData.type === HookType.PortFilter">
                <a-row :gutter="16">
                  <a-col :span="12">
                    <a-form-item label="源端口">
                      <a-input
                        v-model="rule.source_ports_text"
                        placeholder="如：80,443,8000-9000"
                      />
                      <template #extra>
                        <span style="color: var(--color-text-3); font-size: 12px;">
                          支持单个端口（80）和范围（8000-9000），多个用逗号分隔
                        </span>
                      </template>
                    </a-form-item>
                  </a-col>
                  <a-col :span="12">
                    <a-form-item label="目标端口">
                      <a-input
                        v-model="rule.destination_ports_text"
                        placeholder="如：80,443,8000-9000"
                      />
                      <template #extra>
                        <span style="color: var(--color-text-3); font-size: 12px;">
                          支持单个端口（80）和范围（8000-9000），多个用逗号分隔
                        </span>
                      </template>
                    </a-form-item>
                  </a-col>
                </a-row>
              </template>

              <!-- 用户策略：显示用户名下拉多选框 -->
              <template v-if="formData.type === HookType.UserPolicy">
                <a-form-item label="用户">
                  <a-select
                    v-model="rule.selected_user_ids"
                    placeholder="选择用户"
                    multiple
                    allow-clear
                    allow-search
                    :loading="usersLoading"
                    :filter-option="filterUserOption"
                  >
                    <a-option
                      v-for="user in users"
                      :key="user.id"
                      :value="user.id"
                      :label="user.username"
                    >
                      <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span>{{ user.username }}</span>
                        <span style="color: var(--color-text-3); font-size: 12px; margin-left: 8px;">
                          (ID: {{ user.id }})
                        </span>
                      </div>
                    </a-option>
                  </a-select>
                  <template #extra>
                    <span style="color: var(--color-text-3); font-size: 12px;">
                      提示：用户策略类型只处理用户，其他字段将被忽略
                    </span>
                  </template>
                </a-form-item>
              </template>

              <!-- 协议字段：ACL 和端口过滤都支持 -->
              <a-form-item 
                v-if="formData.type === HookType.ACL || formData.type === HookType.PortFilter"
                label="协议"
              >
                <a-select
                  v-model="rule.protocols"
                  placeholder="选择协议"
                  multiple
                  allow-clear
                >
                  <a-option value="tcp">TCP</a-option>
                  <a-option value="udp">UDP</a-option>
                  <a-option value="icmp">ICMP</a-option>
                </a-select>
                <template #extra>
                  <span style="color: var(--color-text-3); font-size: 12px;">
                    支持过滤 TCP、UDP、ICMP 协议
                  </span>
                </template>
              </a-form-item>

            </a-form>
          </a-collapse-item>
        </a-collapse>

        <a-empty v-else description="暂无规则，点击添加规则按钮创建" />
      </a-space>
    </a-modal>

    <!-- 查看规则对话框 -->
    <a-modal
      v-model:visible="viewRulesModalVisible"
      title="查看规则"
      width="700px"
      :footer="false"
    >
      <a-space direction="vertical" :size="16" fill>
        <div v-if="currentHook">
          <a-descriptions :column="2" bordered>
            <a-descriptions-item label="名称">
              {{ currentHook.name }}
            </a-descriptions-item>
            <a-descriptions-item label="类型">
              <a-tag :color="getTypeColor(currentHook.type)">
                {{ getTypeLabel(currentHook.type) }}
              </a-tag>
            </a-descriptions-item>
            <a-descriptions-item label="Hook 点">
              {{ getHookPointLabel(currentHook.hook_point) }}
            </a-descriptions-item>
            <a-descriptions-item label="优先级">
              {{ currentHook.priority }}
            </a-descriptions-item>
            <a-descriptions-item label="状态">
              <a-tag :color="currentHook.enabled ? 'green' : 'gray'">
                {{ currentHook.enabled ? '已启用' : '已禁用' }}
              </a-tag>
            </a-descriptions-item>
            <a-descriptions-item label="规则数">
              {{ currentHook.rules?.length || 0 }}
            </a-descriptions-item>
          </a-descriptions>

          <a-divider>规则详情</a-divider>

          <div v-if="currentHook.rules && currentHook.rules.length > 0">
            <a-card
              v-for="(rule, index) in currentHook.rules"
              :key="index"
              :title="`规则 ${index + 1}`"
              :bordered="false"
              size="small"
              style="margin-bottom: 12px"
            >
              <a-descriptions :column="1" size="small">
                <a-descriptions-item label="动作">
                  <a-tag :color="getActionColor(rule.action)">
                    {{ getActionLabel(rule.action) }}
                  </a-tag>
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="rule.source_ips && rule.source_ips.length"
                  label="源 IP"
                >
                  {{ rule.source_ips.join(', ') }}
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="rule.destination_ips && rule.destination_ips.length"
                  label="目标 IP"
                >
                  {{ rule.destination_ips.join(', ') }}
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="rule.source_networks && rule.source_networks.length"
                  label="源网段"
                >
                  {{ rule.source_networks.join(', ') }}
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="rule.destination_networks && rule.destination_networks.length"
                  label="目标网段"
                >
                  {{ rule.destination_networks.join(', ') }}
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="rule.source_ports && rule.source_ports.length"
                  label="源端口"
                >
                  {{ rule.source_ports.join(', ') }}
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="rule.destination_ports && rule.destination_ports.length"
                  label="目标端口"
                >
                  {{ rule.destination_ports.join(', ') }}
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="rule.port_ranges && rule.port_ranges.length"
                  label="端口范围"
                >
                  {{ rule.port_ranges.map(r => `${r.start}-${r.end}`).join(', ') }}
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="rule.protocols && rule.protocols.length"
                  label="协议"
                >
                  {{ rule.protocols.join(', ').toUpperCase() }}
                </a-descriptions-item>
                <a-descriptions-item
                  v-if="rule.user_ids && rule.user_ids.length"
                  label="用户"
                >
                  <a-space>
                    <a-tag
                      v-for="userId in rule.user_ids"
                      :key="userId"
                    >
                      {{ getUserNameById(userId) }} (ID: {{ userId }})
                    </a-tag>
                  </a-space>
                </a-descriptions-item>
              </a-descriptions>
            </a-card>
          </div>
          <a-empty v-else description="暂无规则" />
        </div>
      </a-space>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue'
import { usePermission } from '@/composables/usePermission'

const { canCreate, canEdit } = usePermission()
import {
  hooksApi,
  type Hook,
  type HookRule,
  type CreateHookRequest,
  type UpdateHookRequest,
  type SyncStatus,
  HookPoint,
  PolicyAction,
  HookType,
} from '@/api/hooks'
import { usersApi, type User } from '@/api/users'
import { Message, Modal } from '@arco-design/web-vue'
import {
  IconPlus,
  IconCode,
  IconCheck,
  IconClose,
  IconRefresh,
} from '@arco-design/web-vue/es/icon'

const loading = ref(false)
const submitLoading = ref(false)
const syncLoading = ref(false)
const hooks = ref<Hook[]>([])
const modalVisible = ref(false)
const rulesModalVisible = ref(false)
const viewRulesModalVisible = ref(false)
const isEdit = ref(false)
const currentHook = ref<Hook | null>(null)
const currentHookPoint = ref<HookPoint>(HookPoint.PreRouting)
const toggleLoading = reactive<Record<string, boolean>>({})
const syncStatus = ref<SyncStatus | null>(null)
const showSyncActions = computed(() => !!(syncStatus.value && syncStatus.value.running))
const users = ref<User[]>([])
const usersLoading = ref(false)

interface HookPointInfo {
  label: string
  value: HookPoint
  description: string
  scenarios: string[]
}

const hookPoints: HookPointInfo[] = [
  { 
    label: 'PRE_ROUTING', 
    value: HookPoint.PreRouting,
    description: '路由前 - 所有进入的流量（客户端→服务器、客户端→客户端、外部→VPN）',
    scenarios: [
      'VPN客户端访问外部网络',
      '外部访问VPN客户端',
      'VPN客户端之间通信',
      'VPN客户端访问VPN服务器'
    ]
  },
  { 
    label: 'INPUT', 
    value: HookPoint.Input,
    description: '输入到本地系统 - VPN客户端访问VPN服务器',
    scenarios: [
      'VPN客户端 ping VPN服务器（10.8.0.1）',
      'VPN客户端访问VPN服务器上的服务',
      'VPN客户端访问VPN服务器的管理接口'
    ]
  },
  { 
    label: 'FORWARD', 
    value: HookPoint.Forward,
    description: '转发流量 - VPN客户端之间的通信',
    scenarios: [
      'VPN客户端A ping VPN客户端B',
      'VPN客户端A访问VPN客户端B的服务',
      'VPN客户端之间的数据转发'
    ]
  },
  { 
    label: 'OUTPUT', 
    value: HookPoint.Output,
    description: '本地系统输出 - VPN服务器发出的流量',
    scenarios: [
      'VPN服务器主动访问VPN客户端',
      'VPN服务器访问外部网络',
      'VPN服务器响应客户端请求'
    ]
  },
  { 
    label: 'POST_ROUTING', 
    value: HookPoint.PostRouting,
    description: '路由后 - VPN客户端访问外部网络的出站流量',
    scenarios: [
      'VPN客户端访问互联网',
      'VPN客户端访问外部服务器',
      'VPN客户端出站流量（NAT后）'
    ]
  },
]

const hookTypes = [
  { label: 'ACL 策略', value: HookType.ACL },
  { label: '端口过滤', value: HookType.PortFilter },
  { label: '用户策略', value: HookType.UserPolicy },
  // 注意：TimeRestriction 和 Custom 类型暂未实现，如需使用请通过API直接创建
]

const formData = reactive<CreateHookRequest & UpdateHookRequest & { rules: any[] }>({
  name: '',
  hook_point: HookPoint.PreRouting,
  priority: 10,
  type: HookType.ACL,
  description: '',
  rules: [],
  enabled: true,
})

const columns = [
  {
    title: 'Hook 名称',
    slotName: 'name',
    width: 200,
    align: 'center',
  },
  {
    title: '类型',
    slotName: 'type',
    width: 120,
    align: 'center',
  },
  {
    title: '优先级',
    slotName: 'priority',
    width: 100,
    align: 'center',
  },
  {
    title: '规则数',
    dataIndex: 'rules',
    width: 100,
    align: 'center',
    render: ({ record }: any) => record.rules?.length || 0,
  },
  {
    title: '统计',
    slotName: 'stats',
    width: 150,
    align: 'center',
  },
  {
    title: '状态',
    slotName: 'enabled',
    width: 100,
    align: 'center',
  },
  {
    title: '操作',
    slotName: 'actions',
    width: 200,
    align: 'center',
  },
]

const filteredHooks = computed(() => {
  return hooks.value.filter((hook) => hook.hook_point === currentHookPoint.value)
})

const getTypeColor = (type: HookType) => {
  const colors: Partial<Record<HookType, string>> = {
    [HookType.ACL]: 'blue',
    [HookType.PortFilter]: 'green',
    [HookType.UserPolicy]: 'purple',
    [HookType.TimeRestriction]: 'orange',
    [HookType.Custom]: 'gray',
  }
  return colors[type] || 'gray'
}

const getTypeLabel = (type: HookType) => {
  const labels: Partial<Record<HookType, string>> = {
    [HookType.ACL]: 'ACL',
    [HookType.PortFilter]: '端口过滤',
    [HookType.UserPolicy]: '用户策略',
    [HookType.TimeRestriction]: '时间限制',
    [HookType.Custom]: '自定义',
  }
  return labels[type] || type
}

const getHookPointLabel = (point: HookPoint) => {
  const hook = hookPoints.find((h) => h.value === point)
  return hook?.label || ''
}

const getCurrentHookPoint = () => {
  return hookPoints.find((h) => h.value === formData.hook_point)
}

const getCurrentHookScenarios = () => {
  const hook = getCurrentHookPoint()
  return hook?.scenarios || []
}

const getActionColor = (action: PolicyAction) => {
  const colors: Partial<Record<PolicyAction, string>> = {
    [PolicyAction.Allow]: 'green',
    [PolicyAction.Deny]: 'red',
    [PolicyAction.Redirect]: 'orange',
    [PolicyAction.Log]: 'blue',
  }
  return colors[action] || 'gray'
}

const getActionLabel = (action: PolicyAction) => {
  const labels: Partial<Record<PolicyAction, string>> = {
    [PolicyAction.Allow]: '允许',
    [PolicyAction.Deny]: '拒绝',
    [PolicyAction.Redirect]: '重定向',
    [PolicyAction.Log]: '记录',
  }
  return labels[action] || ''
}

const fetchHooks = async () => {
  loading.value = true
  try {
    const data = await hooksApi.list()
    hooks.value = data
  } catch (error) {
    Message.error('获取 Hook 列表失败')
  } finally {
    loading.value = false
  }
}

const fetchSyncStatus = async () => {
  try {
    const status = await hooksApi.getSyncStatus()
    syncStatus.value = status
  } catch (error) {
    console.error('获取同步状态失败:', error)
  }
}

const handleForceSync = async () => {
  syncLoading.value = true
  try {
    const result = await hooksApi.forceSync()
    Message.success(result.message || '同步已触发')
    // 立即刷新状态和列表（同步是同步执行的，完成后立即刷新）
    await Promise.all([fetchSyncStatus(), fetchHooks()])
  } catch (error: any) {
    Message.error(error.response?.data?.error || '同步失败')
  } finally {
    syncLoading.value = false
  }
}

const formatTime = (timeStr: string) => {
  if (!timeStr) return '-'
  try {
    const date = new Date(timeStr)
    return date.toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  } catch {
    return timeStr
  }
}

const handleTabChange = (key: string) => {
  currentHookPoint.value = Number(key) as HookPoint
}

const showCreateModal = () => {
  isEdit.value = false
  currentHook.value = null
  resetForm()
  modalVisible.value = true
}

const handleEdit = (record: Hook) => {
  isEdit.value = true
  currentHook.value = record
  formData.name = record.name
  formData.hook_point = record.hook_point
  formData.priority = record.priority
  formData.type = record.type
  formData.description = record.description || ''
  formData.rules = record.rules.map(parseRule)
  modalVisible.value = true
}

const handleViewRules = (record: Hook) => {
  currentHook.value = record
  viewRulesModalVisible.value = true
}

const handleDelete = (record: Hook) => {
  Modal.confirm({
    title: '确认删除',
    content: `确定要删除 Hook "${record.name}" 吗？`,
    onOk: async () => {
      try {
        await hooksApi.delete(record.id)
        Message.success('删除成功')
        fetchHooks()
      } catch (error) {
        Message.error('删除失败')
      }
    },
  })
}

const handleToggle = async (record: Hook) => {
  toggleLoading[record.id] = true
  try {
    await hooksApi.toggle(record.id, record.enabled)
    Message.success(record.enabled ? '已启用' : '已禁用')
    fetchHooks()
  } catch (error) {
    record.enabled = !record.enabled
    Message.error('操作失败')
  } finally {
    toggleLoading[record.id] = false
  }
}

const handleSubmit = async () => {
  if (!formData.name || formData.priority === undefined) {
    Message.warning('请填写必填项')
    return
  }

  submitLoading.value = true
  try {
    const rules = formData.rules.map(formatRule)
    
    if (isEdit.value && currentHook.value) {
      await hooksApi.update(currentHook.value.id, {
        name: formData.name,
        priority: formData.priority,
        description: formData.description,
        rules,
        enabled: formData.enabled,
      })
      Message.success('更新成功')
    } else {
      await hooksApi.create({
        name: formData.name,
        hook_point: formData.hook_point,
        priority: formData.priority,
        type: formData.type,
        description: formData.description,
        rules,
        enabled: formData.enabled,
      })
      Message.success('创建成功')
    }
    modalVisible.value = false
    fetchHooks()
    fetchSyncStatus()
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
  formData.hook_point = HookPoint.PreRouting
  formData.priority = 10
  formData.type = HookType.ACL
  formData.description = ''
  formData.rules = []
  formData.enabled = true
}

const showRulesEditor = () => {
  rulesModalVisible.value = true
}

const addRule = () => {
  formData.rules.push({
    action: PolicyAction.Allow,
    source_ips_text: '',
    destination_ips_text: '',
    source_networks_text: '',
    destination_networks_text: '',
    source_ports_text: '',
    destination_ports_text: '',
    selected_user_ids: [],
    protocols: [],
  })
}

const deleteRule = (index: number) => {
  formData.rules.splice(index, 1)
}

const parseRule = (rule: HookRule) => {
  // 合并单个端口和端口范围
  const formatPorts = (ports?: number[], ranges?: Array<{ start: number, end: number }>): string => {
    const parts: string[] = []
    if (ports && ports.length > 0) {
      parts.push(...ports.map(p => p.toString()))
    }
    if (ranges && ranges.length > 0) {
      parts.push(...ranges.map(r => `${r.start}-${r.end}`))
    }
    return parts.join(',')
  }
  
  // 注意：后端port_ranges不区分源端口和目标端口范围
  // 为了简化，我们将port_ranges同时显示在源端口和目标端口字段中
  // 用户可以根据需要手动调整
  const portRanges = rule.port_ranges || []
  
  return {
    ...rule,
    source_ips_text: rule.source_ips?.join(',') || '',
    destination_ips_text: rule.destination_ips?.join(',') || '',
    source_networks_text: rule.source_networks?.join(',') || '',
    destination_networks_text: rule.destination_networks?.join(',') || '',
    source_ports_text: formatPorts(rule.source_ports, portRanges),
    destination_ports_text: formatPorts(rule.destination_ports, portRanges),
    selected_user_ids: rule.user_ids || [],
  }
}

const formatRule = (rule: any): HookRule => {
  const formatted: HookRule = {
    action: rule.action,
  }

  // 根据hook类型，只包含相关字段
  if (formData.type === HookType.ACL) {
    // ACL类型：只包含IP和网段
    if (rule.source_ips_text) {
      formatted.source_ips = rule.source_ips_text.split(',').filter(Boolean) || undefined
    }
    if (rule.destination_ips_text) {
      formatted.destination_ips = rule.destination_ips_text.split(',').filter(Boolean) || undefined
    }
    if (rule.source_networks_text) {
      formatted.source_networks = rule.source_networks_text.split(',').filter(Boolean) || undefined
    }
    if (rule.destination_networks_text) {
      formatted.destination_networks = rule.destination_networks_text.split(',').filter(Boolean) || undefined
    }
    if (rule.protocols?.length) {
      formatted.protocols = rule.protocols
    }
  } else if (formData.type === HookType.PortFilter) {
    // 端口过滤类型：只包含端口
    // 解析端口：支持单个端口（80）和范围（8000-9000）
    const parsePorts = (text: string): { ports: number[], ranges: Array<{ start: number, end: number }> } => {
      const ports: number[] = []
      const ranges: Array<{ start: number, end: number }> = []
      
      if (!text) return { ports, ranges }
      
      const parts = text.split(',').map(s => s.trim()).filter(Boolean)
      for (const part of parts) {
        if (part.includes('-')) {
          // 端口范围：8000-9000
          const [startStr, endStr] = part.split('-').map(s => s.trim())
          const start = parseInt(startStr || '0', 10)
          const end = parseInt(endStr || '0', 10)
          if (!isNaN(start) && !isNaN(end) && start > 0 && end > 0 && start <= end && start <= 65535 && end <= 65535) {
            ranges.push({ start, end })
          }
        } else {
          // 单个端口
          const port = parseInt(part, 10)
          if (!isNaN(port) && port > 0 && port <= 65535) {
            ports.push(port)
          }
        }
      }
      return { ports, ranges }
    }
    
    // 收集所有端口范围（后端port_ranges不区分源和目标）
    const allRanges: Array<{ start: number, end: number }> = []
    
    if (rule.source_ports_text) {
      const parsed = parsePorts(rule.source_ports_text)
      if (parsed.ports.length > 0) {
        formatted.source_ports = parsed.ports
      }
      if (parsed.ranges.length > 0) {
        allRanges.push(...parsed.ranges)
      }
    }
    if (rule.destination_ports_text) {
      const parsed = parsePorts(rule.destination_ports_text)
      if (parsed.ports.length > 0) {
        formatted.destination_ports = parsed.ports
      }
      if (parsed.ranges.length > 0) {
        allRanges.push(...parsed.ranges)
      }
    }
    
    // 合并所有端口范围
    if (allRanges.length > 0) {
      formatted.port_ranges = allRanges
    }
    
    if (rule.protocols?.length) {
      formatted.protocols = rule.protocols
    }
  } else if (formData.type === HookType.UserPolicy) {
    // 用户策略类型：只包含用户ID（从下拉框的选择值获取）
    if (rule.selected_user_ids && rule.selected_user_ids.length > 0) {
      formatted.user_ids = rule.selected_user_ids
    }
  }

  return formatted
}

const fetchUsers = async () => {
  usersLoading.value = true
  try {
    const data = await usersApi.list()
    users.value = data.filter(u => u.is_active) // 只显示活跃用户
  } catch (error) {
    Message.error('获取用户列表失败')
  } finally {
    usersLoading.value = false
  }
}

const filterUserOption = (inputValue: string, option: any) => {
  const user = users.value.find(u => u.id === option.value)
  if (!user) return false
  return user.username.toLowerCase().includes(inputValue.toLowerCase()) ||
         user.id.toString().includes(inputValue)
}

const getUserNameById = (userId: number) => {
  const user = users.value.find(u => u.id === userId)
  return user ? user.username : `用户 ${userId}`
}

onMounted(() => {
  fetchHooks()
  fetchSyncStatus()
  fetchUsers() // 加载用户列表
  // 定期刷新同步状态
  const statusInterval = setInterval(() => {
    fetchSyncStatus()
  }, 10000) // 每10秒刷新一次
  
  // 组件卸载时清除定时器
  onUnmounted(() => {
    clearInterval(statusInterval)
  })
})
</script>

<style scoped lang="less">
.hooks-page {
  padding: 20px;
  background: #f7f8fa;
  min-height: calc(100vh - 64px - 48px);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  width: 100%;
  margin-bottom: 0;
  
  > div:first-child {
    flex: 1;
  }
  
  h3 {
    margin: 0;
    margin-bottom: 8px;
    font-size: 18px;
    font-weight: 600;
    color: var(--color-text-1);
  }
  
  .sync-status {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-top: 4px;
    font-size: 12px;
    color: var(--color-text-2);
    flex-wrap: wrap;
    
    .sync-info {
      font-size: 12px;
      color: var(--color-text-3);
    }
  }
}

.card-header p {
  margin: 4px 0 0;
  font-size: 13px;
  color: var(--color-text-3);
}

.content-wrapper {
  margin-top: 24px;
}

.hook-name {
  font-weight: 500;
}

.stats-info {
  font-size: 12px;
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

:deep(.arco-collapse-item-header) {
  font-weight: 500;
}

// Hook Tab 标题样式
.hook-tab-title {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 2px;
  
  .hook-tab-name {
    font-weight: 500;
    font-size: 14px;
  }
  
  .hook-tab-desc {
    font-size: 11px;
    color: var(--color-text-3);
    line-height: 1.2;
    max-width: 200px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
}

// Hook 下拉选项样式
:deep(.arco-select-option) {
  padding: 8px 12px;
  
  .hook-option {
    display: flex;
    flex-direction: column;
    gap: 4px;
    
    .hook-option-name {
      font-weight: 500;
      font-size: 14px;
      color: var(--color-text-1);
    }
    
    .hook-option-desc {
      font-size: 12px;
      color: var(--color-text-3);
      line-height: 1.4;
    }
  }
}

// Hook 场景说明样式
.hook-scenarios-title {
  font-weight: 500;
  margin-bottom: 8px;
  color: var(--color-text-1);
}

.hook-scenarios-list {
  margin: 0;
  padding-left: 20px;
  color: var(--color-text-2);
  
  li {
    margin-bottom: 4px;
    line-height: 1.6;
    font-size: 13px;
    
    &:last-child {
      margin-bottom: 0;
    }
  }
}

// Tooltip 内容样式
.hook-tooltip-content {
  text-align: left;
  
  .tooltip-desc {
    margin-bottom: 12px;
    color: var(--color-text-1);
    font-size: 13px;
    line-height: 1.6;
  }
  
  .tooltip-scenarios {
    .tooltip-scenarios-title {
      font-weight: 500;
      margin-bottom: 8px;
      color: var(--color-text-1);
      font-size: 13px;
    }
    
    .tooltip-scenarios-list {
      margin: 0;
      padding-left: 20px;
      color: var(--color-text-2);
      font-size: 12px;
      line-height: 1.8;
      
      li {
        margin-bottom: 4px;
        
        &:last-child {
          margin-bottom: 0;
        }
      }
    }
  }
}

// Tooltip 全局样式覆盖，确保背景色和箭头颜色匹配整体风格
:deep(.arco-tooltip-content) {
  background-color: var(--color-bg-popup) !important;
  color: var(--color-text-1) !important;
  border: 1px solid var(--color-border-2) !important;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15) !important;
}

:deep(.arco-tooltip-arrow) {
  background-color: var(--color-bg-popup) !important;
  border-color: var(--color-border-2) !important;
}
</style>


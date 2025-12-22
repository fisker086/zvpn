<template>
  <div class="audit-logs-page">
    <a-card :bordered="false">
      <template #title>
        <div class="card-header">
          <h3>审计日志</h3>
          <a-space>
            <a-input-search
              v-model="searchKeyword"
              placeholder="搜索用户、IP地址、域名..."
              style="width: 300px"
              @search="handleSearch"
              @clear="handleSearch"
              allow-clear
            />
            <a-button @click="handleRefresh" :loading="loading">
              <template #icon>
                <icon-refresh />
              </template>
              刷新
            </a-button>
          </a-space>
        </div>
      </template>

      <!-- 快速筛选 -->
      <div class="quick-filters">
        <a-space>
          <span>用户:</span>
          <a-select
            v-model="filterUserId"
            placeholder="全部用户"
            style="width: 180px"
            allow-clear
            allow-search
            :loading="usersLoading"
            :filter-option="filterUserOption"
            @change="handleFilterChange"
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

          <span>类型:</span>
          <a-select
            v-model="filterType"
            placeholder="全部"
            style="width: 120px"
            allow-clear
            @change="handleFilterChange"
          >
            <a-option
              v-for="type in logTypes"
              :key="type.value"
              :value="type.value"
            >
              {{ type.label }}
            </a-option>
          </a-select>

          <span>结果:</span>
          <a-select
            v-model="filterResult"
            placeholder="全部"
            style="width: 120px"
            allow-clear
            @change="handleFilterChange"
          >
            <a-option value="allowed">允许</a-option>
            <a-option value="blocked">阻止</a-option>
            <a-option value="success">成功</a-option>
            <a-option value="failed">失败</a-option>
          </a-select>

          <span>时间:</span>
          <a-range-picker
            v-model="dateRange"
            style="width: 240px"
            @change="handleFilterChange"
          />
        </a-space>
      </div>

      <a-table
        :columns="columns"
        :data="logs"
        :loading="loading"
        :pagination="pagination"
        @page-change="handlePageChange"
        @page-size-change="handlePageSizeChange"
        :scroll="{ x: 1400 }"
      >
        <template #time="{ record }">
          {{ formatTime(record.created_at) }}
        </template>

        <template #type="{ record }">
          <a-tag :color="getTypeColor(record.type)" size="small">
            {{ getTypeLabel(record.type) }}
          </a-tag>
        </template>

        <template #action="{ record }">
          <a-tag :color="getActionColor(record.action)" size="small">
            {{ getActionLabel(record.action) }}
          </a-tag>
        </template>

        <template #user="{ record }">
          {{ record.username || `用户${record.user_id}` }}
        </template>

        <template #network="{ record }">
          <div class="network-info">
            <!-- 优先显示资源路径（访问的目标对象） -->
            <div v-if="record.resource_path" class="target-object">
              <a-tag v-if="record.resource_type === 'url'" color="green" size="small">
                <icon-link style="margin-right: 4px;" />
                {{ record.resource_path }}
              </a-tag>
              <a-tag v-else-if="record.resource_type === 'domain'" color="blue" size="small">
                <icon-computer style="margin-right: 4px;" />
                {{ record.resource_path }}
              </a-tag>
              <span v-else class="target-text">{{ record.resource_path }}</span>
            </div>
            <!-- 如果没有资源路径，显示域名 -->
            <div v-else-if="record.domain" class="domain-info">
              <a-tag color="blue" size="small">{{ record.domain }}</a-tag>
            </div>
            <!-- 显示源地址和目标地址 -->
            <div v-if="record.source_ip" class="source-info">
              <span class="text-secondary">从</span> {{ record.source_ip }}<span v-if="record.source_port">:{{ record.source_port }}</span>
            </div>
            <div v-if="record.destination_ip && (!record.resource_path || record.resource_path === record.destination_ip)" class="destination-info">
              <span class="text-secondary">→</span> {{ record.destination_ip }}<span v-if="record.destination_port">:{{ record.destination_port }}</span>
            </div>
            <span v-if="!record.resource_path && !record.domain && !record.source_ip && !record.destination_ip" class="text-secondary">
              -
            </span>
          </div>
        </template>

        <template #protocol="{ record }">
          <a-tag v-if="record.protocol && record.protocol.trim()" :color="getProtocolColor(record.protocol)" size="small">
            {{ getProtocolLabel(record.protocol) }}
          </a-tag>
          <span v-else class="text-secondary">-</span>
        </template>

        <template #result="{ record }">
          <a-tag :color="getResultColor(record.result)" size="small">
            {{ getResultLabel(record.result) }}
          </a-tag>
        </template>

        <template #operations="{ record }">
          <a-button type="text" size="small" @click="handleViewDetail(record)">
            详情
          </a-button>
        </template>
      </a-table>
    </a-card>

    <!-- 详情抽屉 -->
    <a-drawer
      v-model:visible="detailVisible"
      title="日志详情"
      :width="600"
    >
      <a-descriptions :column="1" bordered v-if="currentLog">
        <a-descriptions-item label="时间">
          {{ formatTime(currentLog.created_at) }}
        </a-descriptions-item>
        <a-descriptions-item label="用户">
          {{ currentLog.username || `用户 ${currentLog.user_id}` }}
        </a-descriptions-item>
        <a-descriptions-item label="类型">
          <a-tag :color="getTypeColor(currentLog.type)">
            {{ getTypeLabel(currentLog.type) }}
          </a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="动作">
          <a-tag :color="getActionColor(currentLog.action)">
            {{ getActionLabel(currentLog.action) }}
          </a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="结果">
          <a-tag :color="getResultColor(currentLog.result)">
            {{ getResultLabel(currentLog.result) }}
          </a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="源地址">
          {{ currentLog.source_ip || '-' }}
          <span v-if="currentLog.source_port">:{{ currentLog.source_port }}</span>
        </a-descriptions-item>
        <a-descriptions-item label="访问目标" v-if="currentLog.resource_path || currentLog.domain || currentLog.destination_ip">
          <div style="display: flex; flex-direction: column; gap: 8px;">
            <!-- 优先显示资源路径（访问的目标对象） -->
            <div v-if="currentLog.resource_path">
              <a-tag v-if="currentLog.resource_type === 'url'" color="green" size="small">
                <icon-link style="margin-right: 4px;" />
                {{ currentLog.resource_path }}
              </a-tag>
              <a-tag v-else-if="currentLog.resource_type === 'domain'" color="blue" size="small">
                <icon-computer style="margin-right: 4px;" />
                {{ currentLog.resource_path }}
              </a-tag>
              <span v-else style="font-weight: 500; color: var(--color-text-1);">{{ currentLog.resource_path }}</span>
            </div>
            <!-- 显示域名 -->
            <div v-if="currentLog.domain && currentLog.resource_path !== currentLog.domain">
              <a-tag color="blue" size="small">域名: {{ currentLog.domain }}</a-tag>
            </div>
            <!-- 显示目标IP和端口 -->
            <div v-if="currentLog.destination_ip" style="color: var(--color-text-2); font-size: 13px;">
              目标IP: {{ currentLog.destination_ip }}<span v-if="currentLog.destination_port">:{{ currentLog.destination_port }}</span>
            </div>
          </div>
        </a-descriptions-item>
        <a-descriptions-item label="源地址" v-if="currentLog.source_ip">
          {{ currentLog.source_ip }}<span v-if="currentLog.source_port">:{{ currentLog.source_port }}</span>
        </a-descriptions-item>
        <a-descriptions-item label="协议">
          <a-tag v-if="currentLog.protocol && currentLog.protocol.trim()" :color="getProtocolColor(currentLog.protocol)" size="small">
            {{ getProtocolLabel(currentLog.protocol) }}
          </a-tag>
          <span v-else>-</span>
        </a-descriptions-item>
        <a-descriptions-item label="资源类型" v-if="currentLog.resource_type">
          <a-tag :color="getResourceTypeColor(currentLog.resource_type)" size="small">
            {{ getResourceTypeLabel(currentLog.resource_type) }}
          </a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="Hook" v-if="currentLog.hook_name">
          {{ currentLog.hook_name }}
        </a-descriptions-item>
        <a-descriptions-item label="策略" v-if="currentLog.policy_name">
          {{ currentLog.policy_name }} (ID: {{ currentLog.policy_id }})
        </a-descriptions-item>
        <a-descriptions-item label="原因" v-if="currentLog.reason">
          {{ currentLog.reason }}
        </a-descriptions-item>
        <a-descriptions-item label="元数据" v-if="currentLog.metadata && Object.keys(currentLog.metadata).length > 0">
          <pre style="font-size: 12px; max-height: 200px; overflow: auto;">{{ JSON.stringify(currentLog.metadata, null, 2) }}</pre>
        </a-descriptions-item>
      </a-descriptions>
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import {
  auditLogsApi,
  type AuditLog,
  type AuditLogQuery,
  AuditLogType,
  AuditLogAction,
} from '@/api/audit-logs'
import { usersApi, type User } from '@/api/users'
import { Message } from '@arco-design/web-vue'
import { IconRefresh, IconLink, IconComputer } from '@arco-design/web-vue/es/icon'
import { formatDateTime } from '@/utils/formatters'

const loading = ref(false)
const logs = ref<AuditLog[]>([])
const detailVisible = ref(false)
const currentLog = ref<AuditLog | null>(null)
const searchKeyword = ref('')
const filterUserId = ref<number | undefined>()
const filterType = ref<string | undefined>()
const filterResult = ref<string | undefined>()
const dateRange = ref<[any, any] | null>(null)
const users = ref<User[]>([])
const usersLoading = ref(false)

const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showTotal: true,
  showPageSize: true,
})

const logTypes = [
  { label: '访问', value: AuditLogType.Access },
  { label: '策略', value: AuditLogType.Policy },
  { label: '认证', value: AuditLogType.Auth },
  { label: '配置', value: AuditLogType.Config },
  { label: 'Hook', value: AuditLogType.Hook },
]

const columns = [
  { 
    title: '时间', 
    slotName: 'time', 
    width: 160,
    fixed: 'left',
    align: 'center',
  },
  { 
    title: '类型', 
    slotName: 'type', 
    width: 100,
    align: 'center',
  },
  { 
    title: '动作', 
    slotName: 'action', 
    width: 100,
    align: 'center',
  },
  { 
    title: '用户', 
    slotName: 'user', 
    width: 120,
    align: 'center',
  },
  { 
    title: '网络信息', 
    slotName: 'network', 
    width: 320,
    align: 'center',
  },
  { 
    title: '协议', 
    slotName: 'protocol', 
    width: 80,
    align: 'center',
  },
  { 
    title: '结果', 
    slotName: 'result', 
    width: 100,
    align: 'center',
  },
  { 
    title: '操作', 
    slotName: 'operations', 
    width: 80,
    fixed: 'right',
    align: 'center',
  },
]

const buildQuery = (): AuditLogQuery => {
  const query: AuditLogQuery = {
    page: pagination.current,
    page_size: pagination.pageSize,
  }

  // 用户筛选（优先使用下拉选择）
  if (filterUserId.value) {
    query.user_id = filterUserId.value
  }

  if (filterType.value) {
    query.type = filterType.value as any
  }
  if (filterResult.value) {
    query.result = filterResult.value
  }
  if (dateRange.value && dateRange.value[0] && dateRange.value[1]) {
    query.start_time = formatDateForAPI(dateRange.value[0])
    query.end_time = formatDateForAPI(dateRange.value[1])
  }
  if (searchKeyword.value) {
    // 简单搜索：尝试匹配IP、域名或用户名
    // 如果没有选择用户，才使用搜索框的用户名搜索
    if (!filterUserId.value) {
      if (/^\d+\.\d+\.\d+\.\d+$/.test(searchKeyword.value)) {
        query.source_ip = searchKeyword.value
      } else if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(searchKeyword.value)) {
        // 可能是域名
        query.domain = searchKeyword.value
      } else {
        query.username = searchKeyword.value
      }
    } else {
      // 如果已选择用户，搜索框只用于IP或域名搜索
      if (/^\d+\.\d+\.\d+\.\d+$/.test(searchKeyword.value)) {
        query.source_ip = searchKeyword.value
      } else if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(searchKeyword.value)) {
        query.domain = searchKeyword.value
      }
    }
  }

  return query
}

const formatDateForAPI = (date: any) => {
  if (!date) return undefined
  if (date && typeof date.format === 'function') {
    return date.format('YYYY-MM-DDTHH:mm:ss') + 'Z'
  }
  if (date instanceof Date) {
    return date.toISOString()
  }
  return String(date)
}

const fetchLogs = async () => {
  loading.value = true
  try {
    const query = buildQuery()
    const response = await auditLogsApi.list(query)
    logs.value = response.data
    pagination.total = response.total
  } catch (error) {
    Message.error('获取审计日志失败')
  } finally {
    loading.value = false
  }
}

const handleRefresh = () => {
  pagination.current = 1
  fetchLogs()
}

const handleSearch = () => {
  pagination.current = 1
  fetchLogs()
}

const handleFilterChange = () => {
  pagination.current = 1
  fetchLogs()
}

const handlePageChange = (page: number) => {
  pagination.current = page
  fetchLogs()
}

const handlePageSizeChange = (pageSize: number) => {
  pagination.pageSize = pageSize
  pagination.current = 1
  fetchLogs()
}

const handleViewDetail = (log: AuditLog) => {
  currentLog.value = log
  detailVisible.value = true
}

// 使用工具函数格式化时间
const formatTime = formatDateTime

const getTypeColor = (type: string) => {
  const colors: Record<string, string> = {
    [AuditLogType.Access]: 'blue',
    [AuditLogType.Policy]: 'green',
    [AuditLogType.Auth]: 'orange',
    [AuditLogType.Config]: 'purple',
    [AuditLogType.Hook]: 'cyan',
  }
  return colors[type] || 'gray'
}

const getTypeLabel = (type: string) => {
  const typeObj = logTypes.find(t => t.value === type)
  return typeObj?.label || type
}

const getActionColor = (action: string) => {
  const colors: Record<string, string> = {
    [AuditLogAction.Allow]: 'green',
    [AuditLogAction.Deny]: 'red',
    [AuditLogAction.Log]: 'blue',
    [AuditLogAction.Connect]: 'cyan',
    [AuditLogAction.Disconnect]: 'orange',
    [AuditLogAction.Login]: 'green',
    [AuditLogAction.Logout]: 'gray',
  }
  return colors[action] || 'gray'
}

const getActionLabel = (action: string) => {
  const labels: Record<string, string> = {
    [AuditLogAction.Allow]: '允许',
    [AuditLogAction.Deny]: '拒绝',
    [AuditLogAction.Log]: '记录',
    [AuditLogAction.Connect]: '连接',
    [AuditLogAction.Disconnect]: '断开',
    [AuditLogAction.Login]: '登录',
    [AuditLogAction.Logout]: '登出',
  }
  return labels[action] || action
}

const getResultColor = (result: string) => {
  const colors: Record<string, string> = {
    allowed: 'green',
    blocked: 'red',
    success: 'green',
    failed: 'red',
  }
  return colors[result] || 'gray'
}

const getResultLabel = (result: string) => {
  const labels: Record<string, string> = {
    allowed: '允许',
    blocked: '阻止',
    success: '成功',
    failed: '失败',
  }
  return labels[result] || result
}

const getResourceTypeColor = (type: string) => {
  const colors: Record<string, string> = {
    url: 'green',
    domain: 'blue',
    network: 'gray',
    ip: 'orange',
  }
  return colors[type] || 'gray'
}

const getResourceTypeLabel = (type: string) => {
  const labels: Record<string, string> = {
    url: 'URL',
    domain: '域名',
    network: '网络',
    ip: 'IP地址',
  }
  return labels[type] || type
}

const getProtocolColor = (protocol: string) => {
  const protocolLower = protocol.toLowerCase()
  const colors: Record<string, string> = {
    // Web协议
    http: 'blue',
    https: 'green',
    'http-alt': 'cyan',
    'https-alt': 'green',
    // 数据库协议
    mysql: 'orange',
    postgresql: 'purple',
    redis: 'red',
    mongodb: 'green',
    mssql: 'blue',
    oracle: 'red',
    cassandra: 'purple',
    elasticsearch: 'orange',
    couchdb: 'cyan',
    // 远程访问协议
    ssh: 'blue',
    rdp: 'purple',
    vnc: 'orange',
    telnet: 'gray',
    // 邮件协议
    smtp: 'blue',
    imap: 'cyan',
    imaps: 'green',
    pop3: 'orange',
    pop3s: 'green',
    // 目录服务
    ldap: 'blue',
    ldaps: 'green',
    // 消息队列
    amqp: 'purple',
    mqtt: 'orange',
    kafka: 'red',
    // 其他
    ftp: 'blue',
    ftps: 'green',
    dns: 'cyan',
    tcp: 'gray',
    udp: 'gray',
    icmp: 'gray',
  }
  return colors[protocolLower] || 'gray'
}

const getProtocolLabel = (protocol: string) => {
  const protocolLower = protocol.toLowerCase()
  const labels: Record<string, string> = {
    // Web协议
    http: 'HTTP',
    https: 'HTTPS',
    'http-alt': 'HTTP',
    'https-alt': 'HTTPS',
    // 数据库协议
    mysql: 'MySQL',
    postgresql: 'PostgreSQL',
    redis: 'Redis',
    mongodb: 'MongoDB',
    mssql: 'SQL Server',
    oracle: 'Oracle',
    cassandra: 'Cassandra',
    elasticsearch: 'Elasticsearch',
    couchdb: 'CouchDB',
    // 远程访问协议
    ssh: 'SSH',
    rdp: 'RDP',
    vnc: 'VNC',
    telnet: 'Telnet',
    // 邮件协议
    smtp: 'SMTP',
    imap: 'IMAP',
    imaps: 'IMAPS',
    pop3: 'POP3',
    pop3s: 'POP3S',
    // 目录服务
    ldap: 'LDAP',
    ldaps: 'LDAPS',
    // 消息队列
    amqp: 'AMQP',
    mqtt: 'MQTT',
    kafka: 'Kafka',
    // 其他
    ftp: 'FTP',
    ftps: 'FTPS',
    dns: 'DNS',
    tcp: 'TCP',
    udp: 'UDP',
    icmp: 'ICMP',
  }
  return labels[protocolLower] || protocol.toUpperCase()
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

const filterUserOption = (inputValue: string, option: any) => {
  const user = users.value.find(u => u.id === option.value)
  if (!user) return false
  return user.username.toLowerCase().includes(inputValue.toLowerCase()) ||
         user.id.toString().includes(inputValue)
}

onMounted(() => {
  fetchLogs()
  fetchUsers()
})
</script>

<style scoped lang="less">
.audit-logs-page {
  padding: 20px;
  background: #f7f8fa;
  min-height: calc(100vh - 64px - 48px);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;

  h3 {
    margin: 0;
    font-size: 18px;
    font-weight: 600;
    color: var(--color-text-1);
  }
}

.quick-filters {
  margin-bottom: 16px;
  padding: 12px;
  background: #fafafa;
  border-radius: 4px;

  span {
    color: var(--color-text-2);
    font-size: 14px;
  }
}

.network-info {
  font-size: 13px;
  line-height: 1.6;

  .text-secondary {
    color: var(--color-text-3);
    font-size: 12px;
  }

  .target-object {
    margin-bottom: 4px;
    
    .target-text {
      font-weight: 500;
      color: var(--color-text-1);
    }
  }

  .domain-info {
    margin-bottom: 4px;
  }

  .source-info,
  .destination-info {
    font-size: 12px;
    color: var(--color-text-2);
    margin-top: 2px;
  }
}

:deep(.arco-card) {
  border-radius: 4px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
}

:deep(.arco-table-th) {
  background: #fafafa;
}
</style>

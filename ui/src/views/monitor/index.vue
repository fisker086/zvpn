<template>
  <div class="monitor-page">
    <a-space direction="vertical" :size="20" fill>
      <!-- 统计卡片 -->
      <a-card :bordered="false">
        <a-space direction="vertical" :size="16" fill>
          <div class="stat-header">
            <div class="stat-info">
              <h3>在线用户</h3>
              <p>当前有 {{ connectedUsers.length }} 位用户在线</p>
            </div>
            <a-button type="primary" @click="refreshData">
              <template #icon>
                <icon-refresh />
              </template>
              刷新
            </a-button>
          </div>
          <a-divider :margin="0" />
        </a-space>
      </a-card>

      <!-- 用户列表 -->
      <a-card :bordered="false" title="在线用户列表">
        <a-table
          :columns="columns"
          :data="connectedUsers"
          :loading="loading"
          :pagination="pagination"
          @page-change="handlePageChange"
        >
          <template #username="{ record }">
            <a-space>
              <a-avatar :size="32">
                <icon-user />
              </a-avatar>
              <div>
                <div class="username">{{ record.full_name || record.username }}</div>
                <div class="user-id">{{ record.full_name ? record.username : `ID: ${record.id}` }}</div>
              </div>
            </a-space>
          </template>

          <template #vpn_ip="{ record }">
            <a-tag color="arcoblue">{{ record.vpn_ip }}</a-tag>
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

          <template #connected_at="{ record }">
            <span class="text-secondary">
              {{ formatDateTime(record.connected_at) }}
            </span>
          </template>

          <template #status="{}">
            <a-space>
              <a-badge status="success" />
              <span>在线</span>
            </a-space>
          </template>

          <template #user_agent="{ record }">
            <span class="text-secondary">
              {{ record.user_agent || '未知' }}
            </span>
          </template>

          <template #client_os="{ record }">
            <span class="text-secondary">
              {{ record.client_os || '未知' }}
            </span>
          </template>

          <template #client_ver="{ record }">
            <span class="text-secondary">
              {{ record.client_ver || '未知' }}
            </span>
          </template>
        </a-table>
      </a-card>
    </a-space>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import { vpnApi, type ConnectedUser } from '@/api/vpn'
import { Message } from '@arco-design/web-vue'
import { IconUser, IconRefresh } from '@arco-design/web-vue/es/icon'
import { formatDateTime } from '@/utils'

const loading = ref(false)
const connectedUsers = ref<ConnectedUser[]>([])
let refreshTimer: ReturnType<typeof setInterval> | null = null

const pagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0,
})

const columns = [
  {
    title: '用户名',
    slotName: 'username',
    width: 220,
    fixed: 'left',
    align: 'center',
  },
  {
    title: '客户端',
    slotName: 'user_agent',
    width: 280,
    align: 'center',
  },
  {
    title: '操作系统',
    slotName: 'client_os',
    width: 140,
    align: 'center',
  },
  {
    title: '客户端版本',
    slotName: 'client_ver',
    width: 140,
    align: 'center',
  },
  {
    title: 'VPN IP',
    slotName: 'vpn_ip',
    width: 150,
    align: 'center',
  },
  {
    title: '用户组',
    slotName: 'groups',
    width: 200,
    align: 'center',
  },
  {
    title: '连接时间',
    slotName: 'connected_at',
    width: 200,
    fixed: 'right',
    align: 'center',
  },
  {
    title: '状态',
    slotName: 'status',
    width: 120,
    fixed: 'right',
    align: 'center',
  },
]

const fetchData = async () => {
  loading.value = true
  try {
    const data = await vpnApi.getConnectedUsers()
    connectedUsers.value = data
    pagination.total = data.length
  } catch (error) {
    Message.error('获取在线用户失败')
  } finally {
    loading.value = false
  }
}

const refreshData = () => {
  fetchData()
  Message.success('刷新成功')
}

const handlePageChange = (page: number) => {
  pagination.current = page
}

onMounted(() => {
  fetchData()
  // 每30秒自动刷新一次
  refreshTimer = setInterval(fetchData, 30000)
})

onUnmounted(() => {
  if (refreshTimer) {
    clearInterval(refreshTimer)
  }
})
</script>

<style scoped>
.monitor-page {
  padding: 24px;
  background: #f7f8fa;
  min-height: calc(100vh - 64px - 48px);
}

.stat-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.stat-info h3 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: var(--color-text-1);
}

.stat-info p {
  margin: 4px 0 0;
  font-size: 14px;
  color: var(--color-text-3);
}

.username {
  font-weight: 500;
  color: var(--color-text-1);
}

.user-id {
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
</style>

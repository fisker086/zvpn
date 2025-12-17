<template>
  <div class="dashboard">
    <a-space direction="vertical" :size="20" fill>
      <a-row :gutter="16">
        <a-col :span="6">
          <a-card :bordered="false" hoverable class="priority-card">
            <a-statistic title="总用户数" :value="stats.total_users" :precision="0">
              <template #prefix><icon-user :style="{ color: '#00b42a' }" /></template>
            </a-statistic>
          </a-card>
        </a-col>
        <a-col :span="6">
          <a-card :bordered="false" hoverable>
            <a-statistic title="在线用户" :value="stats.connected_users" :precision="0">
              <template #prefix><icon-user-group :style="{ color: '#165dff' }" /></template>
            </a-statistic>
          </a-card>
        </a-col>
        <a-col :span="6">
          <a-card :bordered="false" hoverable>
            <a-statistic title="策略数" :value="stats.total_policies" :precision="0">
              <template #prefix><icon-settings :style="{ color: '#ff7d00' }" /></template>
            </a-statistic>
          </a-card>
        </a-col>
        <a-col :span="6">
          <a-card :bordered="false" hoverable>
            <a-statistic title="系统负载 (1m)" :value="currentMetrics.load1" :precision="2">
              <template #prefix><icon-dashboard :style="{ color: '#00b42a' }" /></template>
              <template #suffix>
                <a-tooltip content="系统负载平均值，表示1分钟内的平均负载。通常应小于CPU核心数。">
                  <span style="font-size: 14px; color: #86909c; cursor: help;">负载</span>
                </a-tooltip>
              </template>
            </a-statistic>
          </a-card>
        </a-col>
      </a-row>

      <a-row :gutter="16">
        <a-col :span="12">
          <a-card :bordered="false">
            <template #title>
              <a-space><span>系统负载</span><a-tag color="blue">1m / 5m / 15m</a-tag></a-space>
            </template>
            <div ref="loadChartRef" class="chart-container"></div>
          </a-card>
        </a-col>
        <a-col :span="12">
          <a-card :bordered="false">
            <template #title>
              <a-space><span>内存</span><a-tag color="purple">使用率</a-tag></a-space>
            </template>
            <div ref="memChartRef" class="chart-container"></div>
          </a-card>
        </a-col>
      </a-row>

      <a-row :gutter="16">
        <a-col :span="24">
          <a-card :bordered="false">
            <template #title>
              <a-space><span>网络流量</span><a-tag color="cyan">接口：{{ currentIface }}</a-tag></a-space>
            </template>
            <div ref="netChartRef" class="chart-container"></div>
          </a-card>
        </a-col>
      </a-row>
    </a-space>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, nextTick } from 'vue'
import { vpnApi } from '../../api/vpn'
import type { VPNStatus } from '../../api/vpn'
import { systemApi, type SystemMetrics } from '../../api/system'
import { Message } from '@arco-design/web-vue'
import { IconUser, IconUserGroup, IconSettings, IconDashboard } from '@arco-design/web-vue/es/icon'
import * as echarts from 'echarts/core'
import { LineChart } from 'echarts/charts'
import { TitleComponent, TooltipComponent, GridComponent, DatasetComponent, TransformComponent, LegendComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

echarts.use([TitleComponent, TooltipComponent, GridComponent, DatasetComponent, TransformComponent, LineChart, LegendComponent, CanvasRenderer])

const stats = ref<VPNStatus>({ total_users: 0, connected_users: 0, total_policies: 0, vpn_network: '', vpn_port: 0, uptime: '' })
const currentMetrics = ref<SystemMetrics>({
  uptime_seconds: 0, load1: 0, load5: 0, load15: 0,
  mem_total_bytes: 0, mem_used_bytes: 0, mem_free_bytes: 0,
  swap_total_bytes: 0, swap_used_bytes: 0,
  tx_bytes: 0, rx_bytes: 0, interface: '',
  interface_ok: false,
  timestamp: Date.now(),
  interval_sec: 0,
})

const loadChartRef = ref<HTMLElement | null>(null)
const memChartRef = ref<HTMLElement | null>(null)
const netChartRef = ref<HTMLElement | null>(null)
let loadChart: echarts.ECharts | null = null
let memChart: echarts.ECharts | null = null
let netChart: echarts.ECharts | null = null
const MAX_POINTS = 30

interface MetricsPoint {
  time: string
  load1: number
  load5: number
  load15: number
  memUsedPercent: number
  txMbps: number
  rxMbps: number
}

const metricsHistory = ref<MetricsPoint[]>([])
const lastNetBytes = ref<{ tx: number; rx: number; ts: number } | null>(null)
const currentIface = computed(() => currentMetrics.value.interface || '未设置')

const loadStats = async () => {
  try {
    stats.value = await vpnApi.getStatus()
  } catch (error: any) {
    Message.error(error.response?.data?.error || '获取统计数据失败')
  }
}

const loadMetrics = async () => {
  try {
    const data = await systemApi.getMetrics()
    if (!data.interface_ok) {
      Message.error(`接口 ${data.interface || '-'} 不可用，无法读取流量`)
      return
    }
    currentMetrics.value = data
    const memUsedPercent = data.mem_total_bytes ? Math.round((data.mem_used_bytes / data.mem_total_bytes) * 10000) / 100 : 0
    const now = data.timestamp || Date.now()
    const timeLabel = new Date().toLocaleTimeString()
    let txMbps = 0; let rxMbps = 0
    if (lastNetBytes.value) {
      const dtSec = Math.max(1, (now - lastNetBytes.value.ts) / 1000)
      const txDelta = data.tx_bytes > lastNetBytes.value.tx ? data.tx_bytes - lastNetBytes.value.tx : 0
      const rxDelta = data.rx_bytes > lastNetBytes.value.rx ? data.rx_bytes - lastNetBytes.value.rx : 0
      txMbps = (txDelta * 8) / (dtSec * 1_000_000)
      rxMbps = (rxDelta * 8) / (dtSec * 1_000_000)
    }
    lastNetBytes.value = { tx: data.tx_bytes, rx: data.rx_bytes, ts: now }
    metricsHistory.value.push({ time: timeLabel, load1: data.load1, load5: data.load5, load15: data.load15, memUsedPercent, txMbps, rxMbps })
    if (metricsHistory.value.length > MAX_POINTS) metricsHistory.value.shift()
    await nextTick()
    renderCharts()
  } catch (error: any) {
    Message.error(error.response?.data?.error || '获取系统指标失败')
  }
}

const refreshData = async () => {
  await Promise.all([loadStats(), loadMetrics()])
}

const renderCharts = () => {
  if (loadChartRef.value) {
    loadChart = loadChart || echarts.init(loadChartRef.value)
    loadChart.setOption({
      tooltip: { trigger: 'axis' },
      legend: { data: ['load1', 'load5', 'load15'] },
      xAxis: { type: 'category', data: metricsHistory.value.map((m) => m.time) },
      yAxis: { type: 'value' },
      series: [
        { name: 'load1', type: 'line', smooth: true, data: metricsHistory.value.map((m) => m.load1) },
        { name: 'load5', type: 'line', smooth: true, data: metricsHistory.value.map((m) => m.load5) },
        { name: 'load15', type: 'line', smooth: true, data: metricsHistory.value.map((m) => m.load15) },
      ],
    })
  }

  if (memChartRef.value) {
    memChart = memChart || echarts.init(memChartRef.value)
    memChart.setOption({
      tooltip: { trigger: 'axis' },
      legend: { data: ['内存使用率 (%)'] },
      xAxis: { type: 'category', data: metricsHistory.value.map((m) => m.time) },
      yAxis: { type: 'value', min: 0, max: 100 },
      series: [{ name: '内存使用率 (%)', type: 'line', smooth: true, data: metricsHistory.value.map((m) => m.memUsedPercent) }],
    })
  }

  if (netChartRef.value) {
    netChart = netChart || echarts.init(netChartRef.value)
    netChart.setOption({
      tooltip: {
        trigger: 'axis',
        formatter: (params: any) => {
          if (!params || params.length === 0) return ''
          const rows = params.map((p: any) => `${p.seriesName}: ${p.data?.toFixed ? p.data.toFixed(2) : p.data} Mbps`)
          return `<div>${params[0].axisValue}<br/>${rows.join('<br/>')}</div>`
        },
      },
      legend: { data: ['上行 (Mbps)', '下行 (Mbps)'] },
      xAxis: { type: 'category', data: metricsHistory.value.map((m) => m.time) },
      yAxis: { type: 'value', min: 0 },
      series: [
        { name: '上行 (Mbps)', type: 'line', smooth: true, data: metricsHistory.value.map((m) => m.txMbps) },
        { name: '下行 (Mbps)', type: 'line', smooth: true, data: metricsHistory.value.map((m) => m.rxMbps) },
      ],
    })
  }
}

const destroyCharts = () => {
  loadChart?.dispose(); loadChart = null
  memChart?.dispose(); memChart = null
  netChart?.dispose(); netChart = null
}

onMounted(() => {
  refreshData()
  const interval = setInterval(loadMetrics, 5000)
  onUnmounted(() => { clearInterval(interval); destroyCharts() })
})
</script>

<style scoped>
.dashboard { padding: 24px; }
.priority-card { background: #ffffff; }
.chart-container { width: 100%; height: 320px; }
:deep(.arco-card) { border-radius: 8px; }
</style>


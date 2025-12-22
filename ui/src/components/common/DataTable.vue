<template>
  <a-table
    :columns="columns"
    :data="data"
    :loading="loading"
    :pagination="pagination"
    :scroll="scroll"
    @page-change="handlePageChange"
    @page-size-change="handlePageSizeChange"
    v-bind="$attrs"
  >
    <template v-for="(_, name) in $slots" #[name]="slotData">
      <slot :name="name" v-bind="slotData" />
    </template>
  </a-table>
</template>

<script setup lang="ts">
import type { TableColumnData, TableData } from '@arco-design/web-vue'

defineProps<{
  columns: TableColumnData[]
  data: TableData[]
  loading?: boolean
  pagination?: any
  scroll?: any
}>()

const emit = defineEmits<{
  pageChange: [page: number]
  pageSizeChange: [pageSize: number]
}>()

const handlePageChange = (page: number) => {
  emit('pageChange', page)
}

const handlePageSizeChange = (pageSize: number) => {
  emit('pageSizeChange', pageSize)
}
</script>


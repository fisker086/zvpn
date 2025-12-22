import { reactive, computed } from 'vue'

/**
 * 分页管理 Composable
 */
export function usePagination(options: {
  pageSize?: number
  showTotal?: boolean
  showPageSize?: boolean
} = {}) {
  const { pageSize = 10, showTotal = true, showPageSize = true } = options

  const pagination = reactive({
    current: 1,
    pageSize,
    total: 0,
    showTotal,
    showPageSize,
  })

  const totalPages = computed(() => {
    return Math.ceil(pagination.total / pagination.pageSize)
  })

  const hasNextPage = computed(() => {
    return pagination.current < totalPages.value
  })

  const hasPrevPage = computed(() => {
    return pagination.current > 1
  })

  const reset = () => {
    pagination.current = 1
    pagination.total = 0
  }

  const setPage = (page: number) => {
    if (page >= 1 && page <= totalPages.value) {
      pagination.current = page
    }
  }

  const setPageSize = (size: number) => {
    pagination.pageSize = size
    pagination.current = 1
  }

  const nextPage = () => {
    if (hasNextPage.value) {
      pagination.current++
    }
  }

  const prevPage = () => {
    if (hasPrevPage.value) {
      pagination.current--
    }
  }

  return {
    pagination,
    totalPages,
    hasNextPage,
    hasPrevPage,
    reset,
    setPage,
    setPageSize,
    nextPage,
    prevPage,
  }
}


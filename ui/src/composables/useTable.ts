import { ref, reactive } from 'vue'
import { Message } from '@arco-design/web-vue'

/**
 * 表格数据管理 Composable
 * 提供通用的表格分页、搜索、筛选功能
 */
export function useTable<T = any>(
  fetchFn: (params: any) => Promise<{ data: T[]; total?: number }>,
  options: {
    pageSize?: number
    immediate?: boolean
  } = {}
) {
  const { pageSize = 10, immediate = true } = options

  const loading = ref(false)
  const data = ref<T[]>([])
  const searchKeyword = ref('')
  const filters = reactive<Record<string, any>>({})

  const pagination = reactive({
    current: 1,
    pageSize,
    total: 0,
    showTotal: true,
    showPageSize: true,
  })

  // 构建查询参数
  const buildQuery = () => {
    const query: any = {
      page: pagination.current,
      page_size: pagination.pageSize,
    }

    if (searchKeyword.value) {
      query.search = searchKeyword.value
    }

    Object.assign(query, filters)

    return query
  }

  // 获取数据
  const fetchData = async () => {
    loading.value = true
    try {
      const query = buildQuery()
      const response = await fetchFn(query)
      data.value = response.data || []
      pagination.total = response.total || response.data?.length || 0
    } catch (error: any) {
      Message.error(error.response?.data?.error || '获取数据失败')
    } finally {
      loading.value = false
    }
  }

  // 刷新数据
  const refresh = () => {
    pagination.current = 1
    fetchData()
  }

  // 搜索
  const handleSearch = () => {
    pagination.current = 1
    fetchData()
  }

  // 筛选变化
  const handleFilterChange = () => {
    pagination.current = 1
    fetchData()
  }

  // 分页变化
  const handlePageChange = (page: number) => {
    pagination.current = page
    fetchData()
  }

  // 每页数量变化
  const handlePageSizeChange = (pageSize: number) => {
    pagination.pageSize = pageSize
    pagination.current = 1
    fetchData()
  }

  // 设置筛选条件
  const setFilter = (key: string, value: any) => {
    filters[key] = value
    handleFilterChange()
  }

  // 清除筛选条件
  const clearFilters = () => {
    Object.keys(filters).forEach(key => {
      delete filters[key]
    })
    searchKeyword.value = ''
    refresh()
  }

  if (immediate) {
    fetchData()
  }

  return {
    loading,
    data,
    searchKeyword,
    filters,
    pagination,
    fetchData,
    refresh,
    handleSearch,
    handleFilterChange,
    handlePageChange,
    handlePageSizeChange,
    setFilter,
    clearFilters,
  }
}


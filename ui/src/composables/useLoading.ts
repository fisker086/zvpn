import { ref } from 'vue'

/**
 * 加载状态管理 Composable
 */
export function useLoading(initialState = false) {
  const loading = ref(initialState)

  const setLoading = (value: boolean) => {
    loading.value = value
  }

  const withLoading = async <T>(fn: () => Promise<T>): Promise<T> => {
    loading.value = true
    try {
      return await fn()
    } finally {
      loading.value = false
    }
  }

  return {
    loading,
    setLoading,
    withLoading,
  }
}


import { ref } from 'vue'
import { Message } from '@arco-design/web-vue'

/**
 * 异步操作管理 Composable
 * 提供通用的异步操作状态管理和错误处理
 */
export function useAsync<T extends (...args: any[]) => Promise<any>>(
  asyncFn: T,
  options: {
    immediate?: boolean
    onSuccess?: (result: Awaited<ReturnType<T>>) => void
    onError?: (error: any) => void
    showError?: boolean
    showSuccess?: boolean
    successMessage?: string
  } = {}
) {
  const {
    immediate = false,
    onSuccess,
    onError,
    showError = true,
    showSuccess = false,
    successMessage,
  } = options

  const loading = ref(false)
  const error = ref<any>(null)
  const data = ref<Awaited<ReturnType<T>> | null>(null)

  const execute = async (...args: Parameters<T>): Promise<Awaited<ReturnType<T>> | null> => {
    loading.value = true
    error.value = null

    try {
      const result = await asyncFn(...args)
      data.value = result

      if (showSuccess && successMessage) {
        Message.success(successMessage)
      }

      if (onSuccess) {
        onSuccess(result)
      }

      return result
    } catch (err: any) {
      error.value = err

      if (showError) {
        const errorMessage = err.response?.data?.error || err.message || '操作失败'
        Message.error(errorMessage)
      }

      if (onError) {
        onError(err)
      }

      return null
    } finally {
      loading.value = false
    }
  }

  const reset = () => {
    loading.value = false
    error.value = null
    data.value = null
  }

  if (immediate) {
    execute(...([] as unknown as Parameters<T>))
  }

  return {
    loading,
    error,
    data,
    execute,
    reset,
  }
}


import { ref, reactive } from 'vue'
import { Message } from '@arco-design/web-vue'

/**
 * 表单管理 Composable
 * 提供通用的表单提交、验证、重置功能
 */
export function useForm<T extends Record<string, any>>(
  initialData: T,
  submitFn: (data: T) => Promise<any>,
  options: {
    validateFn?: (data: T) => boolean | string
    onSuccess?: (response: any) => void
    onError?: (error: any) => void
    successMessage?: string
  } = {}
) {
  const { validateFn, onSuccess, onError, successMessage = '操作成功' } = options

  const formData = reactive<T>({ ...initialData })
  const loading = ref(false)
  const errors = reactive<Record<string, string>>({})

  // 重置表单
  const resetForm = () => {
    Object.assign(formData, initialData)
    clearErrors()
  }

  // 设置表单数据
  const setFormData = (data: Partial<T>) => {
    Object.assign(formData, data)
  }

  // 设置错误
  const setError = (field: string, message: string) => {
    errors[field] = message
  }

  // 清除错误
  const clearErrors = () => {
    Object.keys(errors).forEach(key => {
      delete errors[key]
    })
  }

  // 清除单个字段错误
  const clearError = (field: string) => {
    delete errors[field]
  }

  // 验证表单
  const validate = (): boolean => {
    clearErrors()

    if (validateFn) {
      const result = validateFn({ ...formData } as T)
      if (typeof result === 'string') {
        Message.warning(result)
        return false
      }
      if (result === false) {
        return false
      }
    }

    return true
  }

  // 提交表单
  const submit = async (): Promise<boolean> => {
    if (!validate()) {
      return false
    }

    loading.value = true
    try {
      const response = await submitFn({ ...formData } as T)
      Message.success(successMessage)
      if (onSuccess) {
        onSuccess(response)
      }
      return true
    } catch (error: any) {
      const errorMessage = error.response?.data?.error || '操作失败'
      Message.error(errorMessage)
      if (onError) {
        onError(error)
      }
      return false
    } finally {
      loading.value = false
    }
  }

  return {
    formData,
    loading,
    errors,
    resetForm,
    setFormData,
    setError,
    clearErrors,
    clearError,
    validate,
    submit,
  }
}


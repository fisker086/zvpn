import { ref } from 'vue'

/**
 * 模态框管理 Composable
 * 提供通用的模态框显示/隐藏状态管理
 */
export function useModal() {
  const visible = ref(false)
  const loading = ref(false)

  const show = () => {
    visible.value = true
  }

  const hide = () => {
    visible.value = false
  }

  const toggle = () => {
    visible.value = !visible.value
  }

  const setLoading = (value: boolean) => {
    loading.value = value
  }

  return {
    visible,
    loading,
    show,
    hide,
    toggle,
    setLoading,
  }
}


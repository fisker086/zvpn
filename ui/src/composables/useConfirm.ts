import { Modal } from '@arco-design/web-vue'

/**
 * 确认对话框 Composable
 */
export function useConfirm() {
  const confirm = (
    content: string,
    options: {
      title?: string
      okText?: string
      cancelText?: string
      onOk?: () => void | Promise<void>
      onCancel?: () => void
      type?: 'info' | 'success' | 'warning' | 'error'
    } = {}
  ) => {
    const {
      title = '确认操作',
      okText = '确定',
      cancelText = '取消',
      onOk,
      onCancel,
      type = 'warning',
    } = options

    Modal[type]({
      title,
      content,
      okText,
      cancelText,
      onOk: async () => {
        if (onOk) {
          await onOk()
        }
      },
      onCancel,
    })
  }

  const confirmDelete = (
    itemName: string,
    onOk: () => void | Promise<void>
  ) => {
    confirm(`确定要删除 "${itemName}" 吗？此操作不可恢复。`, {
      title: '确认删除',
      type: 'error',
      onOk,
    })
  }

  return {
    confirm,
    confirmDelete,
  }
}


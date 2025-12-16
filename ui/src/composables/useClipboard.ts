import { Message } from '@arco-design/web-vue'

/**
 * 剪贴板操作 Composable
 */
export function useClipboard() {
  const copyToClipboard = async (text: string, successMessage = '已复制到剪贴板') => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text)
        Message.success(successMessage)
        return true
      } else {
        // 降级方案：使用传统方法
        const textArea = document.createElement('textarea')
        textArea.value = text
        textArea.style.position = 'fixed'
        textArea.style.left = '-999999px'
        document.body.appendChild(textArea)
        textArea.focus()
        textArea.select()
        try {
          document.execCommand('copy')
          Message.success(successMessage)
          return true
        } catch (err) {
          Message.error('复制失败')
          return false
        } finally {
          document.body.removeChild(textArea)
        }
      }
    } catch (error) {
      Message.error('复制失败')
      return false
    }
  }

  return {
    copyToClipboard,
  }
}


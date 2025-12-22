import { computed } from 'vue'
import { useAuthStore } from '@/stores/auth'

/**
 * 权限管理 composable
 * 提供统一的权限检查方法
 */
export function usePermission() {
  const authStore = useAuthStore()

  /**
   * 是否为管理员
   */
  const isAdmin = computed(() => authStore.isAdmin)

  /**
   * 是否为普通用户（只读）
   */
  const isReadOnly = computed(() => !authStore.isAdmin)

  /**
   * 检查是否有权限执行某个操作
   * @param action 操作名称
   * @returns 是否有权限
   */
  const hasPermission = (action: string): boolean => {
    // 管理员拥有所有权限
    if (isAdmin.value) {
      return true
    }

    // 普通用户只能查看
    const readOnlyActions = ['view', 'read', 'list', 'get']
    return readOnlyActions.includes(action.toLowerCase())
  }

  /**
   * 检查是否可以编辑
   */
  const canEdit = computed(() => isAdmin.value)

  /**
   * 检查是否可以删除
   */
  const canDelete = computed(() => isAdmin.value)

  /**
   * 检查是否可以创建
   */
  const canCreate = computed(() => isAdmin.value)

  return {
    isAdmin,
    isReadOnly,
    hasPermission,
    canEdit,
    canDelete,
    canCreate,
  }
}


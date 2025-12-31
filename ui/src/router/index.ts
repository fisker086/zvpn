import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/login/index.vue'),
    meta: { requiresAuth: false },
  },
  {
    path: '/',
    component: () => import('@/components/layout/MainLayout.vue'),
    meta: { requiresAuth: true },
    children: [
      {
        path: '',
        name: 'Dashboard',
        component: () => import('@/views/dashboard/index.vue'),
        meta: { title: '仪表盘', icon: 'icon-dashboard' },
      },
      {
        path: 'users',
        name: 'Users',
        component: () => import('@/views/users/index.vue'),
        meta: { title: '用户管理', icon: 'icon-user' }, // 普通用户也可以查看
      },
      {
        path: 'policies',
        name: 'Policies',
        component: () => import('@/views/policies/index.vue'),
        meta: { title: '策略管理', icon: 'icon-settings' }, // 普通用户也可以查看
      },
      {
        path: 'monitor',
        name: 'Monitor',
        component: () => import('@/views/monitor/index.vue'),
        meta: { title: '在线用户', icon: 'icon-computer' },
      },
      {
        path: 'groups',
        name: 'Groups',
        component: () => import('@/views/groups/index.vue'),
        meta: { title: '用户组管理', icon: 'icon-user-group' }, // 普通用户也可以查看
      },
      {
        path: 'hooks',
        name: 'Hooks',
        component: () => import('@/views/hooks/index.vue'),
        meta: { title: 'Hook策略', icon: 'icon-code-block' }, // 普通用户也可以查看
      },
      {
        path: 'settings',
        name: 'Settings',
        component: () => import('@/views/settings/index.vue'),
        meta: { title: '系统设置', icon: 'icon-settings', requiresAdmin: true }, // 系统设置仍需要管理员
      },
      {
        path: 'audit-logs',
        name: 'AuditLogs',
        component: () => import('@/views/audit-logs/index.vue'),
        meta: { title: '审计日志', icon: 'icon-file-text' }, // 普通用户也可以查看
      },
    ],
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

// 路由守卫
router.beforeEach(async (to, _, next) => {
  const authStore = useAuthStore()

  if (to.meta.requiresAuth && !authStore.isAuthenticated) {
    next('/login')
  } else if (authStore.isAuthenticated && !authStore.user) {
    // 用户已经认证，但没有用户信息，重新获取用户信息
    try {
      await authStore.fetchProfile()
    } catch (error) {
      // 获取用户信息失败，可能是 token 过期，跳转到登录页
      await authStore.logout()
      next('/login')
      return
    }
    // 继续检查路由权限
    if (to.meta.requiresAdmin && !authStore.isAdmin) {
      next('/')
    } else {
      next()
    }
  } else if (to.meta.requiresAdmin && !authStore.isAdmin) {
    next('/')
  } else if (to.path === '/login' && authStore.isAuthenticated) {
    next('/')
  } else {
    next()
  }
})

export default router


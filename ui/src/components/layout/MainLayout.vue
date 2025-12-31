<template>
  <a-layout class="main-layout">
    <a-layout-sider
      collapsible
      :collapsed="collapsed"
      @collapse="onCollapse"
      :width="220"
      :collapsed-width="64"
    >
      <div class="logo">
        <icon-robot-add v-if="collapsed" :size="28" />
        <span v-else>ZVPN 管理后台</span>
      </div>
      <a-menu
        :selected-keys="[route.name as string]"
        @menu-item-click="handleMenuClick"
      >
        <a-menu-item
          v-for="item in menuItems"
          :key="item.name"
        >
          <template #icon>
            <component :is="item.icon" />
          </template>
          {{ item.title }}
        </a-menu-item>
      </a-menu>
    </a-layout-sider>

    <a-layout>
      <a-layout-header>
        <div class="header-content">
          <div class="header-left">
            <a-breadcrumb>
              <a-breadcrumb-item>
                <icon-home />
              </a-breadcrumb-item>
              <a-breadcrumb-item>{{ currentTitle }}</a-breadcrumb-item>
            </a-breadcrumb>
          </div>
          <div class="header-right">
            <a-space :size="20">
              <a-badge :count="0" :dot-style="{ display: 'none' }">
                <a-button type="text" shape="circle">
                  <icon-notification :size="18" />
                </a-button>
              </a-badge>
              <a-dropdown>
                <a-space class="user-info">
                  <a-avatar :size="32">
                    <icon-user />
                  </a-avatar>
                  <span>{{ authStore.user?.username }}</span>
                </a-space>
                <template #content>
                  <a-doption disabled>
                    <template #icon>
                      <icon-user />
                    </template>
                    {{ authStore.user?.email || '未设置邮箱' }}
                  </a-doption>
                  <a-doption @click="handleLogout">
                    <template #icon>
                      <icon-export />
                    </template>
                    退出登录
                  </a-doption>
                </template>
              </a-dropdown>
            </a-space>
          </div>
        </div>
      </a-layout-header>

      <a-layout-content>
        <router-view />
      </a-layout-content>

      <a-layout-footer>
        <div class="footer-content">
          © 2026 ZVPN Team
        </div>
      </a-layout-footer>
    </a-layout>
  </a-layout>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { Message } from '@arco-design/web-vue'
import {
  IconHome,
  IconDashboard,
  IconUser,
  IconSettings,
  IconComputer,
  IconNotification,
  IconExport,
  IconRobotAdd,
  IconCodeBlock,
  IconUserGroup,
  IconTool,
  IconFile,
} from '@arco-design/web-vue/es/icon'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()

const collapsed = ref(false)

const menuItems = computed(() => {
  const items = [
    {
      name: 'Dashboard',
      title: '仪表盘',
      icon: IconDashboard,
    },
    {
      name: 'Monitor',
      title: '在线用户',
      icon: IconComputer,
    },
  ]

  // 所有用户都可以查看的页面
  items.push(
    {
      name: 'Users',
      title: '用户管理',
      icon: IconUser,
    },
    {
      name: 'Groups',
      title: '用户组管理',
      icon: IconUserGroup,
    },
    {
      name: 'Policies',
      title: '策略管理',
      icon: IconSettings,
    },
    {
      name: 'Hooks',
      title: 'Hook策略',
      icon: IconCodeBlock,
    },
    {
      name: 'AuditLogs',
      title: '审计日志',
      icon: IconFile,
    }
  )

  // 仅管理员可见
  if (authStore.isAdmin) {
    items.push({
      name: 'Settings',
      title: '系统设置',
      icon: IconTool,
    })
  }

  return items
})

const currentTitle = computed(() => {
  const item = menuItems.value.find((item) => item.name === route.name)
  return item?.title || '首页'
})

const onCollapse = (val: boolean) => {
  collapsed.value = val
}

const handleMenuClick = (key: string) => {
  router.push({ name: key })
}

const handleLogout = async () => {
  try {
    await authStore.logout()
    router.push('/login')
    Message.success('退出登录成功')
  } catch (error) {
    console.error('退出登录失败:', error)
  }
}
</script>

<style scoped>
.main-layout {
  height: 100vh;
  background: #f7f8fa;
}

.logo {
  height: 64px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #1d2129;
  font-size: 16px;
  font-weight: 600;
  background: #fff;
  border-bottom: 1px solid var(--color-border-2);
}

.header-content {
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
}

.header-left {
  flex: 1;
}

.header-right {
  display: flex;
  align-items: center;
}

.user-info {
  cursor: pointer;
  padding: 4px 8px;
  border-radius: 4px;
  transition: background-color 0.2s;
}

.user-info:hover {
  background: var(--color-fill-2);
}

.footer-content {
  text-align: center;
  color: var(--color-text-3);
  font-size: 13px;
  letter-spacing: 0.3px;
}

:deep(.arco-layout-sider) {
  background: #fff;
  border-right: 1px solid var(--color-border-2);
}

:deep(.arco-menu) {
  background: transparent;
}

:deep(.arco-menu-item) {
  margin: 4px 12px;
  border-radius: 4px;
}

:deep(.arco-menu-item:hover) {
  background: var(--color-fill-2);
}

:deep(.arco-menu-item.arco-menu-selected) {
  background: rgb(var(--primary-1));
  color: rgb(var(--primary-6));
  font-weight: 500;
}

:deep(.arco-layout-header) {
  height: 64px;
  line-height: 64px;
  background: #fff;
  border-bottom: 1px solid var(--color-border-2);
}

:deep(.arco-layout-content) {
  background: #f7f8fa;
}

:deep(.arco-layout-footer) {
  height: 48px;
  line-height: 48px;
  background: #fff;
  border-top: 1px solid var(--color-border-2);
}
</style>

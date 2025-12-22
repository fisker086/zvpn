<template>
  <a-tag :color="color" :size="size">
    <template v-if="icon">
      <component :is="icon" :style="{ marginRight: '4px' }" />
    </template>
    {{ label }}
  </a-tag>
</template>

<script setup lang="ts">
import type { Component } from 'vue'

defineProps<{
  label: string
  color?: string
  size?: 'small' | 'medium' | 'large'
  icon?: Component
}>()
</script>


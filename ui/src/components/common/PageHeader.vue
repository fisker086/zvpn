<template>
  <div class="page-header">
    <div class="header-left">
      <h3>{{ title }}</h3>
      <p v-if="description" class="description">{{ description }}</p>
    </div>
    <div class="header-right" v-if="$slots.actions">
      <slot name="actions" />
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  title: string
  description?: string
}>()
</script>

<style scoped>
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 20px;
}

.header-left h3 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: var(--color-text-1);
}

.header-left .description {
  margin: 4px 0 0;
  font-size: 14px;
  color: var(--color-text-3);
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}
</style>


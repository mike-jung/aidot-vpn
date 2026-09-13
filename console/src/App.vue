<script setup>
import { translate as tr, localeTag } from './i18n/index.js'
// Root component. We delegate the chrome (nav, header, sidebar) to
// AppLayout and let route-specific content render in the slot.
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import AppLayout from '@/components/AppLayout.vue'
import { isAuthenticated } from '@/stores/auth.js'

const route = useRoute()
const showLayout = computed(() => {
  // The login route renders without the layout chrome.
  return route.name !== 'login' && isAuthenticated.value
})
</script>

<template>
  <AppLayout v-if="showLayout">
    <router-view />
  </AppLayout>
  <router-view v-else />
</template>

<style>
/* Global overrides applied on top of Bootstrap. Keep this file tiny —
   per-component styles belong in their .vue files. */
:root {
  --aidotvpn-bg: var(--bg);
}
body {
  /* background comes from styles/console.css (radial glow over --bg) */
}
</style>

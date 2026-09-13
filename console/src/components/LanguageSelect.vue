<script setup>
import { locale, setLocale } from '../i18n/index.js'
defineProps({ id: {type: String, default: 'console-language'} })
</script>
<template>
  <div class="language-select">
    <label :for="id">Language / 언어</label>
    <select :id="id" class="form-select form-select-sm" :value="locale" @change="setLocale($event.target.value)">
      <option value="en" lang="en">English</option>
      <option value="ko" lang="ko">한국어</option>
    </select>
  </div>
</template>
<style scoped>
.language-select { display:flex; align-items:center; justify-content:space-between; gap:1rem; margin-bottom:1.2rem; text-align:left }
label { font-size:.85rem; white-space:nowrap; color:var(--text-2) }
select { width:auto; min-width:8rem }
</style>

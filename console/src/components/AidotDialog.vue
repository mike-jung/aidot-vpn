<script setup>
import { translate as tr, localeTag } from '../i18n/index.js'
/**
 * AidotDialog — the console's modal.
 *
 * Replaces `alert()`, `confirm()` and `prompt()`, which were scattered
 * across four views. Those work, and they look like a browser error
 * rather than part of the application — the wrong register for "are you
 * sure", and Chrome suppresses them outright after a couple in a row,
 * so a confirmation could silently never appear.
 *
 * Deliberately not a promise-returning `showDialog()` helper. That reads
 * nicely at the call site and hides the dialog's state from the
 * component, which then cannot show a spinner on the confirm button or
 * an error inside the dialog when the action fails. Both are things
 * every destructive action here needs.
 *
 * Escape and a backdrop click close it, unless `busy` — an in-flight
 * request should not be dismissed out from under itself.
 */
import { onBeforeUnmount, onMounted, watch, nextTick, ref } from 'vue'
import AidotIcon from './AidotIcon.vue'

const props = defineProps({
  open: { type: Boolean, default: false },
  wide: { type: Boolean, default: false },
  title: { type: String, required: true },
  /** 'default' | 'danger' — colours the confirm button. */
  tone: { type: String, default: 'default' },
  confirmLabel: { type: String, default: '확인' },
  cancelLabel: { type: String, default: '취소' },
  /** Hides the confirm button, for informational dialogs. */
  confirmOnly: { type: Boolean, default: false },
  /** Disables confirm and blocks dismissal while an action runs. */
  busy: { type: Boolean, default: false },
  /** Shown in red inside the dialog body. */
  error: { type: String, default: '' },
})
const emit = defineEmits(['update:open', 'confirm'])

const panel = ref(null)
let returnFocus = null
let previousOverflow = null
function restoreScroll() { if (previousOverflow !== null) { document.body.style.overflow = previousOverflow; previousOverflow = null } }

function close () {
  if (props.busy) return
  emit('update:open', false)
}

function onKey (e) {
  if (!props.open) return
  if (e.key === 'Escape') { e.preventDefault(); close(); return }
  if (e.key !== 'Tab' || !panel.value) return
  const items = [...panel.value.querySelectorAll('button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])')].filter(el => el.getClientRects().length)
  const first = items[0], last = items.at(-1)
  if (!first) { e.preventDefault(); panel.value.focus(); return }
  if (e.shiftKey && (document.activeElement === first || !items.includes(document.activeElement))) { e.preventDefault(); last.focus() }
  else if (!e.shiftKey && (document.activeElement === last || !items.includes(document.activeElement))) { e.preventDefault(); first.focus() }
}

onMounted(() => document.addEventListener('keydown', onKey))
onBeforeUnmount(() => { document.removeEventListener('keydown', onKey); restoreScroll(); if (returnFocus?.isConnected) returnFocus.focus() })

// Focus the panel when it opens so Escape and Tab work without the user
// clicking first, and so a screen reader announces the dialog.
watch(() => props.open, async (v) => {
  if (!v) { restoreScroll(); if (returnFocus?.isConnected) returnFocus.focus(); returnFocus = null; return }
  if (previousOverflow === null) { previousOverflow = document.body.style.overflow; document.body.style.overflow = 'hidden' }
  returnFocus = document.activeElement
  await nextTick()
  if (props.open) panel.value?.focus()
}, { immediate: true })
</script>

<template>
  <Teleport to="body">
    <div v-if="open" class="dlg-backdrop" @click.self="close">
      <div
        ref="panel"
        class="dlg" :class="{ wide }"
        role="dialog"
        aria-modal="true"
        :aria-busy="busy"
        :aria-label="tr(title)"
        tabindex="-1"
      >
        <div class="dlg-head">
          <h2>{{ tr(title) }}</h2>
          <button
            type="button" class="dlg-x" :aria-label="tr(&quot;닫기&quot;)"
            :disabled="busy" @click="close"
          >
            <AidotIcon name="close" :size="18" />
          </button>
        </div>

        <div class="dlg-body">
          <div v-if="error" class="dlg-error" role="alert">
            <AidotIcon name="alert" :size="16" /><span>{{ tr(error) }}</span>
          </div>
          <slot />
        </div>

        <div class="dlg-foot">
          <slot name="actions">
            <button type="button" class="btn" :disabled="busy" @click="close">
              {{ tr(confirmOnly ? '닫기' : cancelLabel) }}
            </button>
            <button
              v-if="!confirmOnly"
              type="button"
              class="btn"
              :class="tone === 'danger' ? 'danger' : 'primary'"
              :disabled="busy"
              @click="emit('confirm')"
            >
              {{ tr(busy ? '처리 중…' : confirmLabel) }}
            </button>
          </slot>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.dlg-backdrop {
  position: fixed; inset: 0; background: rgba(16, 57, 75, .42);
  display: flex; align-items: center; justify-content: center;
  padding: 1rem; z-index: 1100;
}
.dlg {
  width: 100%; max-width: 460px; background: var(--panel);
  border-radius: 14px; box-shadow: 0 18px 48px rgba(16, 57, 75, .24);
  overflow: hidden; outline: none; max-height: calc(100dvh - 2rem);
  display: flex; flex-direction: column;
}
.dlg.wide { max-width:1080px; }
.dlg-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: .85rem 1rem; border-bottom: 1px solid var(--line);
}
.dlg-head h2 { margin: 0; font-size: 1rem; font-weight: 700; color: var(--text); }
.dlg-x {
  display: inline-flex; align-items: center; justify-content: center;
  width: 30px; height: 30px; border: 0; border-radius: 8px;
  background: transparent; color: var(--text-3); cursor: pointer;
}
.dlg-x:hover:not(:disabled) { background: var(--panel-2); color: var(--text); }
.dlg-x:disabled { opacity: .4; cursor: default; }

.dlg-body { overflow-y: auto; min-height: 0; padding: 1rem; font-size: .9rem; color: var(--text); }
.dlg-error {
  display: flex; align-items: flex-start; gap: .5rem;
  padding: .6rem .7rem; margin-bottom: .8rem;
  background: var(--bad-soft); border: 1px solid var(--bad); border-radius: 9px;
  color: var(--bad); font-size: .84rem;
}

.dlg-head, .dlg-foot { flex-shrink: 0; }
.btn:focus-visible, .dlg-x:focus-visible { outline: 3px solid var(--accent); outline-offset: 2px; }
.dlg-foot {
  display: flex; justify-content: flex-end; gap: .5rem;
  padding: .75rem 1rem; border-top: 1px solid var(--line); background: var(--panel);
}
.btn {
  display: inline-flex; align-items: center; gap: .4rem;
  padding: .45rem .9rem; border-radius: 9px;
  border: 1px solid var(--line-2); background: var(--panel); color: var(--text);
  font-size: .86rem; font-weight: 600; cursor: pointer; white-space: nowrap;
}
.btn:hover:not(:disabled) { background: var(--panel-2); }
.btn:disabled { opacity: .55; cursor: default; }
.btn.primary { background: var(--accent); border-color: var(--accent); color: var(--text); }
.btn.primary:hover:not(:disabled) { background: var(--accent-2); }
.btn.danger { background: var(--bad); border-color: var(--bad); color: var(--text); }
.btn.danger:hover:not(:disabled) { background: var(--bad); }
</style>

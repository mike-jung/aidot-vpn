<script setup>
import { translate as tr, localeTag } from '../i18n/index.js'
/**
 * 추적 — one screen, three subjects.
 *
 * The three traces existed but were hidden behind buttons on other
 * screens: a 추적 button on a device row, another on policy detail, and
 * a clickable actor name in 감사 로그. Each is the right place to reach
 * it *while you are there*, and none of them answers "where is the
 * tracing feature" — which is the question someone arrives with.
 *
 * Shape follows aidot-express's 추적 tabs: pick a subject, pick one of
 * them, read its history. The subjects differ because the domain does —
 * a device, a policy, an admin — but the motion is the same.
 */
import { ref, computed, onMounted } from 'vue'
import { devices as devicesAPI, policies as policiesAPI, audit as auditAPI,
  trace as traceAPI } from '@/api/client.js'

const tab = ref('device')
const TABS = [
  ['device', '단말별', '이 단말에 무슨 일이 있었나'],
  ['policy', '정책별', '이 정책이 누구에게 닿고, 어떻게 바뀌었나'],
  ['actor', '관리자별', '이 사람이 무엇을 했나'],
]

const subjects = ref([])
const loadingList = ref(true)
const picked = ref(null)
const events = ref([])
// One list serves all three tabs, so one pager does too.
const perPage = 10
const page = ref(1)
const pages = computed(() => Math.max(1, Math.ceil(events.value.length / perPage)))
const paged = computed(() =>
  events.value.slice((page.value - 1) * perPage, page.value * perPage))
const devicesOf = ref([])
const busy = ref(false)
const err = ref('')

async function loadSubjects () {
  loadingList.value = true
  picked.value = null
  events.value = []
  devicesOf.value = []
  try {
    if (tab.value === 'device') {
      const r = await devicesAPI.list()
      subjects.value = (r.devices || []).map((d) => ({
        id: d.id, label: d.display_name, sub: d.ipv4 || d.platform || '',
      }))
    } else if (tab.value === 'policy') {
      const r = await policiesAPI.list()
      subjects.value = (r.policies || []).map((p) => ({
        id: p.id, label: p.name, sub: p.description || '',
      }))
    } else {
      // Admins have no list endpoint; the audit log is where they
      // appear, so distinct actors from it are the list.
      const r = await auditAPI.list({ limit: 200 })
      const seen = new Map()
      for (const e of r.entries || []) {
        if (!e.actor_id || seen.has(e.actor_id)) continue
        seen.set(e.actor_id, {
          id: e.actor_id,
          label: e.details?.email || (e.actor_kind === 'user' ? '관리자' : e.actor_kind),
          sub: e.details?.ip || '',
        })
      }
      subjects.value = [...seen.values()]
    }
  } catch (e) {
    err.value = e?.message || String(e)
  } finally {
    loadingList.value = false
  }
}

async function pick (s) {
  picked.value = s
  busy.value = true
  err.value = ''
  events.value = []
  devicesOf.value = []
  try {
    const r = tab.value === 'device' ? await traceAPI.device(s.id)
      : tab.value === 'policy' ? await traceAPI.policy(s.id)
        : await traceAPI.actor(s.id)
    // Newest first: someone opening a trace is asking what happened
    // last, not what happened first.
    events.value = (r.events || []).slice().reverse()
    page.value = 1
    devicesOf.value = r.devices || []
  } catch (e) {
    err.value = e?.message || String(e)
  } finally {
    busy.value = false
  }
}

function switchTab (t) { tab.value = t; loadSubjects() }

const toneClass = (t) => ({
  ok: 'text-success', warn: 'text-warning', bad: 'text-danger', muted: 'text-muted',
}[t] || '')

/** The four stages, read off the events — device tab only. */
const stages = computed(() => {
  if (tab.value !== 'device' || !picked.value) return []
  const at = (a) => {
    const e = events.value.find((x) => x.action === a)
    return e ? new Date(e.at).toLocaleString(localeTag.value) : ''
  }
  const reg = at('device.register')
  const pol = at('policy.assign')
  const hs = at('handshake')
  return [
    { label: '등록 요청', done: !!reg, at: reg },
    { label: '관리자 승인', done: !!reg, at: reg },
    { label: '정책 적용', done: !!pol, at: pol },
    { label: '연결', done: !!hs, at: hs },
  ]
})

const filter = ref('')
const shown = computed(() => {
  const q = filter.value.trim().toLowerCase()
  if (!q) return subjects.value
  return subjects.value.filter((s) =>
    (s.label || '').toLowerCase().includes(q) || (s.sub || '').toLowerCase().includes(q))
})

onMounted(loadSubjects)
</script>

<template>
  <div class="container-fluid py-3">
    <h1 class="h4 mb-1"> {{ tr("추적") }} </h1>
    <p class="text-muted small mb-3">
      {{ tr(TABS.find((t) => t[0] === tab)?.[2]) }}
    </p>

    <ul class="nav nav-tabs mb-3">
      <li v-for="[key, label] in TABS" :key="key" class="nav-item">
        <button
          class="nav-link" :class="{ active: tab === key }"
          type="button" @click="switchTab(key)"
        >{{ tr(label) }}</button>
      </li>
    </ul>

    <div class="row g-3">
      <div class="col-md-4">
        <div class="card">
          <div class="card-header py-2"><strong> {{ tr("고르기") }} </strong></div>
          <div class="card-body p-2">
            <input v-model="filter" class="form-control form-control-sm mb-2" :placeholder="tr(&quot;검색…&quot;)" />
            <div v-if="loadingList" class="text-muted small p-2"> {{ tr("불러오는 중…") }} </div>
            <div v-else-if="!shown.length" class="text-muted small p-2"> {{ tr("없습니다.") }} </div>
            <div v-else class="list-group list-group-flush trace-list">
              <button
                v-for="s in shown" :key="s.id"
                type="button"
                class="list-group-item list-group-item-action py-2"
                :class="{ active: picked && picked.id === s.id }"
                @click="pick(s)"
              >
                <div class="small fw-semibold">{{ s.label }}</div>
                <div v-if="s.sub" class="text-muted font-monospace" style="font-size:.72rem">
                  {{ s.sub }}
                </div>
              </button>
            </div>
          </div>
        </div>
      </div>

      <div class="col-md-8">
        <div class="card">
          <div class="card-header py-2">
            <strong>{{ picked ? picked.label : tr('왼쪽에서 하나 고르세요') }}</strong>
          </div>
          <div class="card-body">
            <div v-if="!picked" class="text-muted small"> {{ tr("고르면 그 대상에 있었던 일이 시간순으로 나옵니다.") }} </div>
            <template v-else>
              <div v-if="stages.length" class="trace-stages mb-3">
                <div v-for="(st, i) in stages" :key="i">
                  <div class="trace-bar" :class="{ on: st.done }" />
                  <div class="trace-lbl" :class="{ on: st.done }">{{ tr(st.label) }}</div>
                  <div class="trace-at">{{ st.at || '—' }}</div>
                </div>
              </div>

              <div v-if="devicesOf.length" class="mb-3">
                <div class="fw-semibold small mb-1"> {{ tr("지금 이 정책을 쓰는 단말 {0}대", [devicesOf.length]) }} </div>
                <div class="d-flex flex-wrap gap-2">
                  <span v-for="d in devicesOf" :key="d.name"
                        class="badge bg-secondary-subtle text-secondary-emphasis">{{ d.name }}</span>
                </div>
              </div>

              <div v-if="busy" class="text-muted small"> {{ tr("불러오는 중…") }} </div>
              <div v-else-if="err" class="alert alert-danger py-2 small">{{ tr(err) }}</div>
              <div v-else-if="!events.length" class="text-muted small"> {{ tr("기록이 없습니다.") }} </div>
              <table v-else class="table table-sm align-middle mb-0">
                <tbody>
                  <tr v-for="(e, i) in paged" :key="i">
                    <td class="small text-muted" style="width:11rem">
                      {{ new Date(e.at).toLocaleString(localeTag) }}
                    </td>
                    <td class="small" style="width:4.5rem">{{ tr(e.actor) }}</td>
                    <td>
                      <span :class="toneClass(e.tone)">{{ tr(e.label) }}</span>
                      <div v-if="e.details" class="text-muted" style="font-size:.74rem">
                        <span v-for="(v, k) in e.details" :key="k" class="me-2">
                          <template v-if="v !== '' && v !== null">{{ tr(k) }} <code>{{ v }}</code></template>
                        </span>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
              <div v-if="pages > 1" class="d-flex justify-content-between align-items-center mt-2">
                <button class="btn btn-sm btn-outline-secondary" type="button"
                        :disabled="page <= 1" @click="page--"> {{ tr("← 이전") }} </button>
                <span class="text-muted small"> {{ tr("{0} / {1}쪽 · {2}건", [page, pages, events.length]) }} </span>
                <button class="btn btn-sm btn-outline-secondary" type="button"
                        :disabled="page >= pages" @click="page++"> {{ tr("다음 →") }} </button>
              </div>
            </template>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* Bootstrap's active tab is dark text on a light fill, which in a dark
   console is dark on dark. Console tokens instead, so the selected tab
   is the one you can read. */
.nav-tabs .nav-link {
  color: var(--text-3, #7b8aa8);
  border-color: transparent;
  background: transparent;
}
.nav-tabs .nav-link:hover { color: var(--text, #e6edf7); }
.nav-tabs .nav-link.active {
  color: var(--text, #e6edf7);
  background: var(--panel, #111827);
  border-color: var(--line, rgba(255,255,255,.12)) var(--line, rgba(255,255,255,.12)) transparent;
  font-weight: 600;
}

.trace-list { max-height: 26rem; overflow-y: auto; }
.trace-stages { display: grid; grid-template-columns: repeat(4, 1fr); gap: .5rem; }
.trace-bar { height: 4px; border-radius: 2px; background: var(--line); }
.trace-bar.on { background: var(--accent); }
.trace-lbl { font-size: .78rem; color: var(--text-3); margin-top: .35rem; }
.trace-lbl.on { color: var(--text); font-weight: 600; }
.trace-at { font-size: .68rem; color: var(--text-3); }
</style>

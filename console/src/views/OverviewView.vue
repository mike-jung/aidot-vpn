<script setup>
import { translate as tr, localeTag } from '../i18n/index.js'
/**
 * The landing screen.
 *
 * The console opened on the device list, which assumes the admin
 * already knows what they are looking for. The questions they actually
 * arrive with — how many phones are live, is the gateway up, is anything
 * stuck — needed three screens and counting by eye.
 *
 * Every comparable console (NetBird, Firezone, wg-easy, Tailscale)
 * opens on a summary rather than a list. This is ours.
 *
 * Deliberately no topology diagram: ours is hub-and-spoke, so the
 * picture is always the same star and carries no information. And no
 * traffic graphs — nobody in a hospital watches those, and the question
 * they would answer is "is this phone alive", which one timestamp
 * answers better.
 */
import { ref, onMounted, computed } from 'vue'
import { RouterLink } from 'vue-router'
import { actionLabel, actionTone } from '@/lib/actions.js'
import { stats as statsAPI, devices as devicesAPI, nodes as nodesAPI, policies as policiesAPI,
         enrollmentRequests as reqAPI, audit as auditAPI } from '@/api/client.js'

const loading = ref(true)

// 통계 — the four numbers answered "is anything broken now" and nothing
// else. These answer the questions a review asks: who is on what
// policy, what has been happening, who is moving traffic, and whether
// usage is rising. All of it from data the controller already had,
// except the connection series, which needed samples because
// last_handshake_at holds one timestamp and cannot describe an hour ago.
/** Which device or policy an audit entry was about. */
function eventSubject (e) {
  const d = e.details || {}
  return d.device_name || d.display_name || d.policy_name || d.name || d.email || ''
}

const stat = ref(null)
async function loadStats () {
  try { stat.value = await statsAPI.overview() } catch { stat.value = null }
}

const bytes = (n) => {
  if (!n) return '0'
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KiB`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MiB`
  return `${(n / 1024 ** 3).toFixed(2)} GiB`
}

/** Points for the connection sparkline, scaled into a 300x60 box. */
const connPath = computed(() => {
  const pts = stat.value?.connections || []
  // One sample cannot make a line. Rather than an empty card that says
  // "no samples yet" — which is wrong once one exists — the template
  // draws a dot for a single point and this returns nothing.
  if (pts.length < 2) return ''
  const max = Math.max(1, ...pts.map((p) => p.total))
  return pts.map((p, i) => {
    const x = (i / (pts.length - 1)) * 300
    const y = 60 - (p.connected / max) * 56
    return `${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`
  }).join(' ')
})
const connMax = computed(() =>
  Math.max(1, ...(stat.value?.connections || []).map((p) => p.total)))

/** Sizes as CSS strings, so the template holds no expressions. */
/**
 * The activity card as a line, not bars.
 *
 * Bars answer "how big was each day"; a line answers "is this rising or
 * falling", which is the question a seven-day card exists for. Same
 * data, and the shape is legible at a glance instead of requiring the
 * reader to compare heights.
 */
const activityPath = computed(() => {
  const d = activityWeek.value
  if (d.length < 2) return ''
  const max = Math.max(1, ...d.map((x) => x.count))
  return d.map((x, i) => {
    const px = (i / (d.length - 1)) * 300
    const py = 56 - (x.count / max) * 48
    return `${i ? 'L' : 'M'}${px.toFixed(1)} ${py.toFixed(1)}`
  }).join(' ')
})
const activityDots = computed(() => {
  const d = activityWeek.value
  const max = Math.max(1, ...d.map((x) => x.count))
  return d.map((x, i) => ({
    cx: (i / Math.max(1, d.length - 1)) * 300,
    cy: 56 - (x.count / max) * 48,
    label: x.date.slice(5),
    count: x.count,
  }))
})
const barWidth = (n) => `${(n / policyMax.value) * 100}%`

const policyMax = computed(() =>
  Math.max(1, ...(stat.value?.by_policy || []).map((p) => p.count)))
const activityMax = computed(() =>
  Math.max(1, ...(stat.value?.activity || []).map((p) => p.count)))

/**
 * Seven slots, always.
 *
 * The query returns only days that have entries, so a fresh install
 * drew one bar across the whole card — which reads as "a huge day"
 * rather than "one day of data". Filling the missing days with zero
 * gives the bar its true width and shows the week it belongs to.
 */
const activityWeek = computed(() => {
  const got = Object.fromEntries((stat.value?.activity || []).map((d) => [d.date, d.count]))
  const out = []
  for (let i = 6; i >= 0; i--) {
    const d = new Date()
    d.setDate(d.getDate() - i)
    const key = d.toISOString().slice(0, 10)
    out.push({ date: key, count: got[key] || 0 })
  }
  return out
})
const deviceList = ref([])
const nodeList = ref([])
const pending = ref([])
const events = ref([])

/**
 * 180 seconds, which is REJECT_AFTER_TIME.
 *
 * WireGuard's session rules, from the protocol:
 *
 *   under ~120s   session valid, data sent as-is
 *   120–179s      data sent with a handshake interleaved
 *   over 180s     handshake required before any data
 *
 * So a 130-second-old handshake belongs to a peer that is working
 * perfectly. This was 120s and reported those as not live — a phone in
 * active use, shown as idle, for a third of every cycle.
 *
 * 180s is also what monitoring scripts in the wild alert on, for the
 * same reason: past it the session is genuinely gone.
 */
const LIVE_WINDOW_MS = 180 * 1000

function isLive (d) {
  if (!d.last_handshake_at) return false
  return Date.now() - new Date(d.last_handshake_at).getTime() < LIVE_WINDOW_MS
}

const liveCount = computed(() => deviceList.value.filter(isLive).length)
const activeCount = computed(() => deviceList.value.filter((d) => d.status === 'active').length)

/**
 * Registered, active, and bound to no policy.
 *
 * This state fails silently: the phone enrolled, the tunnel refuses it,
 * and nobody finds out until the user calls. It is the one number on
 * this page that is a to-do rather than a status.
 */
const unbound = computed(() =>
  deviceList.value.filter((d) => d.status === 'active' && !d.policy_name))

const gateway = computed(() => nodeList.value[0] || null)

/** Fast lookup for hiding numbers whose source did not load. */
const failedLabels = computed(() => new Set(failed.value.map((f) => f.label)))

const gatewayState = computed(() => {
  const n = gateway.value
  if (!n) return { tone: 'muted', label: '노드 없음', detail: '' }
  if (!n.last_report_at) {
    return { tone: 'warn', label: '보고 없음', detail: '게이트웨이가 한 번도 알려오지 않았습니다' }
  }
  if (!n.wg_interface_up) {
    return { tone: 'stop', label: '인터페이스 없음', detail: '터널이 서지 않았습니다' }
  }
  return {
    tone: 'good',
    label: n.wg_backend === 'kernel' ? '커널' : 'wireguard-go',
    detail: n.wg_backend === 'kernel' ? '' : '커널 모듈 없음 — 느립니다',
  }
})

function ago (ts) {
  if (!ts) return '—'
  const s = Math.floor((Date.now() - new Date(ts).getTime()) / 1000)
  if (s < 60) return `${s}초 전`
  if (s < 3600) return `${Math.floor(s / 60)}분 전`
  if (s < 86400) return `${Math.floor(s / 3600)}시간 전`
  return `${Math.floor(s / 86400)}일 전`
}

/**
 * Which calls failed, by name.
 *
 * The first version used allSettled and silently substituted an empty
 * array for anything that failed — so a controller that could not
 * answer produced a page reading "0 devices, no pending requests", which
 * is indistinguishable from a quiet hospital.
 *
 * A dashboard whose whole job is to say what is wrong must not be the
 * one screen that hides it.
 */
const failed = ref([])

async function load () {
  loading.value = true
  failed.value = []

  // Still settled rather than all — a broken nodes endpoint should not
  // hide a device list that loaded fine. The difference is that a
  // failure is now named on screen instead of becoming a zero.
  const [d, n, p, a] = await Promise.allSettled([
    devicesAPI.list(), nodesAPI.list(), reqAPI.list(), auditAPI.list({ limit: 5 }),
  ])

  const take = (res, label, pick) => {
    if (res.status === 'fulfilled') return pick(res.value)
    failed.value.push({ label, reason: String(res.reason?.message || res.reason) })
    return null
  }

  deviceList.value = take(d, '단말 목록', (v) => v.devices || []) ?? []
  nodeList.value = take(n, '노드 상태', (v) => v.nodes || []) ?? []
  pending.value = take(p, '승인 대기',
    (v) => (v.requests || []).filter((r) => r.status === 'pending')) ?? []
  events.value = take(a, '최근 기록', (v) => (v.entries || []).slice(0, 5)) ?? []

  loading.value = false
}

onMounted(() => { load(); loadStats() })
</script>

<template>
  <div class="page">
    <div class="page-head">
      <h1 class="h4 mb-0"> {{ tr("개요") }} </h1>
      <button class="btn btn-sm btn-outline-secondary" type="button" @click="load"> {{ tr("새로고침") }} </button>
    </div>

    <div v-if="loading" class="text-muted p-4"> {{ tr("불러오는 중…") }} </div>

    <!--
      Say which parts of this page are missing.
      
      Every number below is computed from what loaded. If a call failed,
      the number it feeds is not low — it is unknown, and a dashboard
      that prints 0 for unknown is worse than one that prints nothing.
    -->

    <template v-else>
    <!--
      Shown *alongside* the page, not instead of it.
      
      This was v-else-if, so one failing endpoint replaced everything —
      a nodes outage hid a device list that had loaded perfectly. The
      warning is meant to qualify the numbers, not to take their place.
    -->
    <div v-if="!loading && failed.length" class="alert alert-danger py-2 mb-3">
      <div class="fw-semibold small mb-1"> {{ tr("아래 항목을 불러오지 못했습니다 — 이 화면의 숫자는 불완전합니다") }} </div>
      <ul class="mb-0 small">
        <li v-for="f in failed" :key="f.label">
          {{ tr(f.label) }} — <span class="text-muted">{{ tr(f.reason) }}</span>
        </li>
      </ul>
    </div>
      <div class="row g-3 mb-3">
        <div class="col-6 col-lg-3">
          <div class="card h-100">
            <div class="card-body">
              <div class="text-muted small"> {{ tr("연결 중") }} </div>
              <div class="fs-3 fw-semibold">
                <template v-if="!failedLabels.has('단말 목록')">
                  {{ liveCount }}<span class="fs-6 text-muted"> {{ tr("/ {0}대", [activeCount]) }} </span>
                </template>
                <!-- Unknown is not zero. -->
                <span v-else class="text-muted">—</span>
              </div>
              <div class="text-muted" style="font-size:.75rem"> {{ tr("최근 3분 안에 통신한 단말") }} </div>
            </div>
          </div>
        </div>

        <div class="col-6 col-lg-3">
          <div class="card h-100">
            <div class="card-body">
              <div class="text-muted small"> {{ tr("문지기") }} </div>
              <div
                class="fs-5 fw-semibold"
                :class="{
                  'text-success': gatewayState.tone === 'good',
                  'text-danger': gatewayState.tone === 'stop',
                  'text-warning': gatewayState.tone === 'warn',
                  'text-muted': gatewayState.tone === 'muted',
                }"
              >{{ tr(gatewayState.label) }}</div>
              <div class="text-muted" style="font-size:.75rem">
                {{ tr(gatewayState.detail || (gateway ? tr('마지막 보고 {0}', [tr(ago(gateway.last_report_at))]) : '')) }}
              </div>
            </div>
          </div>
        </div>

        <div class="col-6 col-lg-3">
          <RouterLink :to="{ name: 'devices' }" class="text-decoration-none">
            <div class="card h-100" :class="{ 'border-danger': unbound.length }">
              <div class="card-body">
                <div class="text-muted small"> {{ tr("정책 없는 단말") }} </div>
                <div class="fs-3 fw-semibold" :class="unbound.length ? 'text-danger' : ''">
                  {{ unbound.length }}
                </div>
                <div class="text-muted" style="font-size:.75rem"> {{ tr("등록됐지만 연결이 거부됩니다") }} </div>
              </div>
            </div>
          </RouterLink>
        </div>

        <div class="col-6 col-lg-3">
          <RouterLink :to="{ name: 'enrollment-requests' }" class="text-decoration-none">
            <div class="card h-100" :class="{ 'border-primary': pending.length }">
              <div class="card-body">
                <div class="text-muted small"> {{ tr("승인 대기") }} </div>
                <div class="fs-3 fw-semibold">{{ pending.length }}</div>
                <div class="text-muted" style="font-size:.75rem"> {{ tr("폰에서 요청이 와 있습니다") }} </div>
              </div>
            </div>
          </RouterLink>
        </div>
      </div>

      <div class="row g-3">
        <div class="col-lg-7">
          <div class="card h-100">
            <div class="card-header py-2 d-flex justify-content-between align-items-center">
              <strong> {{ tr("단말") }} </strong>
              <RouterLink :to="{ name: 'devices' }" class="small text-decoration-none"> {{ tr("전체 보기 →") }} </RouterLink>
            </div>
            <div class="card-body p-0">
              <div v-if="!deviceList.length" class="p-4 text-center text-muted small"> {{ tr("등록된 단말이 없습니다.") }} </div>
              <table v-else class="table table-sm mb-0 align-middle">
                <tbody>
                  <tr v-for="d in deviceList.slice(0, 6)" :key="d.id">
                    <td class="ps-3">
                      <span class="fw-medium">{{ d.display_name }}</span>
                      <div class="text-muted font-monospace" style="font-size:.72rem">
                        {{ d.ipv4 || '—' }}
                      </div>
                    </td>
                    <td>
                      <span v-if="isLive(d)" class="badge bg-success-subtle text-success-emphasis"> {{ tr("통신 중") }} </span>
                      <span v-else-if="d.last_handshake_at" class="text-muted small">
                        {{ tr(ago(d.last_handshake_at)) }}
                      </span>
                      <!--
                        Never handshaked is not the same as idle: it is a
                        phone that enrolled and never brought a tunnel up.
                      -->
                      <span v-else class="text-muted small"> {{ tr("연결한 적 없음") }} </span>
                      <!--
                        The relay works and is slower, so a phone using
                        it is not a fault — but "why is only this one
                        slow" needs somewhere to be answered.
                      -->
                      <span
                        v-if="d.via_relay"
                        class="badge bg-info-subtle text-info-emphasis ms-1"
                        :title="tr(&quot;UDP 가 막힌 망이라 우회로로 붙었습니다&quot;)"
                      > {{ tr("우회") }} </span>
                    </td>
                    <td class="text-end pe-3">
                      <span v-if="d.policy_name" class="small">{{ d.policy_name }}</span>
                      <span v-else class="badge bg-danger-subtle text-danger-emphasis"> {{ tr("정책 없음") }} </span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div class="col-lg-5">
          <div class="card h-100">
            <div class="card-header py-2 d-flex justify-content-between align-items-center">
              <strong> {{ tr("최근 기록") }} </strong>
              <RouterLink :to="{ name: 'audit' }" class="small text-decoration-none"> {{ tr("감사 로그 →") }} </RouterLink>
            </div>
            <div class="card-body p-0">
              <div v-if="!events.length" class="p-4 text-center text-muted small"> {{ tr("아직 기록이 없습니다.") }} </div>
              <ul v-else class="list-group list-group-flush">
                <li v-for="e in events" :key="e.id" class="list-group-item py-2">
                  <div class="small" :class="actionTone(e.action)">{{ tr(actionLabel(e.action)) }}</div>
                  <div v-if="eventSubject(e)" class="text-muted" style="font-size:.74rem">
                    {{ eventSubject(e) }}
                  </div>
                  <div class="text-muted" style="font-size:.72rem">
                    {{ tr(ago(e.created_at)) }}<span v-if="e.actor_email"> · {{ e.actor_email }}</span>
                  </div>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </template>
  
      <!--
        Charts, drawn as inline SVG.
        No chart library: four small pictures do not justify a
        dependency, and hand-drawn SVG inherits the console's own
        colours instead of fighting a library's theme.
      -->
      <div v-if="stat" class="row g-3 mt-1">
        <div class="col-md-6">
          <div class="card h-100">
            <div class="card-header py-2 d-flex justify-content-between align-items-center">
              <strong> {{ tr("연결 추이") }} </strong>
              <span class="text-muted" style="font-size:.76rem"> {{ tr("최근 24시간 · 5분 간격") }} </span>
            </div>
            <div class="card-body">
              <template v-if="connPath">
                <svg viewBox="0 0 300 60" class="chart" preserveAspectRatio="none">
                  <path
                    :d="connPath" fill="none" stroke="var(--accent)"
                    stroke-width="1.6" vector-effect="non-scaling-stroke"
                  />
                </svg>
                <div class="d-flex justify-content-between text-muted" style="font-size:.74rem">
                  <span> {{ tr("24시간 전") }} </span>
                  <span> {{ tr("최대 {0}대", [connMax]) }} </span>
                  <span> {{ tr("지금") }} </span>
                </div>
              </template>
              <div v-else-if="stat.connections?.length === 1" class="text-muted small"> {{ tr("방금 첫 표본이 쌓였습니다 — 지금 연결 {0}대. 5분마다 한 점씩 쌓여 선이 됩니다.", [stat.connections[0].connected]) }} </div>
              <div v-else class="text-muted small"> {{ tr("아직 표본이 없습니다. 문지기가 보고를 시작하면 5분마다 한 점씩 쌓입니다.") }} </div>
            </div>
          </div>
        </div>

        <div class="col-md-6">
          <div class="card h-100">
            <div class="card-header py-2"><strong> {{ tr("정책별 단말") }} </strong></div>
            <div class="card-body">
              <div v-if="!stat.by_policy?.length" class="text-muted small"> {{ tr("등록된 단말이 없습니다.") }} </div>
              <div v-for="p in stat.by_policy" :key="p.name" class="mb-2">
                <div class="d-flex justify-content-between" style="font-size:.82rem">
                  <span :class="p.name === '(정책 없음)' ? 'text-warning' : ''">{{ p.name === '(정책 없음)' ? tr(p.name) : p.name }}</span>
                  <span class="text-muted"> {{ tr("{0}대", [p.count]) }} </span>
                </div>
                <div class="bar-track">
                  <div
                    class="bar-fill"
                    :class="{ warn: p.name === '(정책 없음)' }"
                    :style="{ width: barWidth(p.count) }"
                  />
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="col-md-6">
          <div class="card h-100">
            <div class="card-header py-2 d-flex justify-content-between align-items-center">
              <strong> {{ tr("최근 활동") }} </strong>
              <span class="text-muted" style="font-size:.76rem"> {{ tr("감사 로그 · 7일") }} </span>
            </div>
            <div class="card-body">
              <svg viewBox="0 0 300 62" class="chart-lg" preserveAspectRatio="none">
                <polyline
                  v-if="activityPath"
                  :points="activityDots.map((p) => `${p.cx},${p.cy}`).join(' ')"
                  fill="none" stroke="var(--accent)" stroke-width="1.6"
                  vector-effect="non-scaling-stroke"
                />
                <circle
                  v-for="(p, i) in activityDots" :key="i"
                  :cx="p.cx" :cy="p.cy" r="2.5" fill="var(--accent)"
                />
              </svg>
              <div class="d-flex justify-content-between text-muted" style="font-size:.66rem">
                <span v-for="(p, i) in activityDots" :key="i">{{ tr(p.label) }}</span>
              </div>
            </div>
          </div>
        </div>

        <div class="col-md-6">
          <div class="card h-100">
            <div class="card-header py-2 d-flex justify-content-between align-items-center">
              <strong> {{ tr("전송량 상위") }} </strong>
              <span class="text-muted" style="font-size:.76rem"> {{ tr("문지기 재시작 이후 누적") }} </span>
            </div>
            <div class="card-body">
              <div v-if="!stat.top_talkers?.length" class="text-muted small"> {{ tr("아직 오간 트래픽이 없습니다.") }} </div>
              <table v-else class="table table-sm mb-0">
                <tbody>
                  <tr v-for="t in stat.top_talkers" :key="t.ipv4 || t.name">
                    <td class="small">
                      {{ t.name }}
                      <span v-if="t.ipv4" class="text-muted font-monospace ms-1" style="font-size:.72rem">
                        {{ t.ipv4 }}
                      </span>
                    </td>
                    <td class="small text-end text-muted">
                      ↓ {{ bytes(t.rx) }} &nbsp; ↑ {{ bytes(t.tx) }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
</div>
</template>

<style scoped>
.page-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1rem;
}
.chart { width: 100%; height: 60px; }
.chart-lg { width: 100%; height: 62px; }
.bar-track { height: 6px; border-radius: 3px; background: var(--line); overflow: hidden; }
.bar-fill { height: 100%; background: var(--accent); border-radius: 3px; }
.bar-fill.warn { background: var(--warn); }
.day-bar { background: var(--accent); border-radius: 3px 3px 0 0; margin: 0 auto 4px; width: 60%; }
</style>

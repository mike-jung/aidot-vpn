<script setup>
import { translate as tr, localeTag } from '../i18n/index.js'
// eslint-disable-next-line no-undef
const appVersion = __APP_VERSION__
// Nodes list — Phase 4b. The shape is identical to DevicesView so we'll
// extract a shared <ResourceTable/> component when we wire it up.
import { ref, onMounted } from 'vue'
import { nodes as nodesAPI, APIError } from '@/api/client.js'

const items = ref([])
const loading = ref(true)
const error = ref(null)

// The gateway is alive when its agent reported within the last minute
// (it reports every fifteen seconds) and the interface is up.
function alive (n) {
  if (!n.last_report_at) return false
  return Date.now() - new Date(n.last_report_at).getTime() < 60_000 && n.wg_interface_up !== false
}
function ago (t) {
  if (!t) return '한 번도 없음'
  const s = Math.max(0, (Date.now() - new Date(t).getTime()) / 1000)
  if (s < 60) return `${Math.round(s)}초 전`
  if (s < 3600) return `${Math.floor(s / 60)}분 전`
  if (s < 86400) return `${Math.floor(s / 3600)}시간 전`
  return `${Math.floor(s / 86400)}일 전`
}
function wgEndpoint (n) {
  const e = (n.public_endpoints || []).find((x) => x.mode === 'wg') || (n.public_endpoints || [])[0]
  return e ? `${e.public_host}:${e.public_port}` : '-'
}
function problems (n) {
  const out = []
  if (!alive(n)) out.push('에이전트 보고가 끊겼습니다 — docker compose logs gateway-agent')
  if (n.wg_interface_up === false) out.push('wg0 이 내려가 있습니다 — docker compose logs wg-data-node')
  if (n.responder_up === false) out.push('응답 서버 없음 — 10.78.0.1:8080 이 답하지 않습니다')
  if (n.agent_version && n.agent_version !== appVersion) out.push(`에이전트 ${n.agent_version} ≠ 프로젝트 ${appVersion} — npm start 로 재빌드`)
  return out
}
const auto = ref(null)
onMounted(() => { auto.value = setInterval(load, 15_000) })
import { onBeforeUnmount } from 'vue'
onBeforeUnmount(() => clearInterval(auto.value))

async function load () {
  loading.value = true
  error.value = null
  try {
    const resp = await nodesAPI.list()
    items.value = resp.nodes || []
  } catch (err) {
    if (err instanceof APIError) {
      error.value = `${err.status}: ${err.message}`
    } else {
      error.value = err.message || String(err)
    }
  } finally {
    loading.value = false
  }
}

function statusBadge (s) {
  if (s === 'active') return 'bg-success'
  if (s === 'maintenance') return 'bg-warning-subtle text-warning-emphasis'
  if (s === 'draining') return 'bg-secondary'
  return 'bg-danger'
}

onMounted(load)
</script>

<template>
  <div>
    <div class="d-flex justify-content-between align-items-center mb-3">
      <div>
        <h1 class="h4 mb-0"> {{ tr("문지기") }} </h1>
        <div class="text-muted" style="font-size:.85rem"> {{ tr("폰이 붙는 WireGuard 게이트웨이. 병원당 한 대, 이중화하면 두 대.") }} </div>
      </div>
      <button class="btn btn-sm btn-outline-secondary" type="button" @click="load"> {{ tr("새로고침") }} </button>
    </div>

    <div v-if="error" class="alert alert-danger">{{ tr(error) }}</div>
    <div v-else-if="loading && !items.length" class="text-muted"> {{ tr("불러오는 중…") }} </div>
    <div v-else-if="!items.length" class="text-muted"> {{ tr("등록된 문지기가 없습니다.") }} </div>

    <!--
      One card per gateway, not a table row. There is one gateway in a
      hospital, two with HA; a table with one row hides the thing it is
      about. The card answers the five questions an admin actually
      asks: is it up, where do phones connect, how many are on it now,
      is anything wrong, and what is its tunnel address.
    -->
    <div v-for="n in items" :key="n.id" class="card mb-3 gw-card">
      <div class="card-body">
        <div class="d-flex align-items-start justify-content-between flex-wrap gap-3">
          <div>
            <div class="d-flex align-items-center gap-2">
              <span class="gw-dot" :class="alive(n) ? 'on' : 'off'" />
              <span class="fs-5 fw-bold">{{ tr(alive(n) ? '살아 있음' : '응답 없음') }}</span>
              <span class="text-muted small"> {{ tr("마지막 보고 {0}", [tr(ago(n.last_report_at))]) }} </span>
            </div>
            <div class="text-muted small mt-1">
              {{ n.hostname }} · {{ tr(n.wg_backend === 'kernel' ? '커널 모듈' : n.wg_backend === 'userspace' ? 'wireguard-go' : '터널 방식 미확인') }}
              <span v-if="n.agent_version"> {{ tr("· 에이전트 {0}", [n.agent_version]) }} </span>
            </div>
          </div>
          <div class="text-end">
            <div class="display-6 fw-bold lh-1">{{ n.online_devices ?? '-' }}<span class="fs-6 text-muted fw-normal"> {{ tr("/ {0}대", [n.total_devices ?? '-']) }} </span></div>
            <div class="text-muted small"> {{ tr("지금 붙어 있는 폰") }} <span class="text-muted"> {{ tr("(2분 내 핸드셰이크)") }} </span></div>
          </div>
        </div>

        <hr />

        <div class="row g-3">
          <div class="col-md-4">
            <div class="gw-k"> {{ tr("폰이 붙는 주소") }} </div>
            <code class="fs-6">{{ wgEndpoint(n) }}</code>
            <div class="text-muted small"> {{ tr("UDP · 방화벽에서 열어야 하는 문") }} </div>
          </div>
          <div class="col-md-4">
            <div class="gw-k"> {{ tr("터널 안 주소") }} </div>
            <code class="fs-6">{{ n.tunnel_address }}</code>
            <div class="text-muted small"> {{ tr("시험 대상 :8080 · 컨트롤러 중계 :10030") }} </div>
          </div>
          <div class="col-md-4">
            <div class="gw-k"> {{ tr("응답 서버") }} </div>
            <span v-if="n.responder_up" class="badge bg-success-subtle text-success-emphasis"> {{ tr("8080 · 10030 대기 중") }} </span>
            <span v-else-if="n.responder_up === false" class="badge bg-danger-subtle text-danger-emphasis"> {{ tr("없음") }} </span>
            <span v-else class="text-muted"> {{ tr("아직 보고 없음") }} </span>
          </div>
        </div>

        <div v-if="problems(n).length" class="alert alert-warning py-2 mt-3 mb-0 small">
          <div v-for="p in problems(n)" :key="p">! {{ tr(p) }}</div>
        </div>
        <div v-if="n.public_key" class="text-muted mt-2" style="font-size:.75rem"> {{ tr("공개키") }} <code>{{ n.public_key.slice(0, 16) }}…</code> {{ tr("— 폰들이 이 키로 문지기를 알아봅니다") }} </div>
      </div>
    </div>
  </div>
</template>

<style>
.gw-dot { display: inline-block; width: 12px; height: 12px; border-radius: 50%; }
.gw-dot.on { background: var(--good); box-shadow: 0 0 0 4px var(--good-soft); }
.gw-dot.off { background: var(--bad); box-shadow: 0 0 0 4px var(--bad-soft); }
.gw-k { color: var(--text-2); font-weight: 600; font-size: .8rem; margin-bottom: .2rem; }
</style>

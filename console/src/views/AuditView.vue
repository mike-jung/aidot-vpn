<script setup>
import { translate as tr, localeTag } from '../i18n/index.js'
/**
 * 동작 코드 → 우리말.
 *
 * The table showed `policy.assign` and left the reader to guess. An
 * audit log is read by someone asking "what happened to this device
 * yesterday", often under time pressure, and a machine token is a
 * lookup they should not have to do. The code stays visible in the
 * detail dialog — it is what the API and any export use.
 */
const ACTIONS = {
  'admin.login': ['관리자 로그인', 'ok'],
  'admin.login_failed': ['관리자 로그인 실패', 'bad'],
  'admin.logout': ['관리자 로그아웃', 'muted'],
  'admin.password_changed': ['관리자 비밀번호 변경', 'warn'],
  'device.register': ['단말 등록', 'ok'],
  'device.revoke': ['단말 폐기', 'bad'],
  'device.rotate_key': ['단말 키 교체', 'warn'],
  'policy.create': ['정책 만들기', 'ok'],
  'policy.update': ['정책 수정', 'warn'],
  'policy.delete': ['정책 삭제', 'bad'],
  'policy.assign': ['정책을 단말에 적용', 'ok'],
  'policy.transport': ['접속 방식 변경', 'warn'],
  // The list is the whole set the server can write, checked against the
  // Go source rather than remembered: an action with no entry falls
  // back to its machine code, which is exactly the thing this table
  // exists to avoid, and a missing one is invisible until it happens.
  'policy.allowed_ip.add': ['갈 수 있는 주소 추가', 'ok'],
  'policy.allowed_ip.remove': ['갈 수 있는 주소 삭제', 'warn'],
  'policy.hostname.add': ['호스트 이름 추가', 'ok'],
  'policy.hostname.remove': ['호스트 이름 삭제', 'warn'],
  'policy.virtual_host.add': ['가상 주소 추가', 'ok'],
  'policy.virtual_host.remove': ['가상 주소 삭제', 'warn'],
  'policy.settings.update': ['정책 설정 변경', 'warn'],
  'device.app_filter.update': ['앱 필터 변경', 'warn'],
}
const actionLabel = (a) => ACTIONS[a]?.[0] || a
const actionTone = (a) => ({
  ok: 'bg-success-subtle text-success-emphasis',
  warn: 'bg-warning-subtle text-warning-emphasis',
  bad: 'bg-danger-subtle text-danger-emphasis',
  muted: 'bg-secondary-subtle text-secondary-emphasis',
}[ACTIONS[a]?.[1] || 'muted'])

/** Who did it, in words rather than a UUID. */
function actorLabel (e) {
  if (e.actor_kind === 'system') return '시스템'
  if (e.actor_kind === 'node') return '문지기'
  if (e.actor_kind === 'device') return '단말'
  return e.details?.email || e.details?.actor_email || '관리자'
}

/** Where it came from, when the entry recorded it. */
function actorWhere (e) {
  const d = e.details || {}
  return d.ip || d.actor_ip || d.endpoint || ''
}

/** What it was done to. */
function targetLabel (e) {
  const d = e.details || {}
  return d.device_name || d.display_name || d.policy_name || d.name ||
    (e.target_kind === 'device' ? '단말' : e.target_kind === 'policy' ? '정책' :
      e.target_kind === 'admin' ? '관리자' : e.target_kind || '-')
}
function targetWhere (e) {
  const d = e.details || {}
  return d.ipv4 || d.device_ipv4 || d.target_ip || d.cidr || ''
}

/**
 * Paging and period.
 *
 * The table fetched a hundred rows and stopped: on an installation with
 * any history that is a window onto the last hour, and the question an
 * audit log is kept for — "what happened on the day of the incident" —
 * had no way to be asked at all.
 *
 * Cursor paging rather than offset, because the log only grows at the
 * head: an offset page shifts under the reader as entries arrive, while
 * a cursor (the seq of the last row seen) keeps a page stable.
 */
const pageSize = 50
const cursor = ref(0)
const cursors = ref([])        // seq to go back to, per page
const from = ref('')
const to = ref('')
const hasMore = ref(false)

const pageLabel = computed(() =>
  cursors.value.length ? `${cursors.value.length + 1}쪽` : '최신 쪽')

function applyPeriod () { cursor.value = 0; cursors.value = []; load() }
function clearPeriod () { from.value = ''; to.value = ''; applyPeriod() }
function nextPage () {
  const last = entries.value[entries.value.length - 1]
  if (!last) return
  cursors.value.push(cursor.value)
  cursor.value = last.seq
  load()
}
function prevPage () {
  cursor.value = cursors.value.pop() || 0
  load()
}

const detail = ref(null)

// 관리자별 추적 — one person's actions, reached by clicking the actor.
//
// An audit log that cannot be read per actor answers "what happened"
// but never "who has been doing this". The name is already on screen,
// so clicking it is the shortest path; a separate admin screen would be
// a second place to look for the same answer.
const traceToneClass = (t) => ({
  ok: 'text-success', warn: 'text-warning', bad: 'text-danger', muted: 'text-muted',
}[t] || '')

const actorTrace = ref(null)
const actorEvents = ref([])
const actorPerPage = 8
const actorPage = ref(1)
const actorPages = computed(() =>
  Math.max(1, Math.ceil(actorEvents.value.length / actorPerPage)))
const actorPaged = computed(() =>
  actorEvents.value.slice((actorPage.value - 1) * actorPerPage, actorPage.value * actorPerPage))
const actorBusy = ref(false)
async function openActor (e) {
  if (!e.actor_id) return
  actorTrace.value = e
  actorEvents.value = []
  actorBusy.value = true
  try {
    const r = await traceAPI.actor(e.actor_id)
    actorEvents.value = (r.events || []).slice().reverse()
    actorPage.value = 1
  } catch {
    actorEvents.value = []
  } finally {
    actorBusy.value = false
  }
}

// AuditView shows recent audit log entries plus a "verify hash chain"
// button that walks the entire chain and reports any tampering.
//
// We render details as a collapsible <pre> per row because audit details
// are JSON of varying shape. Forcing every column into a fixed header
// would lose information.
import { ref, computed, onMounted } from 'vue'
import { trace as traceAPI } from '@/api/client.js'
import AidotDialog from '../components/AidotDialog.vue'
import { audit as auditAPI, APIError } from '@/api/client.js'

const entries = ref([])
const loading = ref(true)
const error = ref(null)
const verifying = ref(false)
const verifyResult = ref(null)

async function load () {
  loading.value = true
  error.value = null
  try {
    const resp = await auditAPI.list({ limit: pageSize, cursor: cursor.value, from: from.value, to: to.value })
    entries.value = resp.entries || []
    // A full page means there is probably another; the API does not
    // report a total, and counting one would cost a second query on
    // every load for information the reader does not need.
    hasMore.value = entries.value.length === pageSize
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

async function verifyChain () {
  verifying.value = true
  verifyResult.value = null
  try {
    const resp = await auditAPI.verifyChain()
    verifyResult.value = {
      ok: resp.ok === true,
      lastSeq: resp.last_seq,
      brokenAtSeq: resp.broken_at_seq,
    }
  } catch (err) {
    verifyResult.value = { ok: false, error: err.message }
  } finally {
    verifying.value = false
  }
}


onMounted(load)
</script>

<template>
  <div>
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h1 class="h3 mb-0"> {{ tr("감사 로그") }} </h1>
      <div class="d-flex gap-2">
        <button
          class="btn btn-sm btn-outline-primary"
          type="button"
          :disabled="verifying"
          @click="verifyChain"
        >
          {{ tr(verifying ? '검증 중...' : '해시 체인 검증') }}
        </button>
        <button
          class="btn btn-sm btn-outline-secondary"
          type="button"
          :disabled="loading"
          @click="load"
        >
          {{ tr(loading ? '로딩...' : '새로고침') }}
        </button>
      </div>
    </div>

    <!-- Verification status -->
    <div
      v-if="verifyResult"
      class="alert"
      :class="verifyResult.ok ? 'alert-success' : 'alert-danger'"
      role="alert"
    >
      <template v-if="verifyResult.ok"> {{ tr("✓ 해시 체인이 일치합니다 (마지막 seq: {0}).", [verifyResult.lastSeq]) }} </template>
      <template v-else-if="verifyResult.brokenAtSeq"> {{ tr("✗ 해시 체인이 손상되었습니다 (seq: {0}). 즉시 운영 팀에 보고하십시오.", [verifyResult.brokenAtSeq]) }} </template>
      <template v-else> {{ tr("✗ 검증 실패: {0}", [verifyResult.error || '알 수 없는 오류']) }} 
      </template>
    </div>

    <!-- Error -->
    <div v-if="error" class="alert alert-danger">{{ tr(error) }}</div>

    <!-- Loading -->
    <div v-else-if="loading" class="text-center py-5">
      <div class="spinner-border text-primary"></div>
    </div>

    <!-- Empty -->
    <div
      v-else-if="!entries.length"
      class="text-center py-5 empty-state"
    >
      <p class="text-muted mb-0"> {{ tr("감사 로그 항목이 없습니다.") }} </p>
    </div>

    <!-- Entries -->
    <div v-else class="card">
      <div class="d-flex flex-wrap align-items-end gap-2 mb-3">
          <div>
            <label class="form-label small text-muted mb-1"> {{ tr("시작일") }} </label>
            <input v-model="from" type="date" class="form-control form-control-sm" />
          </div>
          <div>
            <label class="form-label small text-muted mb-1"> {{ tr("종료일") }} </label>
            <input v-model="to" type="date" class="form-control form-control-sm" />
          </div>
          <button class="btn btn-sm btn-primary" type="button" @click="applyPeriod"> {{ tr("조회") }} </button>
          <button v-if="from || to" class="btn btn-sm btn-outline-secondary" type="button" @click="clearPeriod"> {{ tr("기간 해제") }} </button>
          <div class="ms-auto text-muted small">
            {{ tr(pageLabel) }}
          </div>
        </div>

        <div class="table-responsive">
        <table class="table mb-0 align-middle">
          <thead class="table-light">
            <tr>
              <th style="width: 70px;"> {{ tr("번호") }} </th>
              <th style="width: 150px;"> {{ tr("시간") }} </th>
              <th style="width: 190px;"> {{ tr("누가") }} </th>
              <th style="width: 200px;"> {{ tr("무엇을") }} </th>
              <th> {{ tr("대상") }} </th>
              <th style="width: 60px;" class="text-end"> {{ tr("상세") }} </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="e in entries" :key="e.seq">
              <td class="font-monospace">{{ e.seq }}</td>
              <td class="small">{{ new Date(e.occurred_at).toLocaleString(localeTag) }}</td>
                <td class="small">
                  <button
                    v-if="e.actor_id"
                    class="btn btn-link btn-sm p-0 text-start"
                    type="button"
                    @click="openActor(e)"
                  >{{ tr(actorLabel(e)) }}</button>
                  <span v-else>{{ tr(actorLabel(e)) }}</span>
                  <div v-if="actorWhere(e)" class="text-muted font-monospace" style="font-size:.72rem">
                    {{ actorWhere(e) }}
                  </div>
                </td>
                <td>
                  <span class="badge" :class="actionTone(e.action)">{{ tr(actionLabel(e.action)) }}</span>
                </td>
                <td class="small">
                  {{ tr(targetLabel(e)) }}
                  <div v-if="targetWhere(e)" class="text-muted font-monospace" style="font-size:.72rem">
                    {{ targetWhere(e) }}
                  </div>
                </td>
                <td class="text-end">
                  <button class="btn btn-sm btn-link p-0" type="button" @click="detail = e"> {{ tr("보기") }} </button>
                </td>
              </tr>
          </tbody>
        </table>

        <div class="d-flex justify-content-between align-items-center mt-2">
          <button
            class="btn btn-sm btn-outline-secondary"
            type="button" :disabled="!cursors.length" @click="prevPage"
          > {{ tr("← 최신 쪽") }} </button>
          <span class="text-muted small"> {{ tr("{0}건 표시", [entries.length]) }} </span>
          <button
            class="btn btn-sm btn-outline-secondary"
            type="button" :disabled="!hasMore" @click="nextPage"
          > {{ tr("이전 기록 →") }} </button>
        </div>
      </div>
    </div>
  </div>

    <!-- 관리자별 추적: 감사 로그에서 액터를 눌러 그 사람의 행적을 봅니다. -->
    <AidotDialog
      :open="!!actorTrace"
      :title="tr(actorTrace ? '추적 — ' + actorLabel(actorTrace) : '추적')"
      confirm-only
      @update:open="(v) => { if (!v) actorTrace = null }"
      @confirm="actorTrace = null"
    >
      <div v-if="actorBusy" class="text-muted small"> {{ tr("불러오는 중…") }} </div>
      <div v-else-if="!actorEvents.length" class="text-muted small"> {{ tr("기록이 없습니다.") }} </div>
      <div v-else class="actor-scroll">
      <table class="table table-sm align-middle mb-0">
        <tbody>
          <tr v-for="(e, i) in actorPaged" :key="i">
            <td class="small text-muted" style="width:11rem">{{ new Date(e.at).toLocaleString(localeTag) }}</td>
            <td>
              <span :class="traceToneClass(e.tone)">{{ tr(e.label) }}</span>
              <div v-if="e.details" class="text-muted" style="font-size:.74rem">
                <span v-for="(v, k) in e.details" :key="k" class="me-2">
                  <template v-if="v !== '' && v !== null">{{ tr(k) }} <code>{{ v }}</code></template>
                </span>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      </div>
      <div v-if="actorPages > 1" class="d-flex justify-content-between align-items-center mt-2">
        <button class="btn btn-sm btn-outline-secondary" type="button"
                :disabled="actorPage <= 1" @click="actorPage--"> {{ tr("← 이전") }} </button>
        <span class="text-muted small"> {{ tr("{0} / {1}쪽 · {2}건", [actorPage, actorPages, actorEvents.length]) }} </span>
        <button class="btn btn-sm btn-outline-secondary" type="button"
                :disabled="actorPage >= actorPages" @click="actorPage++"> {{ tr("다음 →") }} </button>
      </div>
    </AidotDialog>

    <!--
      One entry in full: the table answers "what happened", this answers
      "what exactly" — including the machine code an export or an API
      caller uses, and every field the entry carried.
    -->
    <AidotDialog
      :open="!!detail"
      :title="tr(detail ? actionLabel(detail.action) : '')"
      confirm-only
      @update:open="(v) => { if (!v) detail = null }"
      @confirm="detail = null"
    >
      <template v-if="detail">
        <div class="audit-grid">
          <div class="audit-k"> {{ tr("시간") }} </div>
          <div>{{ new Date(detail.occurred_at).toLocaleString(localeTag) }}</div>
          <div class="audit-k"> {{ tr("동작") }} </div>
          <div>{{ tr(actionLabel(detail.action)) }} <code class="text-muted ms-1">{{ detail.action }}</code></div>
          <div class="audit-k"> {{ tr("누가") }} </div>
          <div>{{ tr(actorLabel(detail)) }} <code v-if="actorWhere(detail)" class="ms-1">{{ actorWhere(detail) }}</code></div>
          <div class="audit-k"> {{ tr("대상") }} </div>
          <div>{{ tr(targetLabel(detail)) }} <code v-if="targetWhere(detail)" class="ms-1">{{ targetWhere(detail) }}</code></div>
          <div class="audit-k"> {{ tr("번호") }} </div>
          <div><code>{{ detail.seq }}</code>
            <span class="text-muted small ms-1"> {{ tr("— 빠진 번호가 있으면 기록이 지워진 것입니다") }} </span></div>
        </div>
        <div v-if="detail.details && Object.keys(detail.details).length" class="mt-3">
          <div class="audit-k mb-1"> {{ tr("기록된 값") }} </div>
          <table class="table table-sm mb-0">
            <tbody>
              <tr v-for="(v, k) in detail.details" :key="k">
                <td class="text-muted" style="width:9rem">{{ tr(k) }}</td>
                <td><code>{{ typeof v === 'object' ? JSON.stringify(v) : v }}</code></td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>
    </AidotDialog>

</template>

<style scoped>
.audit-grid { display: grid; grid-template-columns: 5rem 1fr; gap: .5rem .75rem; align-items: baseline; font-size: .9rem; }
.actor-scroll { height: 20rem; overflow-y: auto; }
.audit-k { color: var(--text-2); font-weight: 600; }
/* The empty state used Bootstrap's bg-white, which is a white slab in
   a dark console. These are the console's own tokens, so it follows the
   theme instead of fighting it. */
.empty-state {
  background: var(--panel, #111827);
  border: 1px solid var(--line, rgba(255,255,255,.08));
  border-radius: .5rem;
  color: var(--text-2, #9aa7c2);
}
</style>

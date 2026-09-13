<script setup>
import { translate as tr, localeTag } from '../i18n/index.js'
// Devices list view. Talks to /api/devices. Each row shows device
// metadata; a Revoke button on each row triggers the device.revoke RPC.
//
// Three states are handled explicitly:
//   - loading (spinner)
//   - error (alert)
//   - empty (helpful empty-state)
// …because skipping any of these in real software ends up looking
// broken to the user the first time the API is slow or returns nothing.
import { ref, onMounted, computed, watch } from 'vue'
import AidotDialog from '../components/AidotDialog.vue'
import { devices as devicesAPI, policies as policiesAPI, groups as groupsAPI,
  expiry as expiryAPI, trace as traceAPI, APIError } from '@/api/client.js'

const items = ref([])
const loading = ref(true)
const error = ref(null)
const filter = ref('')


const filtered = computed(() => {
  const q = filter.value.trim().toLowerCase()
  if (!q) return items.value
  return items.value.filter((d) => {
    return (d.display_name || '').toLowerCase().includes(q)
      || (d.platform || '').toLowerCase().includes(q)
      || (d.id || '').toLowerCase().includes(q)
  })
})
/**
 * Paging, in the browser.
 *
 * The device list arrives whole — a fleet is hundreds, not millions —
 * so paging here keeps the search instant and needs no API change. If a
 * deployment ever outgrows that, the cursor already exists on the audit
 * endpoint and the same shape moves server-side.
 */
const perPage = 25
const page = ref(1)
const pageCount = computed(() => Math.max(1, Math.ceil(filtered.value.length / perPage)))
const paged = computed(() =>
  filtered.value.slice((page.value - 1) * perPage, page.value * perPage))
watch(filtered, () => { page.value = 1 })

async function loadPolicies () {
  try {
    policyList.value = (await policiesAPI.list()).policies || []
  } catch {
    // The device list is still useful without it; the assign dialog
    // reports the failure when it is opened.
    policyList.value = []
  }
}

async function load () {
  loading.value = true
  error.value = null
  try {
    const resp = await devicesAPI.list()
    items.value = resp.devices || []
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

// prompt() and alert() before. Both are browser chrome — the wrong
// register for a destructive action, and Chrome suppresses repeats, so a
// confirmation could silently never appear.
// Policy assignment.
//
// The controller has had PUT /devices/{id}/policy since 0.10.0 and the
// API client has had assignToDevice since 1.1.0. Nothing called it —
// binding a device to a policy was only possible at approval time, and
// changing one afterwards was not possible at all from the console.
//
// The device list is where that decision belongs: it is the screen that
// shows which policy a device has, so it should be the screen that
// changes it.
const policyList = ref([])
const assigning = ref(null)
const assignChoice = ref('')
const assignBusy = ref(false)
const assignErr = ref('')

function openAssign (d) {
  assigning.value = d
  // Preselect what the device already has, so the dialog opens showing
  // the truth rather than a blank that looks like "no policy".
  assignChoice.value = d.policy_id || ''
  assignErr.value = ''
}

async function confirmAssign () {
  assignBusy.value = true
  assignErr.value = ''
  try {
    await policiesAPI.assignToDevice(assigning.value.id, assignChoice.value)
    assigning.value = null
    await load()
  } catch (e) {
    assignErr.value = e instanceof APIError ? `${e.status} ${e.message}` : String(e)
  } finally {
    assignBusy.value = false
  }
}

const revoking = ref(null)
const revokeReason = ref('')
const revokeBusy = ref(false)
const revokeErr = ref('')

function onRevoke (d) {
  revoking.value = d
  revokeReason.value = ''
  revokeErr.value = ''
}

async function confirmRevoke () {
  revokeBusy.value = true
  revokeErr.value = ''
  try {
    await devicesAPI.revoke(revoking.value.id, revokeReason.value || 'admin revocation')
    revoking.value = null
    await load()
  } catch (err) {
    revokeErr.value = err.message || '폐기하지 못했습니다'
  } finally {
    revokeBusy.value = false
  }
}

// ----- Per-app split tunnel (Phase 8) -----
//
// We edit a device's app filter in a modal so the table view stays
// uncluttered. The modal binds to a single editing target at a time
// (`appFilterTarget`) so opening it on a second device cleanly
// resets state.
const appFilterTarget = ref(null)        // the device being edited, or null
const appFilterMode = ref('off')         // 'off' | 'include' | 'exclude'
const appFilterPackagesText = ref('')    // newline-separated for editing
const appFilterSaving = ref(false)
const appFilterError = ref(null)

function openAppFilter (d) {
  appFilterTarget.value = d
  appFilterMode.value = d.app_filter_mode || 'off'
  appFilterPackagesText.value = (d.app_filter_packages || []).join('\n')
  appFilterError.value = null
}

function closeAppFilter () {
  appFilterTarget.value = null
  appFilterError.value = null
}

const appFilterPackagesParsed = computed(() => {
  if (appFilterMode.value === 'off') return []
  // One package per line; ignore blank lines.
  return appFilterPackagesText.value
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
})

async function saveAppFilter () {
  const target = appFilterTarget.value
  if (!target) return
  appFilterSaving.value = true
  appFilterError.value = null
  try {
    const updated = await devicesAPI.updateAppFilter(
      target.id,
      appFilterMode.value,
      appFilterPackagesParsed.value,
    )
    // Patch the row in place so the table reflects the new mode/packages
    // immediately without a full reload.
    const i = items.value.findIndex((x) => x.id === target.id)
    if (i >= 0 && updated) items.value[i] = updated
    closeAppFilter()
  } catch (err) {
    appFilterError.value = err.message || String(err)
  } finally {
    appFilterSaving.value = false
  }
}

function appFilterBadge (mode) {
  switch (mode) {
    case 'include': return 'bg-info-subtle text-info-emphasis'
    case 'exclude': return 'bg-warning-subtle text-warning-emphasis'
    default: return 'bg-secondary-subtle text-secondary-emphasis'
  }
}

function appFilterLabel (mode) {
  switch (mode) {
    case 'include': return '허용 앱만'
    case 'exclude': return '제외 앱'
    default: return '전체'
  }
}

// Status values are the wire strings from the controller: 'active',
// 'pending_attest', 'suspended', 'revoked'.
//
// These used to be compared against proto-style names
// ('DEVICE_STATUS_ACTIVE'), which the API has never sent. Every switch
// fell through to its default, so every device rendered a grey badge
// containing the raw string — and `d.status !== 'DEVICE_STATUS_REVOKED'`
// was always true, leaving the revoke button showing on devices that were
// already revoked. Fixed in 0.16.0.
function statusBadgeClass (status) {
  switch (status) {
    case 'active': return 'bg-success'
    case 'pending_attest': return 'bg-warning-subtle text-warning-emphasis'
    case 'suspended': return 'bg-secondary'
    case 'revoked': return 'bg-danger'
    default: return 'bg-secondary-subtle text-secondary-emphasis'
  }
}

function statusLabel (status) {
  switch (status) {
    case 'active': return '활성'
    case 'pending_attest': return '기기 확인 대기'
    case 'suspended': return '일시 정지'
    case 'revoked': return '폐기됨'
    default: return status || '?'
  }
}

// What a status means for the operator, shown under the badge.
//
// 'pending_attest' is the one that needs saying out loud: since 0.10.0 the
// gateway installs a WireGuard peer only for active devices, so such a
// device cannot complete a handshake at all. Without this line the admin
// sees "대기" and reasonably assumes it will resolve itself.
// ---- deployment mode (0.17.0) --------------------------------------------
//
// A phone running both the standalone app and an embedded build registers
// twice: install_id is per app storage, so the controller sees two devices
// with the same display name, each with its own keypair, IP allocation and
// policy assignment. Migration 0010 added the columns to make that
// attributable — and nothing read them until now, so the case they exist
// to reveal stayed invisible.
//
// This does not prevent the duplicate. It cannot: the two apps are
// separate installs. It makes it visible, so an admin scoping a policy
// knows which row the user actually connects with.
function modeLabel (mode) {
  switch (mode) {
    case 'embedded': return '임베디드'
    case 'standalone': return '독립 실행'
    default: return mode || '?'
  }
}

function modeBadgeClass (mode) {
  return mode === 'embedded' ? 'bg-info-subtle text-info-emphasis' : 'bg-secondary-subtle text-secondary-emphasis'
}

// Devices whose display name appears more than once for this user, which
// is what a both-shells-installed handset looks like.
const duplicateNames = computed(() => {
  const counts = {}
  for (const d of items.value) {
    if (d.status === 'revoked') continue
    counts[d.display_name] = (counts[d.display_name] || 0) + 1
  }
  return new Set(Object.keys(counts).filter(n => counts[n] > 1))
})

function isDuplicate (d) {
  return d.status !== 'revoked' && duplicateNames.value.has(d.display_name)
}

function statusHint (status) {
  switch (status) {
    case 'pending_attest':
      return '기기 확인을 통과하지 못해 연결할 수 없습니다. 컨트롤러 로그의 attestation 항목을 확인하세요.'
    case 'suspended':
      return '관리자가 일시 정지했습니다. 연결되지 않습니다.'
    case 'revoked':
      return '폐기된 기기입니다. 다시 쓰려면 재등록해야 합니다.'
    default:
      return ''
  }
}

// Detail dialog. Opened by clicking a row.
const detail = ref(null)

// 추적 — one device's history. The question an admin arrives with is
// "this phone is not working, what happened to it", and answering it
// meant reading three screens and lining up timestamps by hand.
// 그룹 배정. The policy column shows what is in force; this decides
// where it comes from.
// 접속 기한. Separate from 폐기 because it is not a punishment: a
// phone whose access ran out did nothing wrong, and 연장 is one click.
const expiring = ref(null)
const expiryDays = ref(90)
async function openExpiry (d) { expiring.value = d; expiryDays.value = 90 }
async function confirmExpiry (days) {
  const d = expiring.value
  expiring.value = null
  if (!d) return
  try {
    await expiryAPI.setDevice(d.id, days)
    await load()
  } catch (e) {
    err.value = e?.message || String(e)
  }
}

const groupList = ref([])
const grouping = ref(null)
const groupPick = ref('')
async function openGroup (d) {
  grouping.value = d
  groupPick.value = d.group_id || ''
  if (!groupList.value.length) {
    try { groupList.value = (await groupsAPI.list()).groups || [] } catch { /* 목록만 비어 보임 */ }
  }
}
async function confirmGroup () {
  const d = grouping.value
  grouping.value = null
  if (!d) return
  try {
    await groupsAPI.assign(d.id, groupPick.value)
    await load()
  } catch (e) {
    err.value = e?.message || String(e)
  }
}

const tracing = ref(null)
const traceEvents = ref([])
// 추적 대화상자는 사건이 쌓일수록 세로로 늘어나 화면을 넘어갔습니다.
// 목록 높이를 고정하고 쪽으로 나눕니다 — 대화상자 크기가 내용에 따라
// 달라지면 [닫기] 가 화면 밖으로 나가는 일이 생깁니다.
const tracePerPage = 8
const tracePage = ref(1)
const tracePages = computed(() =>
  Math.max(1, Math.ceil(traceEvents.value.length / tracePerPage)))
const tracePaged = computed(() =>
  traceEvents.value.slice((tracePage.value - 1) * tracePerPage, tracePage.value * tracePerPage))
const traceErr = ref('')
const traceBusy = ref(false)
async function openTrace (d) {
  tracing.value = d
  traceEvents.value = []
  tracePage.value = 1
  traceErr.value = ''
  traceBusy.value = true
  try {
    const r = await traceAPI.device(d.id)
    // Newest first. The server returns time order because that is how a
    // history reads end to end; a dialog opened about a device that just
    // failed is asking what happened last.
    traceEvents.value = (r.events || []).slice().reverse()
  } catch (e) {
    traceErr.value = e?.message || String(e)
  } finally {
    traceBusy.value = false
  }
}
/**
 * The four stages, read off the events.
 *
 * Derived rather than stored: a stage strip that is written separately
 * from the events it summarises drifts from them, and then the screen
 * argues with itself. Same wording as the phone, so an operator on the
 * call and the admin at the console describe the same thing.
 */
const traceStages = computed(() => {
  const at = (action) => {
    const e = traceEvents.value.find((x) => x.action === action)
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

const traceTone = {
  ok: 'text-success', warn: 'text-warning', bad: 'text-danger', muted: 'text-muted',
}
function openDetail (d) { detail.value = d }

// Connected = a handshake in the last two minutes. WireGuard rekeys
// every two minutes while there is traffic, so a handshake older than
// that means the peer has gone quiet; wg-easy uses the same threshold.
function online (d) {
  if (!d.last_handshake_at) return false
  return Date.now() - new Date(d.last_handshake_at).getTime() < 2 * 60_000
}
function relative (t) {
  const s = Math.max(0, (Date.now() - new Date(t).getTime()) / 1000)
  if (s < 60) return `${Math.round(s)}초 전`
  if (s < 3600) return `${Math.floor(s / 60)}분 전`
  if (s < 86400) return `${Math.floor(s / 3600)}시간 전`
  return `${Math.floor(s / 86400)}일 전`
}
function bytes (n) {
  if (n == null) return '-'
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KiB`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MiB`
  return `${(n / 1024 ** 3).toFixed(2)} GiB`
}
async function copy (text) { try { await navigator.clipboard.writeText(text) } catch { /* no clipboard */ } }

function formatTimestamp (t) {
  if (!t) return '—'
  return new Date(t).toLocaleString(localeTag.value)
}

onMounted(() => { load(); loadPolicies() })
</script>

<template>
  <div>
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h1 class="h3 mb-0"> {{ tr("디바이스") }} </h1>
      <div class="d-flex gap-2">
        <input
          v-model="filter"
          type="search"
          class="form-control form-control-sm"
          :placeholder="tr(&quot;검색...&quot;)"
          style="width: 220px;"
        />
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

    <!-- Error state -->
    <div v-if="error" class="alert alert-danger" role="alert"> {{ tr("디바이스 목록을 불러오지 못했습니다: {0}", [error]) }} 
    </div>

    <!-- Loading state -->
    <div v-else-if="loading" class="text-center py-5">
      <div class="spinner-border text-primary" role="status">
        <span class="visually-hidden"> {{ tr("로딩 중...") }} </span>
      </div>
    </div>

    <!-- Empty state -->
    <div
      v-else-if="!filtered.length"
      class="text-center py-5 empty-state"
    >
      <p class="mb-1 fw-medium"> {{ tr("디바이스가 없습니다.") }} </p>
      <p class="text-muted small mb-0"> {{ tr("모바일 앱에서 첫 등록을 마치면 여기에 표시됩니다.") }} </p>
    </div>

    <!-- Table -->
    <div v-else class="card">
      <div class="table-responsive">
        <table class="table table-hover mb-0 align-middle">
          <thead class="table-light">
            <tr>
              <th> {{ tr("이름") }} </th>
              <!--
                The address, second.

                "10.78.0.2 hit the EMR at 3am — whose phone is that?" is
                the question this table exists to answer, and the address
                was not shown anywhere in the console. Correlating a
                firewall log with a person meant opening the database.

                Platform moved under the name: it is identity, not a
                column anyone scans.
              -->
              <th> {{ tr("VPN 주소") }} </th>
              <th> {{ tr("정책") }} </th>
              <th> {{ tr("상태") }} </th>
              <th> {{ tr("마지막 접속") }} </th>
              <th class="text-end"> {{ tr("동작") }} </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in paged" :key="d.id" class="device-row" @click="openDetail(d)">
              <td>
                <span class="fw-medium">{{ d.display_name }}</span>
                <br />
                <div class="text-muted" style="font-size:.72rem">
                    {{ d.platform?.replace('PLATFORM_', '') || '?' }}<span
                      v-if="d.os_version"> · {{ d.os_version }}</span><span
                      v-if="d.app_version"> {{ tr("· 앱 {0}", [d.app_version]) }} </span>
                  </div>
                  <div v-if="d.owner_email" class="text-muted" style="font-size:.72rem">
                    {{ d.owner_email }}
                  </div>
              </td>
              <td>
                <code v-if="d.ipv4" class="fw-semibold">{{ d.ipv4 }}</code>
                <span v-else class="text-muted small"> {{ tr("할당 없음") }} </span>
                <div v-if="d.ipv6" class="text-muted font-monospace" style="font-size:.72rem">
                  {{ d.ipv6 }}
                </div>
              </td>
              <td>
                <!--
                  The policy cell is the control.
                  
                  An admin reading this column and wanting to change what
                  they see should not have to find a button elsewhere on
                  the row; the value and the way to edit it are the same
                  thing.
                -->
                <button
                  type="button"
                  class="btn btn-link btn-sm p-0 text-start text-decoration-none"
                  @click="openAssign(d)"
                >
                <!--
                  Where the policy came from, not only what it is: with
                  groups, "why can this phone reach that" needs both.
                -->
                <span v-if="d.policy_name">
                  {{ d.policy_name }}
                  <span class="text-muted" style="font-size:.72rem">
                    {{ d.group_name && !d.policy_direct ? `· ${d.group_name}` : '' }}
                  </span>
                </span>
                <!--
                  Not "unbound" — say what it costs. A device with no
                  policy is refused at connect time, and a list of names
                  gives an admin no way to know that.
                -->
                <span v-else class="text-danger small"> {{ tr("정책 없음") }} <br />
                  <span class="text-muted" style="font-size:.72rem"> {{ tr("연결이 거부됩니다") }} </span>
                </span>
                </button>
              </td>
              <td>
                <!--
                  Expiry sits beside the status, not inside it: the row
                  is still 활성 — the registration is intact — and only
                  the access ran out. Folding it into the status would
                  say the device was revoked, which it was not.
                -->
                <span v-if="d.access_expired" class="badge bg-warning-subtle text-warning-emphasis me-1"> {{ tr("기한 만료") }} </span>
                <span v-if="d.posture_blocked" class="badge bg-danger-subtle text-danger-emphasis me-1"
                      :title="tr('안드로이드 API ' + d.os_sdk)"> {{ tr("OS 너무 낮음") }} </span>
                <span class="badge" :class="statusBadgeClass(d.status)">
                  {{ tr(statusLabel(d.status)) }}
                </span>
                <span class="badge ms-1" :class="modeBadgeClass(d.deployment_mode)">
                  {{ tr(modeLabel(d.deployment_mode)) }}
                </span>
                <div v-if="statusHint(d.status)" class="text-muted small mt-1">
                  {{ tr(statusHint(d.status)) }}
                </div>
                <div v-if="d.host_package" class="text-muted small mt-1"> {{ tr("터널 호스트:") }} <code>{{ d.host_package }}</code>
                </div>
                <div v-if="isDuplicate(d)" class="text-warning-emphasis small mt-1"> {{ tr("같은 이름의 단말이 둘 이상 등록돼 있습니다. 한 대의 폰에 두 모드가 설치된 경우일 수 있으며, 두 모드는 동시에 연결되지 않습니다. 사용자가 실제로 쓰는 쪽에 정책을 지정했는지 확인하세요.") }} </div>
              </td>
              <!--
                Last handshake, not last_seen_at. last_seen_at is written at
                registration and never again; last_handshake_at is what the
                gateway reports every fifteen seconds. The column read "-"
                for a phone that had just made a round trip.
              -->
              <td>
                <span class="dot" :class="online(d) ? 'on' : 'off'" />
                {{ d.last_handshake_at ? tr(relative(d.last_handshake_at)) : '-' }}
              </td>
              <!--
                Stop clicks here. The row opens the detail dialog, and
                every button in this cell sat inside it: pressing 폐기
                opened the detail first and the confirm behind it. One
                guard on the cell covers the buttons that exist and the
                ones added later.
              -->
              <td class="text-end" @click.stop>
                  <!--
                    정책 first: it decides whether the device can connect
                    at all, while 앱 필터 only refines a connection that
                    already works. This row had no way to set a policy —
                    the API and the client function both existed and
                    nothing called them.
                  -->
                  <button
                    v-if="d.status !== 'revoked'"
                    class="btn btn-sm btn-outline-secondary me-1"
                    type="button"
                    @click="openAssign(d)"
                  > {{ tr("정책") }} </button>
                <button
                  v-if="d.status !== 'revoked'"
                  class="btn btn-sm btn-outline-secondary me-1"
                  type="button"
                  @click="openAppFilter(d)"
                > {{ tr("앱 필터") }} </button>
                  <button
                    class="btn btn-sm btn-outline-secondary"
                    type="button"
                    @click="openGroup(d)"
                  > {{ tr("그룹") }} </button>
                  <button
                    class="btn btn-sm"
                    :class="d.access_expired ? 'btn-warning' : 'btn-outline-secondary'"
                    type="button"
                    @click="openExpiry(d)"
                  > {{ tr("기한") }} </button>
                  <button
                    class="btn btn-sm btn-outline-secondary"
                    type="button"
                    @click="openTrace(d)"
                  > {{ tr("추적") }} </button>
                <button
                  v-if="d.status !== 'revoked'"
                  class="btn btn-sm btn-outline-danger"
                  type="button"
                  @click="onRevoke(d)"
                > {{ tr("폐기") }} </button>
              </td>
            </tr>
          </tbody>
        </table>

          <div v-if="pageCount > 1" class="d-flex justify-content-between align-items-center mt-2">
            <button class="btn btn-sm btn-outline-secondary" type="button"
                    :disabled="page <= 1" @click="page--"> {{ tr("← 이전") }} </button>
            <span class="text-muted small">
               {{ tr("{0} / {1}쪽 · 전체 {2}대", [page, pageCount, filtered.length]) }} </span>
            <button class="btn btn-sm btn-outline-secondary" type="button"
                    :disabled="page >= pageCount" @click="page++"> {{ tr("다음 →") }} </button>
          </div>
      </div>
    </div>
    <!-- Per-app split tunnel modal (Phase 8) -->
    <div
      v-if="appFilterTarget"
      class="modal fade show d-block"
      tabindex="-1"
      role="dialog"
      style="background-color: rgba(0,0,0,0.5);"
      @click.self="closeAppFilter"
    >
      <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title"> {{ tr("앱 필터 — {0}", [appFilterTarget.display_name]) }} 
            </h5>
            <button
              type="button"
              class="btn-close"
              :disabled="appFilterSaving"
              @click="closeAppFilter"
            ></button>
          </div>
          <div class="modal-body">
            <p class="text-muted small"> {{ tr("어떤 앱이 VPN을 통과할지를 디바이스 단위로 결정합니다. 변경 사항은 다음 키 갱신(약 12시간 주기) 또는 사용자가 앱을 재등록할 때 단말에 적용됩니다.") }} </p>

            <div class="mb-3">
              <label class="form-label fw-medium"> {{ tr("모드") }} </label>
              <div class="btn-group d-flex" role="group">
                <input
                  id="afm-off"
                  v-model="appFilterMode"
                  type="radio"
                  class="btn-check"
                  value="off"
                  :disabled="appFilterSaving"
                />
                <label class="btn btn-outline-secondary" for="afm-off"> {{ tr("전체 (필터 없음)") }} </label>
                <input
                  id="afm-include"
                  v-model="appFilterMode"
                  type="radio"
                  class="btn-check"
                  value="include"
                  :disabled="appFilterSaving"
                />
                <label class="btn btn-outline-info" for="afm-include"> {{ tr("허용 앱만 통과") }} </label>
                <input
                  id="afm-exclude"
                  v-model="appFilterMode"
                  type="radio"
                  class="btn-check"
                  value="exclude"
                  :disabled="appFilterSaving"
                />
                <label class="btn btn-outline-warning" for="afm-exclude"> {{ tr("제외 앱은 우회") }} </label>
              </div>
              <small class="text-muted d-block mt-1">
                <strong> {{ tr("허용") }} </strong> {{ tr(": 목록 안의 앱만 VPN 통과 ·") }} <strong> {{ tr("제외") }} </strong> {{ tr(": 목록 안의 앱만 VPN 우회 ·") }} <strong> {{ tr("전체") }} </strong> {{ tr(": 모든 앱 VPN 통과") }} </small>
            </div>

            <div class="mb-2" v-if="appFilterMode !== 'off'">
              <label class="form-label fw-medium"> {{ tr("앱 패키지 목록") }} <small class="text-muted fw-normal"> {{ tr("(한 줄에 하나씩, 예: com.acme.intranet)") }} </small>
              </label>
              <textarea
                v-model="appFilterPackagesText"
                class="form-control font-monospace"
                rows="6"
                :disabled="appFilterSaving"
                placeholder="com.acme.intranet&#10;com.acme.email"
              ></textarea>
              <small class="text-muted">
                 {{ tr("{0}개 패키지 입력됨. 단말에 설치되지 않은 패키지는 적용 시 무시됩니다.", [appFilterPackagesParsed.length]) }} </small>
            </div>

            <div v-if="appFilterError" class="alert alert-danger small mb-0">
              {{ tr(appFilterError) }}
            </div>
          </div>
          <div class="modal-footer">
            <button
              type="button"
              class="btn btn-outline-secondary"
              :disabled="appFilterSaving"
              @click="closeAppFilter"
            > {{ tr("취소") }} </button>
            <button
              type="button"
              class="btn btn-primary"
              :disabled="appFilterSaving"
              @click="saveAppFilter"
            >
              {{ tr(appFilterSaving ? '저장 중...' : '저장') }}
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>

    <AidotDialog
      :open="!!assigning"
      :title="tr(&quot;정책 지정&quot;)"
      :confirm-label="tr(&quot;적용&quot;)"
      :busy="assignBusy"
      :error="assignErr"
      @update:open="assigning = null"
      @confirm="confirmAssign"
    >
      <template v-if="assigning">
        <p class="mb-2">
          <strong>{{ assigning.display_name }}</strong> {{ tr("이(가) 갈 수 있는 곳을 정합니다.") }} </p>
        <label class="form-label small"> {{ tr("정책") }} </label>
        <select v-model="assignChoice" class="form-select form-select-sm">
          <option value=""> {{ tr("(지정하지 않음)") }} </option>
          <option v-for="p in policyList" :key="p.id" :value="p.id">{{ p.name }}</option>
        </select>
        <div v-if="!assignChoice" class="form-text text-danger"> {{ tr("지정하지 않으면 이 단말은 연결이 거부됩니다.") }} </div>
        <div v-else class="form-text"> {{ tr("폰이 다음에 연결할 때 반영됩니다. 연결 중이면 끊고 다시 연결하세요.") }} </div>
      </template>
    </AidotDialog>

    <AidotDialog
      :open="!!expiring"
      :title="tr(expiring ? `접속 기한 — ${expiring.display_name}` : '')"
      :confirm-label="tr(&quot;적용&quot;)" :cancel-label="tr(&quot;취소&quot;)"
      @update:open="(v) => { if (!v) expiring = null }"
      @confirm="confirmExpiry(expiryDays)"
    >
      <template v-if="expiring">
        <p v-if="expiring.access_expired" class="alert alert-warning py-2 small"> {{ tr("이 단말은 기한이 지나 지금 연결되지 않습니다. 폐기된 것은 아니며, 기한을 늘리면 바로 돌아옵니다.") }} </p>
        <p v-else-if="expiring.access_expires_at" class="text-muted small"> {{ tr("지금 기한: {0}", [new Date(expiring.access_expires_at).toLocaleString(localeTag)]) }} 
        </p>
        <p v-else class="text-muted small"> {{ tr("지금은 기한이 없습니다 — 계속 연결됩니다.") }} </p>

        <label class="form-label small text-muted"> {{ tr("오늘부터") }} </label>
        <select v-model.number="expiryDays" class="form-select form-select-sm">
          <option :value="30"> {{ tr("30일") }} </option>
          <option :value="90"> {{ tr("90일") }} </option>
          <option :value="180"> {{ tr("180일") }} </option>
          <option :value="365"> {{ tr("1년") }} </option>
          <option :value="0"> {{ tr("기한 없음") }} </option>
        </select>
        <p class="text-muted small mt-2 mb-0"> {{ tr("기한이 지나면 문지기가 이 단말을 받지 않습니다. 등록은 남아 있어 언제든 늘릴 수 있습니다.") }} </p>
      </template>
    </AidotDialog>

    <AidotDialog
      :open="!!grouping"
      :title="tr(grouping ? `그룹 정하기 — ${grouping.display_name}` : '')"
      :confirm-label="tr(&quot;적용&quot;)" :cancel-label="tr(&quot;취소&quot;)"
      @update:open="(v) => { if (!v) grouping = null }"
      @confirm="confirmGroup"
    >
      <template v-if="grouping">
        <label class="form-label small text-muted"> {{ tr("그룹") }} </label>
        <select v-model="groupPick" class="form-select form-select-sm">
          <option value=""> {{ tr("(그룹 없음)") }} </option>
          <option v-for="g in groupList" :key="g.id" :value="g.id">
            {{ g.name }}<template v-if="g.policy_name"> — {{ g.policy_name }}</template>
          </option>
        </select>
        <p class="text-muted small mt-2 mb-0"> {{ tr("그룹의 정책이 이 단말에 적용됩니다. 이 단말에 정책을 따로 지정했다면 그쪽이 우선합니다.") }} </p>
      </template>
    </AidotDialog>

    <!--
      추적 — one device, in order.
      Four stages across the top in the same words the phone shows its
      own user (등록 요청 → 관리자 승인 → 정책 적용 → 연결), then every
      event underneath. The stages are derived from the events, so the
      strip and the list can never disagree.
    -->
    <AidotDialog
      :open="!!tracing"
      :title="tr(tracing ? `추적 — ${tracing.display_name}` : '')"
      confirm-only
      @update:open="(v) => { if (!v) tracing = null }"
      @confirm="tracing = null"
    >
      <template v-if="tracing">
        <div class="trace-stages mb-3">
          <div v-for="(st, i) in traceStages" :key="i" class="trace-stage">
            <div class="trace-bar" :class="{ on: st.done }" />
            <div class="trace-lbl" :class="{ on: st.done }">{{ tr(st.label) }}</div>
            <div class="trace-at">{{ st.at || '—' }}</div>
          </div>
        </div>

        <div v-if="traceBusy" class="text-muted small"> {{ tr("불러오는 중…") }} </div>
        <div v-else-if="traceErr" class="alert alert-danger py-2 small">{{ tr(traceErr) }}</div>
        <div v-else-if="!traceEvents.length" class="text-muted small"> {{ tr("아직 기록이 없습니다.") }} </div>
        <div v-else class="trace-scroll">
        <table class="table table-sm align-middle mb-0">
          <thead>
            <tr><th style="width:11rem"> {{ tr("시간") }} </th><th style="width:4.5rem"> {{ tr("누가") }} </th><th> {{ tr("무슨 일") }} </th></tr>
          </thead>
          <tbody>
            <tr v-for="(e, i) in tracePaged" :key="i">
              <td class="small text-muted">{{ new Date(e.at).toLocaleString(localeTag) }}</td>
              <td class="small">{{ tr(e.actor) }}</td>
              <td>
                <span :class="traceTone[e.tone] || ''">{{ tr(e.label) }}</span>
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
        <div v-if="tracePages > 1" class="d-flex justify-content-between align-items-center mt-2">
          <button class="btn btn-sm btn-outline-secondary" type="button"
                  :disabled="tracePage <= 1" @click="tracePage--"> {{ tr("← 이전") }} </button>
          <span class="text-muted small">
             {{ tr("{0} / {1}쪽 · 사건 {2}건", [tracePage, tracePages, traceEvents.length]) }} </span>
          <button class="btn btn-sm btn-outline-secondary" type="button"
                  :disabled="tracePage >= tracePages" @click="tracePage++"> {{ tr("다음 →") }} </button>
        </div>
      </template>
    </AidotDialog>

    <!--
      Device detail. What wg-easy and Tailscale put on a device page:
      connection state, last handshake, transfer both ways, how the peer
      reached the gateway (direct or relayed), the address it came from,
      the tunnel address, the key. Then what only we know: policy,
      registration, platform.
    -->
    <AidotDialog
      :open="!!detail"
      :title="tr(detail?.display_name || '단말')"
      confirm-only
      @update:open="(v) => { if (!v) detail = null }"
      @confirm="detail = null"
    >
      <template v-if="detail">
        <div class="detail-grid">
          <div class="detail-k"> {{ tr("연결 상태") }} </div>
          <div><span class="dot" :class="online(detail) ? 'on' : 'off'" /> {{ tr(online(detail) ? '연결 중' : '끊김') }}
            <span class="text-muted small"> {{ tr("— 핸드셰이크 2분 이내면 연결 중") }} </span></div>

          <div class="detail-k"> {{ tr("마지막 핸드셰이크") }} </div>
          <div>{{ tr(detail.last_handshake_at ? `${relative(detail.last_handshake_at)} · ${formatTimestamp(detail.last_handshake_at)}` : '아직 없음') }}</div>

          <div class="detail-k"> {{ tr("전송량") }} </div>
          <div> {{ tr("↓ 받음") }} <code>{{ bytes(detail.rx_bytes) }}</code> {{ tr("↑ 보냄") }} <code>{{ bytes(detail.tx_bytes) }}</code>
            <span class="text-muted small"> {{ tr("— 문지기 기준, 재시작 시 0 부터") }} </span></div>

          <div class="detail-k"> {{ tr("접속 방식") }} </div>
          <div>{{ tr(detail.via_relay === true ? '우회 (릴레이)' : detail.via_relay === false ? '직접' : '-') }}</div>

          <div class="detail-k"> {{ tr("접속 지점") }} </div>
          <div><code>{{ detail.last_endpoint || '-' }}</code>
            <span class="text-muted small"> {{ tr("— 폰이 붙어온 공인 주소:포트") }} </span></div>

          <div class="detail-k"> {{ tr("터널 주소") }} </div>
          <div><code>{{ detail.ipv4 }}</code> <code v-if="detail.ipv6" class="ms-1">{{ detail.ipv6 }}</code></div>

          <div class="detail-k"> {{ tr("공개키") }} </div>
          <div><code>{{ (detail.public_key || '').slice(0, 16) }}…</code>
            <button class="btn btn-link btn-sm p-0 ms-2" type="button" @click="copy(detail.public_key)"> {{ tr("복사") }} </button></div>

          <div class="detail-k"> {{ tr("정책") }} </div>
          <div>{{ tr(detail.policy_name || '(없음)') }}</div>

          <div class="detail-k"> {{ tr("기기") }} </div>
          <div>{{ detail.model || '-' }}
            <span v-if="!detail.model" class="text-muted small"> {{ tr("— 앱 1.9.0 이상에서 보고합니다") }} </span></div>

          <div class="detail-k"> {{ tr("플랫폼") }} </div>
          <div>{{ detail.platform || '-' }} <span v-if="detail.os_version" class="text-muted small">{{ detail.os_version }}</span>
            <span v-if="detail.app_version" class="text-muted small"> {{ tr("· 앱 {0}", [detail.app_version]) }} </span></div>

          <div class="detail-k"> {{ tr("등록") }} </div>
          <div>{{ formatTimestamp(detail.created_at) }} <span class="text-muted small">· {{ detail.install_id }}</span></div>

          <div class="detail-k"> {{ tr("상태") }} </div>
          <div>{{ tr(detail.status) }}</div>
        </div>
      </template>
    </AidotDialog>

    <AidotDialog
      :open="!!revoking" :title="tr(&quot;디바이스 폐기&quot;)" tone="danger" :confirm-label="tr(&quot;폐기&quot;)"
      :busy="revokeBusy" :error="revokeErr"
      @update:open="revoking = null" @confirm="confirmRevoke"
    >
      <template v-if="revoking">
        <p class="mb-2">
          <strong>{{ revoking.display_name }}</strong> {{ tr("을(를) 폐기합니다. 이 기기는 즉시 연결이 끊기고 다시 등록해야 합니다.") }} </p>
        <label class="form-label small"> {{ tr("폐기 사유 (선택)") }} </label>
        <input
          v-model="revokeReason" class="form-control form-control-sm"
          :placeholder="tr(&quot;예: 분실 신고&quot;)" @keyup.enter="confirmRevoke"
        />
      </template>
    </AidotDialog>

</template>

<style>
/* Global on purpose: the detail grid renders inside AidotDialog's slot,
   outside this component's scoped styles. */
.device-row { cursor: pointer; }
.device-row:hover td { background: var(--bs-table-hover-bg); }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: .35rem; vertical-align: 1px; }
.dot.on { background: var(--good); box-shadow: 0 0 0 3px var(--good-soft); }
.dot.off { background: var(--text-3); }
.detail-grid { display: grid; grid-template-columns: 9rem 1fr; gap: .55rem .75rem; align-items: baseline; font-size: .9rem; }
.detail-k { color: var(--text-2); font-weight: 600; }
.trace-stages { display: grid; grid-template-columns: repeat(4, 1fr); gap: .5rem; }
.trace-bar { height: 4px; border-radius: 2px; background: var(--line); }
.trace-bar.on { background: var(--accent); }
.trace-lbl { font-size: .78rem; color: var(--text-3); margin-top: .35rem; }
.trace-lbl.on { color: var(--text); font-weight: 600; }
.trace-at { font-size: .68rem; color: var(--text-3); }
/* Fixed so the dialog does not grow with its content — a dialog whose
   height follows the data eventually puts its own close button off
   screen. */
.trace-scroll { height: 22rem; overflow-y: auto; }
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

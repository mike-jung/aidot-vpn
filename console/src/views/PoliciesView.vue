<script setup>
import { translate as tr, localeTag } from '../i18n/index.js'
// PoliciesView — Phase 8: full policy CRUD + AllowedIPs management.
//
// Layout:
//   Left column   — list of policies, click to select.
//   Right column  — detail view for the selected policy:
//                    name/description/enabled fields + AllowedIPs table.
//
// We keep the design intentionally flat (no modal dialogs, no toast
// notifications) — admin consoles are weighted toward power users who
// prefer dense, predictable UI to delight-y interactions.

import { ref, onMounted, computed } from 'vue'
import { policies, trace as traceAPI, APIError } from '@/api/client.js'
import AidotDialog from '../components/AidotDialog.vue'

// ---- list state ----------------------------------------------------------
const list = ref([])
const loadingList = ref(true)
const listErr = ref(null)

async function refreshList () {
  loadingList.value = true
  listErr.value = null
  try {
    const resp = await policies.list()
    list.value = resp.policies || []
    if (selectedId.value && !list.value.find(p => p.id === selectedId.value)) {
      selectedId.value = null
      detail.value = null
    }
  } catch (e) {
    listErr.value = e instanceof APIError ? `${e.status} ${e.message}` : String(e)
  } finally {
    loadingList.value = false
  }
}

// ---- detail state --------------------------------------------------------
const selectedId = ref(null)

// 정책별 추적 — what changed, and who it reaches.
//
// The question before editing a policy is "who does this touch"; the
// device list answers it. The history answers "why is it like this".
// Both were reachable only by reading two other screens and matching
// ids by hand.
const tracing = ref(false)
const traceEvents = ref([])
const traceDevices = ref([])
const traceBusy = ref(false)
const traceErr = ref('')
async function openTrace () {
  if (!selectedId.value) return
  tracing.value = true
  traceBusy.value = true
  traceErr.value = ''
  traceEvents.value = []
  traceDevices.value = []
  try {
    const r = await traceAPI.policy(selectedId.value)
    traceEvents.value = r.events || []
    traceDevices.value = r.devices || []
  } catch (e) {
    traceErr.value = e?.message || String(e)
  } finally {
    traceBusy.value = false
  }
}
const traceTone = {
  ok: 'text-success', warn: 'text-warning', bad: 'text-danger', muted: 'text-muted',
}
const detail = ref(null)

// Dialog state for the two destructive actions.
//
// The 1.2.0 edit that replaced confirm() with AidotDialog added the
// markup and the handlers and not these — so the template referenced
// four names that did not exist. Vue reports that as a render warning,
// not an error, and `vite build` says nothing at all: the dialogs simply
// never opened and 삭제 did nothing.
// Transport settings, edited separately from name and description.
//
// These change how traffic moves rather than what it may reach, and a
// rename should not be able to flip them by accident.
const transportMode = ref('direct')
const transportNat = ref(false)
const transportChannel = ref('direct')
const transportBusy = ref(false)
const transportErr = ref('')

const MODES = [
  {
    key: 'direct',
    label: '직접 연결',
    detail: 'UDP 로 바로 붙습니다. 가장 빠르고, 병원 안에서는 이것으로 충분합니다.',
  },
  {
    key: 'auto',
    label: '막히면 우회',
    detail: '먼저 직접 붙어보고, 안 되면 우회로를 씁니다. 폰을 밖으로 들고 나갈 때.',
  },
  {
    key: 'relay',
    label: '항상 우회',
    detail: '항상 릴레이로 연결합니다. 접근 가능한 릴레이 서버가 필요하며 통신 부하가 늘어납니다.',
  },
]

async function saveTransport () {
  transportBusy.value = true
  transportErr.value = ''
  try {
    await policies.updateTransport(detail.value.id, transportMode.value,
      transportNat.value, transportChannel.value)
    await selectPolicy(detail.value.id)
  } catch (e) {
    transportErr.value = e instanceof APIError ? `${e.status} ${e.message}` : String(e)
  } finally {
    transportBusy.value = false
  }
}

// Virtual destinations.
//
// The phone is told vhVirtual; the gateway rewrites it to vhReal. The
// real address never reaches the handset — which is the thing 감추기
// could not do, because a policy line of 192.168.0.22/32 is itself the
// real address, delivered to the phone.
const virtualHosts = ref([])
const vhVirtual = ref('')
const vhReal = ref('')
const vhDesc = ref('')
const vhBusy = ref(false)
const vhErr = ref('')

async function loadVirtualHosts (id) {
  try { virtualHosts.value = (await policies.listVirtualHosts(id)).virtual_hosts || [] }
  catch { virtualHosts.value = [] }
}

async function addVirtualHost () {
  vhBusy.value = true
  vhErr.value = ''
  try {
    await policies.addVirtualHost(detail.value.id, vhVirtual.value, vhReal.value, vhDesc.value)
    vhVirtual.value = ''; vhReal.value = ''; vhDesc.value = ''
    await loadVirtualHosts(detail.value.id)
  } catch (e) {
    vhErr.value = e instanceof APIError ? e.message : String(e)
  } finally {
    vhBusy.value = false
  }
}

async function removeVirtualHost (hostId) {
  try {
    await policies.removeVirtualHost(detail.value.id, hostId)
    await loadVirtualHosts(detail.value.id)
  } catch (e) {
    vhErr.value = e instanceof APIError ? e.message : String(e)
  }
}

const askDelete = ref(false)
const askRemoveCidr = ref(null)
const dlgBusy = ref(false)
const dlgErr = ref('')
const detailErr = ref(null)
const loadingDetail = ref(false)

async function selectPolicy (id) {
  selectedId.value = id
  loadingDetail.value = true
  detailErr.value = null
  try {
    detail.value = await policies.get(id)
    // Loaded together so the detail pane never shows a policy's CIDRs
    // next to another policy's DNS settings during a switch.
    await Promise.all([loadSettings(id), loadHostnames(id)])
  } catch (e) {
    detailErr.value = e instanceof APIError ? `${e.status} ${e.message}` : String(e)
    detail.value = null
  } finally {
    loadingDetail.value = false
  }
  // Load the transport settings into the form, so it opens showing what
  // the policy has rather than a default that would overwrite it.
  transportMode.value = detail.value?.endpoint_mode || 'direct'
  transportNat.value = !!detail.value?.source_nat
  transportChannel.value = detail.value?.control_channel || 'direct'
  await loadVirtualHosts(id)
  transportErr.value = ''
}

// ---- create form ---------------------------------------------------------
const newName = ref('')
const newDesc = ref('')
const creating = ref(false)
const createErr = ref(null)

async function createPolicy () {
  if (!newName.value.trim()) {
    createErr.value = '이름이 필요합니다.'
    return
  }
  creating.value = true
  createErr.value = null
  try {
    const created = await policies.create(newName.value.trim(), newDesc.value.trim())
    newName.value = ''
    newDesc.value = ''
    await refreshList()
    await selectPolicy(created.id)
  } catch (e) {
    createErr.value = e instanceof APIError ? `${e.status} ${e.message}` : String(e)
  } finally {
    creating.value = false
  }
}

// ---- detail edits --------------------------------------------------------
const savingDetail = ref(false)
async function saveDetail () {
  if (!detail.value) return
  savingDetail.value = true
  try {
    await policies.update(detail.value.id, detail.value.name,
      detail.value.description || '', detail.value.enabled)
    await refreshList()
  } catch (e) {
    detailErr.value = e instanceof APIError ? `${e.status} ${e.message}` : String(e)
  } finally {
    savingDetail.value = false
  }
}

function deletePolicy () {
  if (!detail.value) return
  // Dialog, not confirm(). See AidotDialog for why.
  dlgErr.value = ''
  askDelete.value = true
}

async function confirmDeletePolicy () {
  dlgBusy.value = true
  dlgErr.value = ''
  try {
    await policies.delete(detail.value.id)
    askDelete.value = false
    detail.value = null
    selectedId.value = null
    await refreshList()
  } catch (e) {
    dlgErr.value = e instanceof APIError ? `${e.status} ${e.message}` : String(e)
  } finally {
    dlgBusy.value = false
  }
}

// ---- AllowedIPs ----------------------------------------------------------
const newCidr = ref('')
const newCidrDesc = ref('')
const cidrErr = ref(null)
const cidrWarn = ref(null)
const addingCidr = ref(false)

async function addCidr () {
  if (!detail.value) return
  if (!newCidr.value.trim()) {
    cidrErr.value = 'CIDR이 비어있습니다.'
    return
  }
  addingCidr.value = true
  cidrErr.value = null
  try {
    const res = await policies.addAllowedIP(detail.value.id, newCidr.value.trim(), newCidrDesc.value.trim())
    // The server accepted it and is telling us it will not apply.
    // Distinct from an error: the row exists, the admin should know
    // why it will do nothing.
    cidrWarn.value = res?.warning || null
    newCidr.value = ''
    newCidrDesc.value = ''
    await selectPolicy(detail.value.id)
  } catch (e) {
    cidrErr.value = e instanceof APIError ? `${e.status} ${e.message}` : String(e)
  } finally {
    addingCidr.value = false
  }
}

function removeCidr (aipId) {
  if (!detail.value) return
  dlgErr.value = ''
  askRemoveCidr.value = aipId
}

async function confirmRemoveCidr () {
  dlgBusy.value = true
  dlgErr.value = ''
  const aipId = askRemoveCidr.value
  try {
    await policies.removeAllowedIP(detail.value.id, aipId)
    askRemoveCidr.value = null
    await selectPolicy(detail.value.id)
  } catch (e) {
    detailErr.value = e instanceof APIError ? `${e.status} ${e.message}` : String(e)
  }
}


// ---- tunnel settings: route scope + DNS (0.16.0) --------------------------
//
// route_scope and the DNS fields shipped in 0.11.0 and 0.15.0 but had no
// UI, so an admin could only set them with direct SQL. Both shape what a
// device can reach, which makes "no UI" a real operational problem rather
// than a cosmetic one.

const settings = ref(null)
const settingsErr = ref(null)
const savingSettings = ref(false)
// Bound to text inputs; the API takes arrays, so we split on save.
const dnsServersText = ref('')
const searchDomainsText = ref('')

async function loadSettings (id) {
  settingsErr.value = null
  try {
    settings.value = await policies.getSettings(id)
    dnsServersText.value = (settings.value.dns_servers || []).join(', ')
    searchDomainsText.value = (settings.value.dns_search_domains || []).join(', ')
  } catch (e) {
    settingsErr.value = e instanceof APIError ? `${e.status} ${e.message}` : String(e)
    settings.value = null
  }
}

function splitCsv (text) {
  return text.split(',').map(v => v.trim()).filter(Boolean)
}

async function saveSettings () {
  if (!selectedId.value) return
  savingSettings.value = true
  settingsErr.value = null
  try {
    settings.value = await policies.updateSettings(selectedId.value, {
      routeScope: settings.value.route_scope,
      dnsServers: splitCsv(dnsServersText.value),
      searchDomains: splitCsv(searchDomainsText.value),
    })
    dnsServersText.value = (settings.value.dns_servers || []).join(', ')
    searchDomainsText.value = (settings.value.dns_search_domains || []).join(', ')
  } catch (e) {
    settingsErr.value = e instanceof APIError ? `${e.status} ${e.message}` : String(e)
  } finally {
    savingSettings.value = false
  }
}

// ---- hostname rules ------------------------------------------------------

const hostnames = ref([])
const hostnameErr = ref(null)
const newHostname = ref('')
const newGuard = ref('')
const newHostDesc = ref('')
const addingHostname = ref(false)

async function loadHostnames (id) {
  hostnameErr.value = null
  try {
    const res = await policies.listHostnames(id)
    hostnames.value = res.hostnames || []
  } catch (e) {
    hostnameErr.value = e instanceof APIError ? `${e.status} ${e.message}` : String(e)
    hostnames.value = []
  }
}

async function addHostname () {
  if (!selectedId.value || !newHostname.value.trim()) return
  addingHostname.value = true
  hostnameErr.value = null
  try {
    await policies.addHostname(selectedId.value, {
      hostname: newHostname.value.trim(),
      guardCidr: newGuard.value.trim(),
      description: newHostDesc.value.trim(),
    })
    newHostname.value = ''
    newGuard.value = ''
    newHostDesc.value = ''
    await loadHostnames(selectedId.value)
  } catch (e) {
    hostnameErr.value = e instanceof APIError ? `${e.status} ${e.message}` : String(e)
  } finally {
    addingHostname.value = false
  }
}

async function removeHostname (hostnameId) {
  if (!selectedId.value) return
  hostnameErr.value = null
  try {
    await policies.removeHostname(selectedId.value, hostnameId)
    await loadHostnames(selectedId.value)
  } catch (e) {
    hostnameErr.value = e instanceof APIError ? `${e.status} ${e.message}` : String(e)
  }
}

const unguardedCount = computed(
  () => hostnames.value.filter(h => h.unguarded).length
)

// ---- computed ------------------------------------------------------------

const allowedIpCount = computed(() => detail.value?.allowed_ips?.length || 0)

onMounted(refreshList)
</script>

<template>
  <div>
    <div class="d-flex justify-content-between align-items-center mb-3">
      <h1 class="h3 mb-0"> {{ tr("정책") }} </h1>
      <button class="btn btn-outline-secondary btn-sm" @click="refreshList"> {{ tr("새로고침") }} </button>
    </div>

    <div v-if="listErr" class="alert alert-danger">{{ tr(listErr) }}</div>

    <div class="row">
      <div class="col-md-4">
        <div class="card mb-3">
          <div class="card-header py-2"><strong> {{ tr("새 정책 만들기") }} </strong></div>
          <div class="card-body">
            <div v-if="createErr" class="alert alert-danger py-2 small mb-2">{{ tr(createErr) }}</div>
            <input v-model="newName" type="text" class="form-control mb-2" :placeholder="tr(&quot;정책 이름 (예: Engineering)&quot;)" />
            <input v-model="newDesc" type="text" class="form-control mb-2" :placeholder="tr(&quot;설명 (선택)&quot;)" />
            <button class="btn btn-primary btn-sm w-100" :disabled="creating" @click="createPolicy">
              {{ tr(creating ? '저장 중...' : '만들기') }}
            </button>
          </div>
        </div>

        <div class="card">
          <div class="card-header py-2"><strong> {{ tr("정책 목록") }} </strong></div>
          <div v-if="loadingList" class="card-body text-muted small"> {{ tr("불러오는 중...") }} </div>
          <div v-else-if="list.length === 0" class="card-body text-muted small"> {{ tr("정책이 아직 없습니다. 왼쪽 폼에서 만들 수 있습니다.") }} </div>
          <ul v-else class="list-group list-group-flush">
            <li v-for="p in list" :key="p.id"
                class="list-group-item list-group-item-action"
                :class="{ active: p.id === selectedId }"
                @click="selectPolicy(p.id)"
                style="cursor: pointer;">
              <div class="d-flex justify-content-between align-items-center">
                <strong>{{ p.name }}</strong>
                <span :class="p.enabled ? 'badge bg-success' : 'badge bg-secondary'">
                  {{ tr(p.enabled ? '활성' : '비활성') }}
                </span>
              </div>
              <div class="text-muted small text-truncate" v-if="p.description">{{ p.description }}</div>
            </li>
          </ul>
        </div>
      </div>

      <div class="col-md-8">
        <div v-if="!detail" class="card">
          <div class="card-body text-center py-5 text-muted"> {{ tr("왼쪽 목록에서 정책을 선택하세요.") }} </div>
        </div>

        <div v-else>
          <div v-if="detailErr" class="alert alert-danger">{{ tr(detailErr) }}</div>

          <div class="card mb-3">
            <div class="card-header d-flex justify-content-between align-items-center py-2">
              <strong> {{ tr("정책 상세") }} </strong>
              <div class="d-flex gap-2">
                <button class="btn btn-outline-secondary btn-sm" @click="openTrace"> {{ tr("추적") }} </button>
                <button class="btn btn-outline-danger btn-sm" @click="deletePolicy"> {{ tr("삭제") }} </button>
              </div>
            </div>
            <div class="card-body">
              <div class="mb-2">
                <label class="form-label small text-muted"> {{ tr("이름") }} </label>
                <input v-model="detail.name" type="text" class="form-control form-control-sm" />
              </div>
              <div class="mb-2">
                <label class="form-label small text-muted"> {{ tr("설명") }} </label>
                <input v-model="detail.description" type="text" class="form-control form-control-sm" />
              </div>
              <div class="form-check mb-2">
                <input v-model="detail.enabled" id="enabled" type="checkbox" class="form-check-input" />
                <label for="enabled" class="form-check-label"> {{ tr("활성") }} </label>
              </div>
              <button class="btn btn-primary btn-sm" :disabled="savingDetail" @click="saveDetail">
                {{ tr(savingDetail ? '저장 중...' : '저장') }}
              </button>
            </div>
          </div>

          <div class="card">
            <div class="card-header py-2">
              <strong> {{ tr("허용 CIDR (Split Tunnel)") }} </strong>
              <span class="text-muted small ms-2"> {{ tr("{0}개", [allowedIpCount]) }} </span>
            </div>
            <div class="card-body">
              <p class="text-muted small mb-3"> {{ tr("스플릿 모드에서는 등록된 CIDR을 VPN 터널로 라우팅합니다. 허용 목록이 비어 있으면 업무망 접근 권한이 없습니다.") }} </p>

              <div v-if="cidrErr" class="alert alert-danger py-2 small">{{ tr(cidrErr) }}</div>


              <div v-if="cidrWarn" class="alert alert-warning py-2 small">{{ tr(cidrWarn) }}</div>

              <div class="row g-2 mb-3">
                <div class="col-md-4">
                  <input v-model="newCidr" type="text" class="form-control form-control-sm"
                         placeholder="10.10.0.0/16" />
                </div>
                <div class="col-md-5">
                  <input v-model="newCidrDesc" type="text" class="form-control form-control-sm"
                         :placeholder="tr(&quot;설명 (예: 사내 본사망)&quot;)" />
                </div>
                <div class="col-md-3">
                  <button class="btn btn-outline-primary btn-sm w-100" :disabled="addingCidr" @click="addCidr">
                    {{ tr(addingCidr ? '추가 중...' : 'CIDR 추가') }}
                  </button>
                </div>
              </div>

              <table v-if="allowedIpCount > 0" class="table table-sm table-hover mb-0">
                <thead class="table-light">
                  <tr>
                    <th style="width: 30%;">CIDR</th>
                    <th> {{ tr("설명") }} </th>
                    <th style="width: 10%;"></th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="aip in detail.allowed_ips" :key="aip.id">
                    <td><code>{{ aip.cidr }}</code></td>
                    <td>{{ aip.description || '-' }}</td>
                    <td class="text-end">
                      <button class="btn btn-outline-danger btn-sm py-0" @click="removeCidr(aip.id)">×</button>
                    </td>
                  </tr>
                </tbody>
              </table>
              <p v-else class="text-muted small text-center mb-0 py-2"> {{ tr("아직 등록된 CIDR이 없습니다.") }} </p>
            </div>
          </div>

          <!-- ===== 터널 범위 & DNS (0.16.0) ===== -->
          <!--
            Virtual destinations.
            
            The phone is handed 10.79.0.22; the gateway rewrites it to
            192.168.0.22. A CIDR line above puts the real address on the
            phone. This is the way to keep it off.
          -->
          <div class="card mt-3">
            <div class="card-header py-2">
              <strong> {{ tr("가상 주소로 접근") }} </strong>
              <span class="text-muted ms-2" style="font-size:.78rem"> {{ tr("폰에는 가짜 주소만 알려주고, 문지기가 진짜 주소로 바꿉니다") }} </span>
            </div>
            <div class="card-body">
              <div v-if="vhErr" class="alert alert-danger py-2 small">{{ tr(vhErr) }}</div>
              <div class="row g-2 mb-2">
                <div class="col-4">
                  <input
                    v-model="vhVirtual" class="form-control form-control-sm"
                    :placeholder="tr(&quot;폰이 쓸 주소 10.79.0.22&quot;)"
                  />
                </div>
                <div class="col-4">
                  <input
                    v-model="vhReal" class="form-control form-control-sm"
                    :placeholder="tr(&quot;진짜 주소 192.168.0.22&quot;)"
                  />
                </div>
                <div class="col-3">
                  <input
                    v-model="vhDesc" class="form-control form-control-sm"
                    :placeholder="tr(&quot;설명 (EMR)&quot;)"
                  />
                </div>
                <div class="col-1">
                  <button
                    class="btn btn-sm btn-primary w-100" type="button"
                    :disabled="vhBusy || !vhVirtual || !vhReal"
                    @click="addVirtualHost"
                  > {{ tr("추가") }} </button>
                </div>
              </div>
              <div class="form-text mb-2"> {{ tr("폰이 쓸 주소는") }} <code>10.79.x.x</code> {{ tr("안에서 고릅니다. 폰 주소(10.78)와 겹치지 않는 대역입니다. 시험만 해보려면 진짜 주소에") }} <code>10.78.0.1</code> {{ tr("(문지기 자신)을 적으면 다른 서버 없이 됩니다. 관리실 컴퓨터 자신은 안 됩니다 — 도커 문지기가 자기 호스트로 갈 수 없습니다.") }} </div>
              <table v-if="virtualHosts.length" class="table table-sm mb-0">
                <thead><tr><th> {{ tr("폰이 쓰는 주소") }} </th><th></th><th> {{ tr("진짜 주소") }} </th><th> {{ tr("설명") }} </th><th></th></tr></thead>
                <tbody>
                  <tr v-for="h in virtualHosts" :key="h.id">
                    <td><code>{{ h.virtual_ip }}</code></td>
                    <td class="text-muted">→</td>
                    <td><code>{{ h.real_ip }}</code></td>
                    <td class="text-muted small">{{ h.description }}</td>
                    <td class="text-end">
                      <button class="btn btn-sm btn-outline-danger" type="button" @click="removeVirtualHost(h.id)">✕</button>
                    </td>
                  </tr>
                </tbody>
              </table>
              <p v-else class="text-muted small mb-0"> {{ tr("아직 없습니다.") }} </p>
            </div>
          </div>

          <!--
            How the phone reaches the gateway.
            
            Placed before the tunnel settings because it decides whether
            the tunnel comes up at all — the settings below only shape a
            tunnel that already works.
          -->
          <div class="card mt-3">
            <div class="card-header py-2">
              <strong> {{ tr("접속 방식") }} </strong>
              <span class="text-muted ms-2" style="font-size:.78rem"> {{ tr("폰이 문지기에 어떻게 붙을지") }} </span>
            </div>
            <div class="card-body">
              <div v-if="transportErr" class="alert alert-danger py-2 small">
                {{ tr(transportErr) }}
              </div>

              <div v-for="m in MODES" :key="m.key" class="form-check mb-2">
                <input
                  :id="'mode-' + m.key"
                  v-model="transportMode"
                  :value="m.key"
                  class="form-check-input"
                  type="radio"
                />
                <label class="form-check-label" :for="'mode-' + m.key">
                  <span class="fw-semibold">{{ tr(m.label) }}</span>
                  <span class="d-block text-muted" style="font-size:.78rem">
                    {{ tr(m.detail) }}
                  </span>
                </label>
              </div>

              <hr class="my-3" />

              <!--
                Where the app reaches the controller.
                
                Separate from the endpoint modes above: those decide how
                the tunnel is carried, this decides whether the
                controller's address ends up compiled into the APK.
              -->
              <div class="mb-2">
                <div class="fw-semibold small mb-1"> {{ tr("컨트롤러 주소") }} </div>
                <div class="form-check">
                  <input
                    id="chan-direct" v-model="transportChannel" value="direct"
                    class="form-check-input" type="radio"
                  />
                  <label class="form-check-label" for="chan-direct">
                    <span class="fw-semibold"> {{ tr("그대로 사용") }} </span>
                    <span class="d-block text-muted" style="font-size:.78rem"> {{ tr("앱에 넣어둔 서버 주소를 그대로 씁니다. 터널이 없어도 됩니다.") }} </span>
                  </label>
                </div>
                <div class="form-check">
                  <input
                    id="chan-tunnel" v-model="transportChannel" value="tunnel"
                    class="form-check-input" type="radio"
                  />
                  <label class="form-check-label" for="chan-tunnel">
                    <span class="fw-semibold"> {{ tr("감추기 (터널로 우회)") }} </span>
                    <span class="d-block text-muted" style="font-size:.78rem"> {{ tr("등록 후에는 터널 안 주소로 통신합니다. APK에 포함된 최초 등록 주소가 제거되는 것은 아닙니다.") }} </span>
                  </label>
                </div>
                <!--
                  The cost, at the switch. Hiding the address makes the
                  control channel depend on the gateway proxy, and a
                  device that cannot reach the controller cannot be told
                  it was revoked.
                -->
                <div v-if="transportChannel === 'tunnel'" class="alert alert-warning py-2 small mt-2 mb-0"> {{ tr("문지기의 중계가 살아 있어야 동작합니다. 중계가 멈추면 그 폰은") }} <strong> {{ tr("폐기되었다는 사실도 전달받지 못합니다.") }} </strong>
                </div>
              </div>

              <hr class="my-3" />

              <div class="form-check">
                <input
                  id="source-nat"
                  v-model="transportNat"
                  class="form-check-input"
                  type="checkbox"
                />
                <label class="form-check-label" for="source-nat">
                  <span class="fw-semibold"> {{ tr("주소 바꿔서 보내기") }} </span>
                  <span class="d-block text-muted" style="font-size:.78rem"> {{ tr("목적지 서버에 답신 경로를 넣을 수 없을 때 켭니다.") }} <strong> {{ tr("도커로 띄운 문지기는 항상 이 경우입니다") }} </strong> {{ tr("— 문지기 뒤 서버에 가려면 켜세요.") }} </span>
                </label>
              </div>
              <!--
                State the cost where the switch is, not in a document.
                Turning this on ends the per-device audit trail, and an
                admin should meet that fact at the moment of deciding.
              -->
              <div v-if="transportNat" class="alert alert-warning py-2 small mt-2 mb-0"> {{ tr("켜면 목적지 서버 기록에") }} <strong> {{ tr("모든 폰이 문지기 주소") }} </strong> {{ tr("로 남습니다. \"10.78.0.2 가 새벽 3시에 조회했다 — 누구 폰인가\" 를 답할 수 없게 됩니다.") }} </div>

              <button
                class="btn btn-sm btn-primary mt-3"
                type="button"
                :disabled="transportBusy"
                @click="saveTransport"
              >{{ tr(transportBusy ? '저장 중…' : '접속 방식 저장') }}</button>
            </div>
          </div>

          <div class="card mt-3">
            <div class="card-header py-2">
              <strong class="small"> {{ tr("터널 범위 & DNS") }} </strong>
            </div>
            <div class="card-body">
              <div v-if="settingsErr" class="alert alert-danger py-2 small">{{ tr(settingsErr) }}</div>

              <div v-if="settings">
                <!--
                  Route scope is the axis that decides what happens to
                  traffic the policy does not permit. It is independent of
                  the per-app filter, which lives on each device.
                -->
                <label class="form-label small fw-semibold mb-1"> {{ tr("경로 범위") }} </label>
                <select v-model="settings.route_scope" class="form-select form-select-sm mb-1">
                  <option value="policy"> {{ tr("스플릿 — 허용한 곳만 터널로, 나머지는 일반망") }} </option>
                  <option value="full"> {{ tr("잠금 — 전부 터널로, 정책 밖은 차단 (인터넷도 차단)") }} </option>
                </select>
                <p v-if="settings.route_scope === 'full'"
                   class="text-warning-emphasis small mb-3"> {{ tr("잠금은 이 정책을 쓰는 단말에서 인터넷 접속까지 막습니다. 전용 임상 단말이 아니면 스플릿을 쓰세요.") }} </p>
                <p v-else class="text-muted small mb-3"> {{ tr("단말은 병원 서버 외에는 평소처럼 인터넷을 씁니다.") }} </p>

                <label class="form-label small fw-semibold mb-1"> {{ tr("DNS 서버") }} <span class="text-muted fw-normal"> {{ tr("(쉼표 구분, IP만)") }} </span>
                </label>
                <input v-model="dnsServersText" class="form-control form-control-sm mb-1"
                       placeholder="10.10.1.53" />
                <p class="text-muted small mb-3"> {{ tr("리졸버 IP는 허용 대상에 자동 포함되므로 CIDR로 따로 넣지 마세요.") }} </p>

                <label class="form-label small fw-semibold mb-1"> {{ tr("검색 도메인") }} </label>
                <input v-model="searchDomainsText" class="form-control form-control-sm mb-1"
                       placeholder="hospital.local" />
                <p class="text-muted small mb-3"> {{ tr("짧은 이름 뒤에 붙습니다.") }} <code>emr</code> → <code>emr.hospital.local</code>
                </p>

                <!--
                  Rendered verbatim from the API so a script driving these
                  endpoints sees the same warning the console does.
                -->
                <div v-if="settings.dns_scope_warning"
                     class="alert alert-warning py-2 small mb-3">
                  <strong> {{ tr("주의") }} </strong> {{ tr(settings.dns_scope_warning) }}
                </div>

                <button class="btn btn-sm btn-primary" :disabled="savingSettings"
                        @click="saveSettings">
                  {{ tr(savingSettings ? '저장 중…' : '터널 설정 저장') }}
                </button>
              </div>
              <p v-else class="text-muted small mb-0"> {{ tr("불러오는 중…") }} </p>
            </div>
          </div>

          <!-- ===== 호스트명 규칙 ===== -->
          <div class="card mt-3">
            <div class="card-header py-2 d-flex justify-content-between align-items-center">
              <strong class="small"> {{ tr("호스트명 규칙") }} </strong>
              <span v-if="unguardedCount > 0" class="badge bg-warning-subtle text-warning-emphasis"> {{ tr("허용 범위 없음 {0}건", [unguardedCount]) }} </span>
            </div>
            <div class="card-body">
              <div v-if="hostnameErr" class="alert alert-danger py-2 small">{{ tr(hostnameErr) }}</div>

              <p class="text-muted small"> {{ tr("IP 대신 이름으로 정책을 쓸 수 있습니다. 컨트롤러가 주기적으로 해석해 허용 목록에 반영하므로, 서버 IP가 바뀌어도 정책을 고칠 필요가 없습니다.") }} </p>

              <div class="row g-2 mb-2">
                <div class="col-md-5">
                  <input v-model="newHostname" class="form-control form-control-sm"
                         placeholder="emr.hospital.local" />
                </div>
                <div class="col-md-4">
                  <input v-model="newGuard" class="form-control form-control-sm"
                         :placeholder="tr(&quot;허용 범위 10.10.0.0/16&quot;)" />
                </div>
                <div class="col-md-3">
                  <button class="btn btn-sm btn-outline-primary w-100"
                          :disabled="addingHostname || !newHostname.trim()"
                          @click="addHostname"> {{ tr("추가") }} </button>
                </div>
              </div>
              <input v-model="newHostDesc" class="form-control form-control-sm mb-2"
                     :placeholder="tr(&quot;설명 (선택)&quot;)" />

              <!--
                The guard is not optional advice. Whoever controls the DNS
                answer controls the ACL, so a rule without one lets a
                spoofed or compromised resolver point the name anywhere and
                the gateway will permit it.
              -->
              <div class="alert alert-secondary py-2 small">
                <strong> {{ tr("허용 범위를 꼭 채우세요.") }} </strong> {{ tr("비워두면 DNS 답변을 조작할 수 있는 쪽이 접근 권한을 정하게 됩니다. 범위를 지정하면 그 밖으로 해석된 답변은 기록을 남기고 버려집니다.") }} </div>

              <table v-if="hostnames.length" class="table table-sm align-middle mb-0">
                <thead>
                  <tr>
                    <th> {{ tr("호스트명") }} </th>
                    <th> {{ tr("허용 범위") }} </th>
                    <th> {{ tr("현재 해석 결과") }} </th>
                    <th class="text-end"></th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="h in hostnames" :key="h.id">
                    <td>
                      <code>{{ h.hostname }}</code>
                      <div v-if="h.description" class="text-muted small">{{ h.description }}</div>
                    </td>
                    <td>
                      <code v-if="h.guard_cidr">{{ h.guard_cidr }}</code>
                      <span v-else class="badge bg-warning-subtle text-warning-emphasis"> {{ tr("없음") }} </span>
                    </td>
                    <td>
                      <span v-if="h.resolved.length" class="small">
                        <code v-for="r in h.resolved" :key="r" class="me-1">{{ r }}</code>
                      </span>
                      <span v-else class="text-muted small"> {{ tr("아직 해석되지 않음") }} </span>
                    </td>
                    <td class="text-end">
                      <button class="btn btn-sm btn-outline-danger"
                              @click="removeHostname(h.id)"> {{ tr("삭제") }} </button>
                    </td>
                  </tr>
                </tbody>
              </table>
              <p v-else class="text-muted small text-center mb-0 py-2"> {{ tr("등록된 호스트명이 없습니다.") }} </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

    <AidotDialog
      :open="askDelete" :title="tr(&quot;정책 삭제&quot;)" tone="danger" :confirm-label="tr(&quot;삭제&quot;)"
      :busy="dlgBusy" :error="dlgErr"
      @update:open="askDelete = false" @confirm="confirmDeletePolicy"
    >
      <p class="mb-1" v-if="detail">
        <strong>{{ detail.name }}</strong> {{ tr("을(를) 삭제합니다.") }} </p>
      <p class="text-muted mb-0" style="font-size:.84rem"> {{ tr("이 정책을 쓰던 디바이스는 정책 없음 상태가 되어 연결이 거부됩니다.") }} </p>
    </AidotDialog>

    <AidotDialog
      :open="!!askRemoveCidr" :title="tr(&quot;허용 주소 제거&quot;)" tone="danger" :confirm-label="tr(&quot;제거&quot;)"
      :busy="dlgBusy" :error="dlgErr"
      @update:open="askRemoveCidr = null" @confirm="confirmRemoveCidr"
    >
      <p class="mb-0"> {{ tr("이 주소를 정책에서 제거합니다.") }} </p>
    </AidotDialog>

    <!--
      정책별 추적 — what changed, and who it reaches.
      The devices come first: before editing a policy the question is
      "who does this touch", and the history answers the follow-up,
      "why is it like this".
    -->
    <AidotDialog
      :open="tracing"
      :title="tr(detail ? '추적 — ' + detail.name : '추적')"
      confirm-only
      @update:open="(v) => { if (!v) tracing = false }"
      @confirm="tracing = false"
    >
      <div class="mb-3">
        <div class="fw-semibold small mb-1"> {{ tr("지금 이 정책을 쓰는 단말 {0}대", [traceDevices.length]) }} </div>
        <div v-if="!traceDevices.length" class="text-muted small"> {{ tr("없습니다.") }} </div>
        <div v-else class="d-flex flex-wrap gap-2">
          <span v-for="d in traceDevices" :key="d.name" class="badge bg-secondary-subtle text-secondary-emphasis">
            {{ d.name }}
          </span>
        </div>
        <div class="text-muted mt-1" style="font-size:.75rem"> {{ tr("정책을 고치면 이 단말들에 전달됩니다.") }} </div>
      </div>

      <div class="fw-semibold small mb-1"> {{ tr("이 정책에 있었던 일") }} </div>
      <div v-if="traceBusy" class="text-muted small"> {{ tr("불러오는 중…") }} </div>
      <div v-else-if="traceErr" class="alert alert-danger py-2 small">{{ tr(traceErr) }}</div>
      <div v-else-if="!traceEvents.length" class="text-muted small"> {{ tr("기록이 없습니다.") }} </div>
      <table v-else class="table table-sm align-middle mb-0">
        <tbody>
          <tr v-for="(e, i) in traceEvents" :key="i">
            <td class="small text-muted" style="width:11rem">{{ new Date(e.at).toLocaleString(localeTag) }}</td>
            <td class="small" style="width:4.5rem">{{ tr(e.actor) }}</td>
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
    </AidotDialog>

</template>

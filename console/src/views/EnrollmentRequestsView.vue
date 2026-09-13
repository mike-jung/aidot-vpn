<script setup>
import { translate as tr, localeTag } from '../i18n/index.js'
/**
 * 등록 요청 — approve devices that asked to enrol.
 *
 * Replaces the copy-a-token flow, which asked someone to move 38
 * characters onto a phone with no channel to do it.
 *
 * The operator's job here is one comparison: the six digits on the
 * handset in front of them against the six digits in the row. That is
 * the authorisation — the shared password only decides who may join the
 * queue.
 *
 * So the code is the largest thing on each row, and approving opens a
 * dialog that shows it again beside the policy picker rather than
 * acting on the click. A one-click approve would make the comparison
 * skippable, which removes the only real check in the flow.
 */
import { computed, onMounted, ref } from 'vue'
import { enrollmentRequests, policies as policiesApi } from '@/api/client.js'
import AidotIcon from '../components/AidotIcon.vue'
import AidotDialog from '../components/AidotDialog.vue'

const requests = ref([])
const policies = ref([])
const loading = ref(false)
const error = ref('')

const approving = ref(null)
const chosenPolicy = ref('')
const busy = ref(false)
const dialogError = ref('')

const rejecting = ref(null)
const approved = ref('')

// 최근 처리 showed slice(0, 10) — the rest existed and was unreachable,
// which is worse than a long list: the operator cannot tell whether the
// request they are looking for was handled or never arrived.
const decidedPerPage = 10
const decidedPage = ref(1)
const decidedPages = computed(() =>
  Math.max(1, Math.ceil(decided.value.length / decidedPerPage)))
const decidedPaged = computed(() =>
  decided.value.slice((decidedPage.value - 1) * decidedPerPage, decidedPage.value * decidedPerPage))

// The shared password, shown here rather than on 설정.
//
// This is the screen an admin is looking at while someone stands next to
// them with a phone, and "what do I type?" is the question they have at
// that moment. Putting it two clicks away in 설정 would mean looking it
// up somewhere else every time.
const sharedPassword = ref('')
const isDefaultPassword = ref(false)
const showPassword = ref(false)
const changing = ref(false)
const newPassword = ref('')
const pwBusy = ref(false)
const pwError = ref('')

const pending = computed(() => requests.value.filter((r) => r.status === 'pending'))
const decided = computed(() => requests.value.filter((r) => r.status !== 'pending'))

const STATUS = {
  pending: { label: '승인 대기', cls: 'wait' },
  approved: { label: '승인됨', cls: 'ok' },
  rejected: { label: '거절됨', cls: 'off' },
  expired: { label: '시간 초과', cls: 'off' },
}

async function load () {
  loading.value = true
  error.value = ''
  try {
    const [r, p, pw] = await Promise.all([
      enrollmentRequests.list(),
      policiesApi.list(),
      enrollmentRequests.getPassword(),
    ])
    requests.value = r.requests || []
    policies.value = p.policies || []
    sharedPassword.value = pw.password || ''
    isDefaultPassword.value = !!pw.is_default
    lastLoaded.value = new Date()
  } catch (e) {
    error.value = e.message || '불러오지 못했습니다'
  } finally {
    loading.value = false
  }
}

// Loaded on open and on request.
//
// This polled every five seconds, which made the whole page twitch —
// timers restarting, "N분 남음" counting down, rows appearing under the
// cursor. The operator is standing here with a phone in hand and knows
// exactly when they pressed the button; a refresh they control is
// calmer and no slower.
//
// The device side does not poll at all any more: it holds a connection
// and the controller answers the moment 승인 is clicked.
const lastLoaded = ref(null)

onMounted(load)

function openChange () {
  newPassword.value = ''
  pwError.value = ''
  changing.value = true
}

async function confirmChange () {
  pwBusy.value = true
  pwError.value = ''
  try {
    const res = await enrollmentRequests.setPassword(newPassword.value)
    sharedPassword.value = res.password
    isDefaultPassword.value = false
    changing.value = false
  } catch (e) {
    pwError.value = e.message || '바꾸지 못했습니다'
  } finally {
    pwBusy.value = false
  }
}

function openApprove (r) {
  approving.value = r
  // No preselection.
  //
  // This defaulted to the first policy in the list, so approving without
  // touching the dropdown bound a device to whichever policy happened to
  // sort first — an access decision nobody made. The operator then sees
  // a policy on the device they never chose.
  //
  // Empty means the admin picks, and the warning under the dropdown says
  // what an empty choice costs.
  chosenPolicy.value = ''
  dialogError.value = ''
}

async function confirmApprove () {
  busy.value = true
  dialogError.value = ''
  try {
    await enrollmentRequests.approve(approving.value.id, chosenPolicy.value)
    const name = approving.value.display_name
    approving.value = null
    await load()
    // Said once, where the decision was made. An operator who wants it
    // back should not have to guess which screen owns the reversal.
    approved.value = name
  } catch (e) {
    dialogError.value = e.message || '승인하지 못했습니다'
  } finally {
    busy.value = false
  }
}

async function confirmReject () {
  busy.value = true
  dialogError.value = ''
  try {
    await enrollmentRequests.reject(rejecting.value.id)
    rejecting.value = null
    await load()
  } catch (e) {
    dialogError.value = e.message || '거절하지 못했습니다'
  } finally {
    busy.value = false
  }
}

/** Minutes left before a request expires, for the waiting rows. */
function minutesLeft (iso) {
  const ms = new Date(iso) - Date.now()
  return ms <= 0 ? 0 : Math.ceil(ms / 60000)
}

function fmt (iso) {
  const d = iso instanceof Date ? iso : new Date(iso)
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}
</script>

<template>
  <div>
    <h1 class="h3 mb-1"> {{ tr("등록 요청") }} </h1>
    <p class="text-muted small mb-3"> {{ tr("폰에서 등록을 요청하면 여기에 나타납니다.") }} <strong> {{ tr("폰 화면의 숫자와 아래 숫자가 같은지 확인한 뒤") }} </strong> {{ tr("승인하세요.") }} </p>

    <div v-if="error" class="alert alert-danger py-2 small">{{ tr(error) }}</div>

    <div v-if="approved" class="alert alert-success py-2 small d-flex justify-content-between align-items-center">
      <span>
        <strong>{{ approved }}</strong> {{ tr("을(를) 승인했습니다. 폰 화면이 곧 바뀝니다.") }} <span class="text-muted"> {{ tr("되돌리려면 디바이스 에서 폐기하세요.") }} </span>
      </span>
      <button type="button" class="btn-close btn-sm" :aria-label="tr(&quot;닫기&quot;)" @click="approved = ''" />
    </div>


    <div class="pw-card" :class="{ warn: isDefaultPassword }">
      <div>
        <div class="pw-label"> {{ tr("등록 비밀번호") }} </div>
        <div class="pw-value">
          <code>{{ showPassword ? sharedPassword : '•'.repeat(sharedPassword.length || 8) }}</code>
          <button type="button" class="btn btn-sm btn-link p-0 ms-2"
                  @click="showPassword = !showPassword">
            {{ tr(showPassword ? '숨기기' : '보기') }}
          </button>
        </div>
        <div v-if="isDefaultPassword" class="pw-warn"> {{ tr("설치할 때 넣어둔 기본값입니다. 실제로 쓰기 전에 바꾸세요.") }} </div>
        <div v-else class="pw-hint"> {{ tr("폰에서 등록할 때 이 값을 입력합니다.") }} </div>
      </div>
      <button type="button" class="btn btn-outline-secondary btn-sm" @click="openChange"> {{ tr("변경") }} </button>
    </div>

    <!-- 대기 중 -->
    <div class="card mb-4">
      <div class="card-header py-2 d-flex justify-content-between align-items-center">
        <strong> {{ tr("승인 대기 {0}", [pending.length ? `(${pending.length})` : '']) }} </strong>
        <span class="d-flex align-items-center gap-2">
          <span v-if="lastLoaded" class="text-muted" style="font-size:.76rem">
             {{ tr("{0} 기준", [fmt(lastLoaded)]) }} </span>
          <button
            type="button" class="btn btn-outline-secondary btn-sm"
            :disabled="loading" @click="load"
          >{{ tr(loading ? '읽는 중…' : '새로고침') }}</button>
        </span>
      </div>
      <div class="card-body p-0">
        <div v-if="loading && !requests.length" class="p-4 text-center text-muted small"> {{ tr("불러오는 중…") }} </div>
        <div v-else-if="!pending.length" class="p-5 text-center">
          <div class="fw-bold mb-1"> {{ tr("기다리는 요청이 없습니다.") }} </div>
          <div class="text-muted small mb-3"> {{ tr("폰에서 앱을 열고 등록 비밀번호를 입력하면 여기에 나타납니다.") }} </div>

          <!--
            An empty list is the same picture whether nothing was sent or
            something went to the wrong place. That ambiguity is what the
            report was about: the password was accepted on the phone and
            the console showed nothing, with no way to tell which.

            So the screen says what it would have to be true for a
            request to appear here, in the order worth checking.
          -->
          <details class="text-start d-inline-block small">
            <summary class="text-primary" style="cursor:pointer"> {{ tr("폰에서는 보냈는데 여기에 없다면") }} </summary>
            <ul class="text-muted mt-2 mb-0 ps-3">
              <li> {{ tr("폰의 앱이") }} <strong> {{ tr("이 서버") }} </strong> {{ tr("를 보고 있나요? 앱에 넣은 주소가") }} <code>localhost</code> {{ tr("면 폰 자기 자신을 가리킵니다. 컴퓨터 IP 여야 합니다.") }} </li>
              <li> {{ tr("요청은") }} <strong> {{ tr("10분") }} </strong> {{ tr("뒤 만료됩니다. 아래 “최근 처리” 에") }} <em> {{ tr("시간 초과") }} </em> {{ tr("로 남아 있는지 보세요.") }} </li>
              <li> {{ tr("위의") }} <strong> {{ tr("새로고침") }} </strong> {{ tr("을 눌러 다시 읽어보세요. 그래도 없으면 브라우저에서 Ctrl+Shift+R 로 강력 새로고침 해보세요.") }} </li>
            </ul>
          </details>
        </div>
        <div v-for="r in pending" :key="r.id" class="req">
          <div class="req-code">{{ r.verification_code }}</div>
          <div class="req-main">
            <div class="req-name">{{ r.display_name }}</div>
            <div class="req-sub">
               {{ tr("{0} · {1} 요청 ·", [r.platform, fmt(r.created_at)]) }} <span class="text-warning-emphasis"> {{ tr("{0}분 남음", [minutesLeft(r.expires_at)]) }} </span>
            </div>
          </div>
          <div class="req-actions">
            <button type="button" class="btn btn-outline-secondary btn-sm" @click="rejecting = r"> {{ tr("거절") }} </button>
            <button type="button" class="btn btn-primary btn-sm" @click="openApprove(r)"> {{ tr("승인") }} </button>
          </div>
        </div>
      </div>
    </div>

    <!-- 처리됨 -->
    <div class="card">
      <div class="card-header py-2 d-flex justify-content-between align-items-center">
        <span>
          <strong> {{ tr("최근 처리") }} </strong>
          <span v-if="!decided.length" class="text-muted ms-2" style="font-size:.78rem"> {{ tr("아직 없습니다") }} </span>
        </span>
        <!--
          Where the reversal lives.
          
          Approving creates a device; that decision is finished. Undoing
          it means invalidating the device, which is 디바이스 → 폐기 —
          a different screen and a different question ("is this handset
          still ours?"). Without this line an operator looks for an undo
          button in a list that is a record, not a control.
        -->
        <RouterLink
          v-if="decided.some((r) => r.status === 'approved')"
          :to="{ name: 'devices' }"
          class="text-decoration-none" style="font-size:.78rem"
        > {{ tr("승인을 취소하려면 디바이스 에서 폐기 →") }} </RouterLink>
      </div>
      <div class="card-body p-0">
        <table class="table table-sm mb-0 align-middle">
          <tbody>
            <tr v-for="r in decidedPaged" :key="r.id">
              <td class="ps-3 fw-semibold">{{ r.display_name }}</td>
              <td class="small font-monospace text-muted">{{ r.verification_code }}</td>
              <td>
                <span class="pill" :class="STATUS[r.status]?.cls">
                  {{ tr(STATUS[r.status]?.label || r.status) }}
                </span>
              </td>
              <td class="small text-muted pe-3">{{ fmt(r.created_at) }}</td>
            </tr>
          </tbody>
        </table>
          <div v-if="decidedPages > 1" class="d-flex justify-content-between align-items-center mt-2">
            <button class="btn btn-sm btn-outline-secondary" type="button"
                    :disabled="decidedPage <= 1" @click="decidedPage--"> {{ tr("← 이전") }} </button>
            <span class="text-muted small">
               {{ tr("{0} / {1}쪽 · 전체 {2}건", [decidedPage, decidedPages, decided.length]) }} </span>
            <button class="btn btn-sm btn-outline-secondary" type="button"
                    :disabled="decidedPage >= decidedPages" @click="decidedPage++"> {{ tr("다음 →") }} </button>
          </div>
      </div>
    </div>

    <AidotDialog
      :open="changing" :title="tr(&quot;등록 비밀번호 변경&quot;)" :confirm-label="tr(&quot;변경&quot;)"
      :busy="pwBusy" :error="pwError"
      @update:open="changing = false" @confirm="confirmChange"
    >
      <p class="mb-2"> {{ tr("새 비밀번호를 정하고, 폰을 등록할 사람에게 알려주세요.") }} </p>
      <input
        v-model="newPassword" class="form-control form-control-sm"
        :placeholder="tr(&quot;6자 이상, 공백 없이&quot;)" @keyup.enter="confirmChange"
      />
      <div class="form-text"> {{ tr("이미 기다리는 요청은 그대로 유지됩니다. 다음 요청부터 새 비밀번호가 필요합니다.") }} </div>
    </AidotDialog>

    <!-- 승인 -->
    <AidotDialog
      :open="!!approving"
      :title="tr(&quot;등록 승인&quot;)"
      :confirm-label="tr(&quot;승인&quot;)"
      :busy="busy"
      :error="dialogError"
      @update:open="approving = null"
      @confirm="confirmApprove"
    >
      <template v-if="approving">
        <p class="mb-2"> {{ tr("폰 화면에 이 숫자가 보이는지 확인하세요.") }} </p>
        <div class="code-box">{{ approving.verification_code }}</div>
        <dl class="row small mb-3">
          <dt class="col-4 text-muted fw-normal"> {{ tr("기기 이름") }} </dt>
          <dd class="col-8">{{ approving.display_name }}</dd>
          <dt class="col-4 text-muted fw-normal"> {{ tr("종류") }} </dt>
          <dd class="col-8">{{ approving.platform }}</dd>
        </dl>

        <label class="form-label small"> {{ tr("적용할 정책") }} </label>
        <select v-model="chosenPolicy" class="form-select form-select-sm">
          <option value=""> {{ tr("(지정하지 않음)") }} </option>
          <option v-for="p in policies" :key="p.id" :value="p.id">{{ p.name }}</option>
        </select>
        <div v-if="!chosenPolicy" class="form-text text-warning"> {{ tr("정책을 골라야 합니다. 지정하지 않으면 등록은 되지만 아무 데도 갈 수 없습니다.") }} </div>
      </template>
    </AidotDialog>

    <!-- 거절 -->
    <AidotDialog
      :open="!!rejecting"
      :title="tr(&quot;등록 거절&quot;)"
      tone="danger"
      :confirm-label="tr(&quot;거절&quot;)"
      :busy="busy"
      :error="dialogError"
      @update:open="rejecting = null"
      @confirm="confirmReject"
    >
      <template v-if="rejecting">
        <p class="mb-1">
          <strong>{{ rejecting.display_name }}</strong> {{ tr("의 등록 요청을 거절합니다.") }} </p>
        <p class="text-muted mb-0" style="font-size:.84rem"> {{ tr("폰에서 다시 요청할 수 있습니다.") }} </p>
      </template>
    </AidotDialog>
  </div>
</template>

<style scoped>
.pw-card {
  display: flex; align-items: center; justify-content: space-between; gap: 1rem;
  padding: .75rem 1rem; margin-bottom: 1rem;
  background: var(--panel-2); border: 1px solid var(--line); border-radius: 10px;
}
.pw-card.warn { background: var(--warn-soft); border-color: var(--warn); }
.pw-label { font-size: .78rem; color: var(--text-3); }
.pw-value code { font-size: 1.05rem; font-weight: 700; color: var(--text); }
.pw-hint { font-size: .78rem; color: var(--text-3); }
.pw-warn { font-size: .78rem; color: var(--warn); font-weight: 600; }

.req {
  display: flex; align-items: center; gap: 1rem;
  padding: .85rem 1rem; border-bottom: 1px solid var(--line);
}
.req:last-child { border-bottom: 0; }

/* The comparison is the whole job, so the code is the largest thing on
   the row. Monospace and letter-spaced: six digits read aloud are easier
   to track when they do not run together. */
.req-code {
  font-family: 'Courier New', monospace;
  font-size: 1.6rem; font-weight: 700; letter-spacing: .12em;
  color: var(--text); min-width: 7.2rem;
}
.req-main { flex: 1 1 auto; min-width: 0; }
.req-name { font-weight: 700; color: var(--text); }
.req-sub { font-size: .78rem; color: var(--text-3); }
.req-actions { display: flex; gap: .4rem; flex: 0 0 auto; }

.code-box {
  font-family: 'Courier New', monospace;
  font-size: 2rem; font-weight: 700; letter-spacing: .16em;
  text-align: center; color: var(--text);
  background: var(--good-soft); border: 1px solid var(--good); border-radius: 10px;
  padding: .7rem; margin-bottom: 1rem;
}

.pill {
  display: inline-block; padding: .1rem .5rem; border-radius: 999px;
  font-size: .74rem; font-weight: 600;
}
.pill.wait { background: var(--warn-soft); color: var(--warn); }
.pill.ok { background: var(--good-soft); color: var(--good); }
.pill.off { background: var(--line); color: var(--text-3); }
</style>

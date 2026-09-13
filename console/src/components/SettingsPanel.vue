<script setup>
import { translate as tr, localeTag } from '../i18n/index.js'
// Account, access rules and console connection settings.
import { computed, onMounted, ref } from 'vue'
import LanguageSelect from './LanguageSelect.vue'
import ConsoleConnection from './ConsoleConnection.vue'
import AidotIcon from '../components/AidotIcon.vue'
import { claims } from '../stores/auth'
import { settingsPorts, expiry as expiryAPI, accessRules, totp as totpAPI } from '@/api/client.js'
import { changePassword as authChangePassword } from '@/stores/auth.js'


const showHelp = ref(false)

/**
 * 2단계 인증.
 *
 * Three steps on purpose: the secret is issued, a code from it has to
 * verify, and only then does it apply to logins. Enabling in one call
 * would lock out an admin whose scan silently failed — they would find
 * out at the next login, from the wrong side of the door.
 *
 * The recovery codes are shown once and never again, because they are
 * stored hashed. Saying so on screen matters more than it looks: an
 * admin who assumes they can come back for them later has no second
 * factor and no way in when the phone is lost.
 */
const totpSecret = ref('')
const totpUri = ref('')
const totpCode = ref('')
const recoveryCodes = ref([])
const totpErr = ref('')
const totpBusy = ref(false)

async function startTotp () {
  totpBusy.value = true
  totpErr.value = ''
  recoveryCodes.value = []
  try {
    const r = await totpAPI.setup()
    totpSecret.value = r.secret
    totpUri.value = r.uri
  } catch (e) {
    totpErr.value = e?.message || String(e)
  } finally {
    totpBusy.value = false
  }
}

async function enableTotp () {
  totpBusy.value = true
  totpErr.value = ''
  try {
    const r = await totpAPI.enable(totpCode.value.trim())
    recoveryCodes.value = r.recovery_codes || []
    totpSecret.value = ''
    totpUri.value = ''
    totpCode.value = ''
  } catch (e) {
    totpErr.value = e?.message || String(e)
  } finally {
    totpBusy.value = false
  }
}

const disablePassword = ref('')
async function disableTotp () {
  totpBusy.value = true
  totpErr.value = ''
  try {
    await totpAPI.disable(disablePassword.value)
    disablePassword.value = ''
    recoveryCodes.value = []
    totpErr.value = ''
  } catch (e) {
    totpErr.value = e?.message || String(e)
  } finally {
    totpBusy.value = false
  }
}

// 접근 규칙 — the two rules that decide whether a registered device is
// handed to the gateway at all. They live here rather than on 디바이스
// because they are settings, not per-device actions, and an admin
// looking for "why is that phone not connecting" needs to find them.
const rules = ref({ device_expiry_days: 0, min_os_sdk: 0 })
const rulesSaved = ref('')
async function loadRules () {
  try { rules.value = await accessRules.get() } catch { /* 기본값 유지 */ }
}
async function saveExpiryDefault () {
  await expiryAPI.setDefault(Number(rules.value.device_expiry_days) || 0)
  rulesSaved.value = '기본 기한을 저장했습니다.'
}
async function saveMinOS () {
  await accessRules.setMinOS(Number(rules.value.min_os_sdk) || 0)
  rulesSaved.value = '최소 안드로이드 버전을 저장했습니다.'
}
onMounted(loadRules)

// Password change, in place.
const pwCurrent = ref('')
const pwNew = ref('')
const pwConfirm = ref('')
const pwBusy = ref(false)
const pwErr = ref('')
const pwDone = ref(false)
async function changePassword () {
  pwBusy.value = true; pwErr.value = ''; pwDone.value = false
  try {
    await authChangePassword(pwCurrent.value, pwNew.value)
    pwDone.value = true
    pwCurrent.value = pwNew.value = pwConfirm.value = ''
  } catch (e) {
    pwErr.value = e?.message || String(e)
  } finally {
    pwBusy.value = false
  }
}

// The port map, from the controller's own environment. Not a copy of
// the defaults — the numbers actually in effect, which is what an admin
// checking a firewall needs.
const ports = ref([])
const portsNote = ref('')
const portsErr = ref('')
onMounted(async () => {
  try {
    const d = await settingsPorts.get()
    ports.value = d.ports || []
    portsNote.value = d.note || ''
  } catch (e) {
    portsErr.value = String(e?.message || e)
  }
})

const scopeLabel = { external: '밖에서 열기', admin: '관리자 PC 만', local: '닫기' }
const scopeClass = {
  external: 'bg-success-subtle text-success-emphasis',
  admin: 'bg-secondary-subtle text-secondary-emphasis',
  local: 'bg-danger-subtle text-danger-emphasis',
}

const username = computed(() =>
  claims.value?.preferred_username || claims.value?.sub || '(알 수 없음)')
const email = computed(() => claims.value?.email || '—')
const roles = computed(() => {
  const r = claims.value?.realm_access?.roles || []
  // Keycloak adds several built-ins that mean nothing to an operator
  // reading this screen.
  const noise = new Set(['offline_access', 'uma_authorization', 'default-roles-aidotvpn'])
  return r.filter((x) => !noise.has(x))
})

/** True while the default password is still in use, as far as we can tell.
 *
 *  We cannot read the password, so this is a heuristic on the account
 *  name — deliberately a weak signal shown as a reminder, not a claim.
 *  It is better to nag an admin who already rotated than to stay silent
 *  for one who never did.
 */
const looksDefault = computed(() => username.value === 'admin')

</script>

<template>
  <LanguageSelect id="settings-language" />
  <ConsoleConnection />
    <section class="mb-4">
      <h3 class="h6"> {{ tr("2단계 인증") }} </h3>
      <p class="text-muted small"> {{ tr("비밀번호만으로는 이 콘솔에 들어올 수 없게 합니다. 인증 앱(Google Authenticator, 1Password 등)의 6자리 숫자를 함께 입력하게 됩니다.") }} </p>

      <div v-if="totpErr" class="alert alert-danger py-2 small">{{ tr(totpErr) }}</div>

      <template v-if="recoveryCodes.length">
        <div class="alert alert-warning py-2">
          <div class="fw-semibold mb-1"> {{ tr("2단계 인증을 켰습니다. 아래 복구 코드를 지금 저장하세요.") }} </div>
          <div class="small mb-2"> {{ tr("이 화면을 닫으면 다시 볼 수 없습니다. 서버에는 원본 대신 해시를 저장하므로 복원할 수 없습니다. 인증 기기를 잃어버렸을 때를 대비해 안전하게 보관하세요.") }} </div>
          <div class="d-flex flex-wrap gap-2">
            <code v-for="c in recoveryCodes" :key="c" class="recovery-code">{{ c }}</code>
          </div>
        </div>
      </template>

      <template v-else-if="totpSecret">
        <div class="mb-2 small"> {{ tr("인증 앱에 아래 열쇠를 등록한 다음, 앱에 뜨는 6자리 숫자를 넣고 [켜기] 를 누르세요.") }} </div>
        <code class="d-block mb-2 p-2 totp-secret">{{ totpSecret }}</code>
        <div class="row g-2 align-items-end">
          <div class="col-auto">
            <label class="form-label small text-muted mb-1"> {{ tr("인증 앱의 숫자") }} </label>
            <input v-model="totpCode" class="form-control form-control-sm"
                   inputmode="numeric" maxlength="6" placeholder="000000" style="width: 8rem" />
          </div>
          <div class="col-auto">
            <button class="btn btn-sm btn-primary" type="button"
                    :disabled="totpBusy || totpCode.trim().length < 6" @click="enableTotp"> {{ tr("켜기") }} </button>
          </div>
        </div>
      </template>

      <template v-else>
        <div class="d-flex flex-wrap gap-2 align-items-end">
          <button class="btn btn-sm btn-outline-primary" type="button"
                  :disabled="totpBusy" @click="startTotp"> {{ tr("2단계 인증 켜기") }} </button>
          <div class="vr d-none d-md-block" />
          <div>
            <label class="form-label small text-muted mb-1"> {{ tr("끄려면 비밀번호") }} </label>
            <input v-model="disablePassword" type="password"
                   class="form-control form-control-sm" style="width: 12rem" />
          </div>
          <button class="btn btn-sm btn-outline-danger" type="button"
                  :disabled="totpBusy || !disablePassword" @click="disableTotp"> {{ tr("끄기") }} </button>
        </div>
        <div class="form-text"> {{ tr("끌 때 비밀번호를 다시 묻습니다. 2단계를 끄는 것은 그것이 막아 주던 모든 것을 되돌리는 일이라, 잠기지 않은 화면에서 빌린 세션만으로는 부족합니다.") }} </div>
      </template>
    </section>

    <section class="mb-4">
      <h3 class="h6"> {{ tr("접근 규칙") }} </h3>
      <p class="text-muted small"> {{ tr("등록된 단말이라도 이 규칙에 걸리면 문지기가 받지 않습니다. 폐기와는 다릅니다 — 규칙을 풀면 바로 돌아옵니다.") }} </p>

      <div class="row g-2 align-items-end mb-2">
        <div class="col-auto">
          <label class="form-label small text-muted mb-1"> {{ tr("새 단말 기본 기한 (일)") }} </label>
          <input v-model="rules.device_expiry_days" type="number" min="0"
                 class="form-control form-control-sm" style="width: 8rem" />
        </div>
        <div class="col-auto">
          <button class="btn btn-sm btn-outline-primary" type="button" @click="saveExpiryDefault"> {{ tr("저장") }} </button>
        </div>
        <div class="col text-muted small"> {{ tr("0 이면 기한 없음") }} </div>
      </div>

      <div class="row g-2 align-items-end">
        <div class="col-auto">
          <label class="form-label small text-muted mb-1"> {{ tr("최소 안드로이드 (API 레벨)") }} </label>
          <input v-model="rules.min_os_sdk" type="number" min="0"
                 class="form-control form-control-sm" style="width: 8rem" />
        </div>
        <div class="col-auto">
          <button class="btn btn-sm btn-outline-primary" type="button" @click="saveMinOS"> {{ tr("저장") }} </button>
        </div>
        <div class="col text-muted small"> {{ tr("0 이면 검사 안 함 · 34 = 안드로이드 14 · 보고하지 않는 단말은 통과합니다") }} </div>
      </div>

      <div v-if="rulesSaved" class="text-success small mt-2">{{ tr(rulesSaved) }}</div>
    </section>

  <div class="settings-panel">
<div class="row g-3">
      <div class="col-lg-6">
        <div class="card h-100">
          <div class="card-header py-2"><strong> {{ tr("내 계정") }} </strong></div>
          <div class="card-body">
            <dl class="row mb-0 small">
              <dt class="col-4 text-muted fw-normal"> {{ tr("아이디") }} </dt>
              <dd class="col-8"><code>{{ username }}</code></dd>

              <dt class="col-4 text-muted fw-normal"> {{ tr("이메일") }} </dt>
              <dd class="col-8">{{ email }}</dd>

              <dt class="col-4 text-muted fw-normal"> {{ tr("권한") }} </dt>
              <dd class="col-8">
                <span v-if="!roles.length" class="text-muted"> {{ tr("없음") }} </span>
                <span
                  v-for="r in roles"
                  :key="r"
                  class="badge bg-secondary me-1"
                >{{ tr(r) }}</span>
              </dd>
            </dl>
          </div>
        </div>
      </div>

      <div class="col-lg-6">
        <div class="card h-100">
          <div class="card-header py-2"><strong> {{ tr("비밀번호") }} </strong></div>
          <div class="card-body">
            <!--
              The form lives here. It used to be a button that opened an
              external identity server's account page in a new tab. The
              controller keeps admin passwords itself now (argon2id), so
              the change is one request from this dialog.
            -->
            <div class="mb-2">
              <label class="form-label small mb-1"> {{ tr("현재 비밀번호") }} </label>
              <input v-model="pwCurrent" type="password" class="form-control form-control-sm" autocomplete="current-password" />
            </div>
            <div class="mb-2">
              <label class="form-label small mb-1"> {{ tr("새 비밀번호") }} </label>
              <input v-model="pwNew" type="password" class="form-control form-control-sm" autocomplete="new-password" />
            </div>
            <div class="mb-3">
              <label class="form-label small mb-1"> {{ tr("새 비밀번호 확인") }} </label>
              <input v-model="pwConfirm" type="password" class="form-control form-control-sm" autocomplete="new-password" />
            </div>
            <div v-if="pwErr" class="alert alert-danger py-2 small">{{ tr(pwErr) }}</div>
            <div v-if="pwDone" class="alert alert-success py-2 small"> {{ tr("비밀번호를 바꿨습니다. 다음 로그인부터 적용됩니다.") }} </div>
            <button
              type="button" class="btn btn-primary btn-sm"
              :disabled="pwBusy || !pwCurrent || !pwNew || pwNew !== pwConfirm"
              @click="changePassword"
            >{{ tr(pwBusy ? '바꾸는 중…' : '비밀번호 변경') }}</button>
            <div class="form-text mt-2"> {{ tr("8자 이상. 확인 비밀번호가 다르면 버튼이 눌리지 않습니다.") }} </div>
          </div>
        </div>
      </div>


      <!--
        Every port, as the controller read it. Same rows as
        `npm run ports`, without the terminal.
      -->
      <div class="col-12">
        <div class="card">
          <div class="card-header py-2 d-flex justify-content-between align-items-center">
            <strong> {{ tr("포트") }} </strong>
            <span class="text-muted" style="font-size:.78rem">{{ tr(portsNote) }}</span>
          </div>
          <div class="card-body p-0">
            <div v-if="portsErr" class="alert alert-danger py-2 small m-3">{{ tr(portsErr) }}</div>
            <div v-else class="table-responsive"><table class="table table-sm mb-0 align-middle">
              <thead>
                <tr><th class="ps-3"> {{ tr("이름") }} </th><th> {{ tr("포트") }} </th><th> {{ tr(".env 변수") }} </th><th> {{ tr("용도") }} </th><th class="pe-3"> {{ tr("방화벽") }} </th></tr>
              </thead>
              <tbody>
                <tr v-for="p in ports" :key="p.env">
                  <td class="ps-3 fw-medium">{{ tr(p.name) }}</td>
                  <td><code>{{ p.port }}/{{ p.proto }}</code></td>
                  <td><code class="text-muted">{{ p.env }}</code></td>
                  <td class="text-muted small">{{ tr(p.reason) }}</td>
                  <td class="pe-3"><span class="badge" :class="scopeClass[p.scope]">{{ tr(scopeLabel[p.scope]) }}</span></td>
                </tr>
              </tbody>
            </table></div>
          </div>
        </div>
      </div>

    </div>
  </div>
</template>

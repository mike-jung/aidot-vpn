<script setup>
import { translate as tr, localeTag } from '../i18n/index.js'
/**
 * The landing page.
 *
 * It used to be a spinner and an immediate redirect to Keycloak — so the
 * first thing an admin saw was Keycloak's default theme, which is where
 * the "구식" impression came from. Now there is a page of our own: the
 * mark, one sentence, one button. Returning users with a live session
 * skip it.
 *
 * Design references: cctv-gateway's login (three parallax waves along
 * the bottom, stilled under prefers-reduced-motion) and aidot-delivery's
 * cards (translucent glass over an aurora gradient). One accent, large
 * radii, nothing decorative that does not also orient the reader.
 */
import { ref } from 'vue'
import LanguageSelect from '../components/LanguageSelect.vue'
import { useRoute, useRouter } from 'vue-router'
import { login, mustChangePassword } from '@/stores/auth.js'
import { loginDestination, navigateAfterLogin } from '@/router/login-navigation.js'

const router = useRouter()
const route = useRoute()
const email = ref('')
const password = ref('')
const code = ref('')
const needCode = ref(false)
const busy = ref(false)
const err = ref('')

async function go () {
  if (busy.value) return
  busy.value = true; err.value = ''
  try {
    await login(email.value, password.value, code.value)
    // A seeded password is used once: straight to the settings dialog.
    const next = loginDestination(router, route.query.next, mustChangePassword.value)
    await navigateAfterLogin(router, next)
  } catch (e) {
    // 428 means the password was right and a second factor is owed.
    // Showing "wrong password" here would send the operator to reset a
    // password that was never the problem.
    if (e?.status === 428) {
      needCode.value = true
      err.value = code.value
        ? '숫자가 맞지 않습니다. 인증 앱의 현재 숫자를 다시 확인하세요.'
        : ''
      return
    }
    err.value = e.message
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="landing">
    <div class="aurora aurora-a" aria-hidden="true" />
    <div class="aurora aurora-b" aria-hidden="true" />

    <main class="panel" role="main">
      <LanguageSelect id="login-language" />
      <img src="/favicon.svg" alt="" class="mark" width="72" height="72" />
      <h1 class="title">AidotVpn</h1>
      <p class="sub"> {{ tr("기관 밖에서 안전한 터널을 통해 데이터를 주고 받습니다.") }} </p>

      <!--
        The form is ours. It used to be a button that sent the admin to
        an external identity server; the controller keeps sessions
        itself now, so the login is one request from this card.
      -->
      <form class="form" @submit.prevent="go">
        <label class="lbl" for="email"> {{ tr("아이디 또는 이메일") }} </label>
        <input id="email" v-model="email" class="inp" type="text" autocomplete="username" autocapitalize="none" :spellcheck="false" required autofocus />
        <label class="lbl" for="password"> {{ tr("비밀번호") }} </label>
        <input id="password" v-model="password" class="inp" type="password" autocomplete="current-password" required />
      <div v-if="needCode" class="mb-3">
        <label class="form-label small"> {{ tr("인증 앱의 6자리 숫자") }} </label>
        <input
          v-model="code" class="form-control" inputmode="numeric"
          autocomplete="one-time-code" maxlength="10" placeholder="000000"
        />
        <div class="form-text"> {{ tr("숫자를 못 쓰면 등록할 때 받은 복구 코드를 대신 입력하세요.") }} </div>
      </div>

        <p v-if="err" class="err" role="alert">{{ tr(err) }}</p>
        <button class="cta" type="submit" :disabled="busy || !email || !password">
          <span v-if="!busy"> {{ tr("로그인") }} </span>
          <span v-else class="cta-busy"><span class="dot" /><span class="dot" /><span class="dot" /></span>
        </button>
      </form>

      <p class="hint"> {{ tr("계정은 관리자가 만듭니다. 비밀번호를 잊었으면 다른 관리자에게 초기화를 요청하세요.") }} </p>
    </main>

    <!--
      Three waves, offset in phase and speed so they drift against each
      other. Pure CSS transforms on inline SVG: no library, no images,
      and the whole thing stops under prefers-reduced-motion.
    -->
    <div class="waves" aria-hidden="true">
      <svg class="wave wave-1" viewBox="0 0 1440 120" preserveAspectRatio="none">
        <path d="M0,64 C240,120 480,0 720,64 C960,128 1200,8 1440,64 L1440,120 L0,120 Z" />
      </svg>
      <svg class="wave wave-2" viewBox="0 0 1440 120" preserveAspectRatio="none">
        <path d="M0,72 C260,20 520,124 780,72 C1040,20 1300,124 1440,72 L1440,120 L0,120 Z" />
      </svg>
      <svg class="wave wave-3" viewBox="0 0 1440 120" preserveAspectRatio="none">
        <path d="M0,80 C300,110 600,40 900,80 C1200,120 1380,50 1440,80 L1440,120 L0,120 Z" />
      </svg>
    </div>

    <footer class="foot">U&amp;S Networks · AIDOT</footer>
  </div>
</template>

<style scoped>
.landing {
  position: relative; min-height: 100vh; overflow: hidden;
  display: grid; place-items: center;
  background:
    radial-gradient(1000px 600px at 15% -10%, rgba(27,132,255,.18), transparent 60%),
    radial-gradient(800px 500px at 100% 10%, rgba(114,57,234,.14), transparent 55%),
    linear-gradient(180deg, #0a0f1c 0%, #0b1120 100%);
}
.aurora {
  position: absolute; border-radius: 50%; filter: blur(60px); opacity: .55; pointer-events: none;
}
.aurora-a { width: 46vw; height: 46vw; left: -12vw; top: -14vw; background: radial-gradient(circle, #22d3ee 0%, transparent 65%); }
.aurora-b { width: 40vw; height: 40vw; right: -10vw; top: 6vw; background: radial-gradient(circle, #7239ea 0%, transparent 65%); }

.panel {
  position: relative; z-index: 2;
  width: min(420px, calc(100vw - 2rem));
  padding: 2.75rem 2.25rem 2rem;
  border-radius: 24px;
  background: rgba(17, 24, 39, .55);
  border: 1px solid rgba(255,255,255,.08);
  box-shadow: 0 1px 0 rgba(255,255,255,.06) inset, 0 30px 60px rgba(0,0,0,.45);
  backdrop-filter: blur(18px) saturate(1.2);
  text-align: center;
}
.mark { display: block; margin: 0 auto 1rem; border-radius: 18px; box-shadow: 0 8px 24px rgba(34,211,238,.25); }
.title { font-size: 1.85rem; font-weight: 800; letter-spacing: -.02em; color: var(--text, #e6ebf5); margin: 0; }
.sub { color: var(--text-2, #9aa7c2); margin: .5rem 0 1.75rem; font-size: .95rem; }

.form { display: flex; flex-direction: column; text-align: left; }
.lbl { font-size: .78rem; font-weight: 600; color: var(--text-2, #9aa7c2); margin: .6rem 0 .3rem; }
.inp {
  padding: .7rem .9rem; border-radius: 12px; font: inherit; color: var(--text, #e6ebf5);
  background: rgba(15, 23, 42, .8); border: 1px solid rgba(255,255,255,.1);
}
.inp:focus { outline: none; border-color: #22d3ee; box-shadow: 0 0 0 3px rgba(34,211,238,.2); }
.err { margin: .6rem 0 0; font-size: .82rem; color: #fb7185; }
.cta { margin-top: 1.1rem; }
.cta {
  width: 100%; padding: .9rem 1rem; border: 0; border-radius: 14px;
  font: inherit; font-weight: 700; font-size: 1rem; color: #061018;
  background: linear-gradient(135deg, #22d3ee, #1b84ff);
  box-shadow: 0 10px 24px rgba(27,132,255,.35);
  cursor: pointer; transition: transform .12s ease, box-shadow .12s ease;
}
.cta:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 14px 28px rgba(27,132,255,.45); }
.cta:disabled { opacity: .8; cursor: default; }
.cta-busy { display: inline-flex; gap: 6px; }
.dot { width: 7px; height: 7px; border-radius: 50%; background: #061018; animation: pulse 1s infinite ease-in-out; }
.dot:nth-child(2) { animation-delay: .15s; } .dot:nth-child(3) { animation-delay: .3s; }
@keyframes pulse { 0%,80%,100% { opacity: .25 } 40% { opacity: 1 } }

.hint { margin: 1.1rem 0 0; font-size: .78rem; color: var(--text-3, #6b7896); }

.waves { position: absolute; left: 0; right: 0; bottom: 0; height: 22vh; min-height: 140px; pointer-events: none; }
.wave { position: absolute; left: 0; bottom: 0; width: 200%; height: 100%; }
.wave path { fill: #1b84ff; }
.wave-1 { opacity: .10; animation: drift 26s linear infinite; }
.wave-2 { opacity: .14; animation: drift 19s linear infinite reverse; }
.wave-3 { opacity: .20; animation: drift 13s linear infinite; }
@keyframes drift { from { transform: translateX(0) } to { transform: translateX(-50%) } }
@media (prefers-reduced-motion: reduce) { .wave, .dot { animation: none; } }

.foot { position: absolute; bottom: 1rem; left: 0; right: 0; text-align: center; font-size: .72rem; color: var(--text-3, #6b7896); z-index: 2; }
</style>

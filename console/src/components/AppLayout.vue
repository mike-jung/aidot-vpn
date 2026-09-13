<script setup>
import { translate as tr, localeTag } from '../i18n/index.js'

/**
 * AppLayout — chrome around every authenticated route.
 *
 * Three things beyond the nav links:
 *
 *  1. The rail collapses to an icon-only wall. Persisted, because a
 *     preference that resets on every page load is worse than not
 *     offering one.
 *  2. The user chip opens a menu (프로필 / 설정 / 로그아웃).
 *  3. 프로필 and 로그아웃 open dialogs rather than acting immediately.
 *
 * A native `confirm()` handled logout before. It works, and it looks
 * like a browser error — the wrong register for "are you sure" — and
 * some browsers suppress it outright.
 */
import { computed, onMounted, onBeforeUnmount, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { claims, logout, IDLE_MS } from '@/stores/auth.js'
import { setSessionExpiredHandler } from '@/api/client.js'
import AidotDialog from './AidotDialog.vue'
import AidotIcon from './AidotIcon.vue'
import SettingsPanel from './SettingsPanel.vue'

const router = useRouter()

const username = computed(() => {
  if (!claims.value) return 'admin'
  return claims.value.preferred_username
    || claims.value.email
    || claims.value.sub?.slice(0, 8)
    || 'admin'
})
const email = computed(() => claims.value?.email || '—')
const roles = computed(() => {
  const r = claims.value?.realm_access?.roles || []
  // 로그인 서버's built-ins mean nothing to an operator reading this.
  const noise = new Set(['offline_access', 'uma_authorization', 'default-roles-aidotvpn'])
  return r.filter((x) => !noise.has(x))
})
const initial = computed(() => (username.value[0] || 'A').toUpperCase())

const navItems = [
  // First, because it is the screen an admin should land on.
  { name: 'overview', label: '개요', icon: 'nodes' },
  { name: 'devices', label: '디바이스', icon: 'devices' },
  { name: 'nodes', label: '문지기', icon: 'nodes' },
  { name: 'groups', label: '그룹', icon: 'shield' },
  { name: 'policies', label: '정책', icon: 'policies' },
  { name: 'reach', label: '도달 범위', icon: 'policies' },
  { name: 'enrollment-requests', label: '등록 요청', icon: 'profile' },
  { name: 'trace', label: '추적', icon: 'audit' },
  { name: 'audit', label: '감사 로그', icon: 'audit' },
  { name: 'ha', label: '고가용성 (HA)', icon: 'shield' },
]

const isActive = (name) => router.currentRoute.value.name === name

// ----------------------------------------------------------------- rail

const RAIL_KEY = 'aidotvpn.rail.collapsed'
const collapsed = ref(false)

onMounted(() => {
  // Restored from storage; narrow viewports start collapsed, because a
  // 220px rail costs more than it gives on a laptop screen.
  const saved = localStorage.getItem(RAIL_KEY)
  collapsed.value = saved === null ? window.innerWidth < 1100 : saved === '1'
})
watch(collapsed, (v) => localStorage.setItem(RAIL_KEY, v ? '1' : '0'))

// ------------------------------------------------------------ user menu

const menuOpen = ref(false)
const menuRoot = ref(null)
const showProfile = ref(false)
const showSettings = ref(false)
watch(() => router.currentRoute.value.query, q => { if (q.settings === '1' || q.changePassword === '1') showSettings.value = true }, {immediate: true})
const showLogout = ref(false)
const sessionExpired = ref(false)

function onDocClick (e) {
  if (menuRoot.value && !menuRoot.value.contains(e.target)) menuOpen.value = false
}
function onKey (e) {
  if (e.key !== 'Escape') return
  // Innermost first: Escape closes the thing on top, not everything.
  if (showLogout.value) showLogout.value = false
  else if (showProfile.value) showProfile.value = false
  else if (showSettings.value) showSettings.value = false
  else menuOpen.value = false
}
onMounted(() => {
  document.addEventListener('click', onDocClick)
  document.addEventListener('keydown', onKey)

  // A 401 anywhere ends the session. Registered here rather than in
  // each view: the response is the same wherever it happens, and
  // twelve views each inventing a message is what produced "노드를
  // 불러오지 못했습니다" for an expired token.
  setSessionExpiredHandler(() => { sessionExpired.value = true })
})
onBeforeUnmount(() => {
  document.removeEventListener('click', onDocClick)
  document.removeEventListener('keydown', onKey)
})

// -------------------------------------------------------------- dialogs

function openProfile () { menuOpen.value = false; showProfile.value = true }
function openSettings () { menuOpen.value = false; showSettings.value = true }
/**
 * Straight to login, not through logout.
 *
 * The session is already gone — that is why this dialog is open — so
 * sending the user through 로그인 서버's logout endpoint first does
 * nothing useful and adds a step that can fail. It did fail: the
 * return address was not on 로그인 서버's post-logout list, and the
 * button landed on a "We're sorry" page instead of a login form.
 */
function relogin () {
  sessionExpired.value = false
  router.replace({ name: 'login', query: { next: router.currentRoute.value.fullPath } })
}

function askLogout () { menuOpen.value = false; showLogout.value = true }
async function confirmLogout () { showLogout.value = false; await logout(); router.replace({ name: 'login' }) }


const usingDefault = computed(() => username.value === 'admin')

/**
 * Log out after thirty minutes without interaction.
 *
 * The server expires the session anyway; this makes the browser agree,
 * so an unattended console does not sit there looking usable. Every
 * real interaction resets it — a click, a key, a scroll — and the timer
 * is cleared when the layout unmounts so it cannot fire after a manual
 * logout.
 */
const idleWarning = ref(false)
let idleTimer = null

function armIdleTimer () {
  if (idleTimer) clearTimeout(idleTimer)
  idleWarning.value = false
  idleTimer = setTimeout(async () => {
    idleWarning.value = true
    await logout()
    window.location.assign('/login?reason=idle')
  }, IDLE_MS)
}

const IDLE_EVENTS = ['pointerdown', 'keydown', 'scroll', 'wheel']

onMounted(() => {
  armIdleTimer()
  IDLE_EVENTS.forEach((e) =>
    window.addEventListener(e, armIdleTimer, { passive: true }))
})

onBeforeUnmount(() => {
  if (idleTimer) clearTimeout(idleTimer)
  IDLE_EVENTS.forEach((e) => window.removeEventListener(e, armIdleTimer))
})
</script>

<template>
  <div class="app-shell" :class="{ 'rail-collapsed': collapsed }">
    <aside class="rail">
      <div class="rail-head">
        <span v-if="!collapsed" class="brand">AidotVpn</span>
        <button
          type="button"
          class="rail-toggle"
          :title="tr(collapsed ? '메뉴 펼치기' : '메뉴 줄이기')"
          :aria-label="tr(collapsed ? '메뉴 펼치기' : '메뉴 줄이기')"
          :aria-expanded="!collapsed"
          @click="collapsed = !collapsed"
        >
          <AidotIcon :name="collapsed ? 'expand' : 'collapse'" :size="18" />
        </button>
      </div>

      <nav class="rail-nav">
        <RouterLink
          v-for="item in navItems"
          :key="item.name"
          :to="{ name: item.name }"
          class="rail-link"
          :class="{ active: isActive(item.name) }"
          :title="tr(collapsed ? item.label : undefined)"
        >
          <AidotIcon :name="item.icon" :size="20" />
          <span v-if="!collapsed" class="rail-label">{{ tr(item.label) }}</span>
        </RouterLink>
      </nav>
    </aside>

    <div class="app-main">
      <header class="topbar">
        <div class="spacer" />

        <div ref="menuRoot" class="user-menu">
          <button
            type="button"
            class="user-chip"
            :aria-expanded="menuOpen"
            aria-haspopup="menu"
            @click="menuOpen = !menuOpen"
          >
            <span class="avatar">{{ initial }}</span>
            <span class="user-name">{{ username }}</span>
            <AidotIcon name="chevron-down" :size="16" class="chev" :class="{ up: menuOpen }" />
          </button>

          <div v-if="menuOpen" class="menu" role="menu">
            <div class="menu-head">
              <div class="menu-name">{{ username }}</div>
              <div class="menu-mail">{{ email }}</div>
            </div>
            <button type="button" class="menu-item" role="menuitem" @click="openProfile">
              <AidotIcon name="profile" :size="18" /><span> {{ tr("프로필") }} </span>
            </button>
            <button type="button" class="menu-item" role="menuitem" @click="openSettings">
              <AidotIcon name="settings" :size="18" /><span> {{ tr("설정") }} </span>
            </button>
            <div class="menu-sep" />
            <button type="button" class="menu-item danger" role="menuitem" @click="askLogout">
              <AidotIcon name="logout" :size="18" /><span> {{ tr("로그아웃") }} </span>
            </button>
          </div>
        </div>
      </header>

      <main class="app-content">
        <slot />
      </main>
    </div>

    <AidotDialog
      :open="showLogout"
      :title="tr(&quot;로그아웃&quot;)"
      :confirm-label="tr(&quot;로그아웃&quot;)"
      :cancel-label="tr(&quot;취소&quot;)"
      @update:open="showLogout = false"
      @confirm="confirmLogout"
    >
      <p class="mb-0"> {{ tr("로그아웃하면 이 브라우저의 세션이 끝납니다. 다른 기기의 로그인은 그대로입니다.") }} </p>
    </AidotDialog>

    <AidotDialog
      :open="sessionExpired"
      :title="tr(&quot;로그인이 만료되었습니다&quot;)"
      :confirm-label="tr(&quot;다시 로그인&quot;)"
      :cancel-label="tr(&quot;나중에&quot;)"
      @update:open="sessionExpired = false"
      @confirm="relogin"
    >
      <p class="mb-1"> {{ tr("보안을 위해 일정 시간이 지나면 로그인이 풀립니다.") }} </p>
      <p class="text-muted mb-0" style="font-size:.84rem"> {{ tr("화면의 내용은 만료 이전 것입니다. 다시 로그인하면 최신으로 바뀝니다.") }} </p>
    </AidotDialog>

    <!--
      Settings, as a dialog. It was a page in the left rail; now it opens
      from the user menu, next to 프로필 and 로그아웃, and closes the same
      way. Same cards, same data — SettingsPanel is the old page's body.
    -->
    <AidotDialog :open="showSettings" :title="tr('설정')" wide confirm-only @update:open="showSettings = $event">
      <SettingsPanel v-if="showSettings" />
    </AidotDialog>

    <div v-if="showProfile" class="backdrop" @click.self="showProfile = false">
      <div class="dialog" role="dialog" aria-modal="true" :aria-label="tr(&quot;프로필&quot;)">
        <div class="dialog-head">
          <h2> {{ tr("프로필") }} </h2>
          <button type="button" class="icon-btn" :aria-label="tr(&quot;닫기&quot;)" @click="showProfile = false">
            <AidotIcon name="close" :size="18" />
          </button>
        </div>

        <div class="dialog-body">
          <div class="profile-top">
            <span class="avatar lg">{{ initial }}</span>
            <div>
              <div class="profile-name">{{ username }}</div>
              <div class="profile-mail">{{ email }}</div>
            </div>
          </div>

          <dl class="kv">
            <dt> {{ tr("아이디") }} </dt><dd><code>{{ username }}</code></dd>
            <dt> {{ tr("이메일") }} </dt><dd>{{ email }}</dd>
            <dt> {{ tr("권한") }} </dt>
            <dd>
              <span v-if="!roles.length" class="muted"> {{ tr("없음") }} </span>
              <span v-for="r in roles" :key="r" class="chip">{{ tr(r) }}</span>
            </dd>
          </dl>

          <div v-if="usingDefault" class="warn">
            <AidotIcon name="alert" :size="18" />
            <div>
              <strong> {{ tr("기본 비밀번호를 쓰고 있는 것 같습니다.") }} </strong> {{ tr("설치할 때 넣어둔 값이라 이 문서를 본 사람은 다 압니다. 실제로 쓰기 전에 반드시 바꾸세요.") }} </div>
          </div>

          <div class="pw">
            <div>
              <div class="pw-title"> {{ tr("비밀번호") }} </div>
              <div class="pw-sub"> {{ tr("설정 대화상자에서 바로 바꿉니다.") }} </div>
            </div>
            <button type="button" class="btn primary" @click="showProfile = false; openSettings()">
              <AidotIcon name="key" :size="16" /><span> {{ tr("비밀번호 변경") }} </span>
            </button>
          </div>
        </div>

        <div class="dialog-foot">
          <button type="button" class="btn" @click="showProfile = false"> {{ tr("닫기") }} </button>
        </div>
      </div>
    </div>


  </div>
</template>

<style scoped>
.app-shell { display: flex; min-height: 100vh; background: transparent; }

/* ----------------------------------------------------------------- rail */
.rail {
  width: 220px;
  flex: 0 0 220px;
  background: var(--bg-elev); border-right: 1px solid var(--line);
  color: var(--text-2);
  display: flex;
  flex-direction: column;
  /* Only width animates. Transitioning `all` made the labels fade
     through a half-rendered state on every toggle. */
  transition: width .18s ease, flex-basis .18s ease;
}
.rail-collapsed .rail { width: 64px; flex-basis: 64px; }

.rail-head {
  display: flex; align-items: center; justify-content: space-between;
  gap: .5rem; padding: .85rem .75rem; min-height: 52px;
}
.rail-collapsed .rail-head {
  /* Centred, matching the nav icons below it.
     Left-aligned it sat off-axis from the column of icons it heads —
     visible only in a render, which is why the layout gets one. */
  justify-content: center;
  padding: .85rem 0;
}
.brand { font-weight: 800; color: var(--text); font-size: .95rem; letter-spacing: .02em; }

.rail-toggle {
  display: inline-flex; align-items: center; justify-content: center;
  width: 30px; height: 30px; border-radius: 8px;
  border: 0; background: transparent; color: var(--text-3); cursor: pointer;
  transition: background .12s ease, color .12s ease;
}
.rail-toggle:hover { background: var(--panel-2); color: var(--text); }
.rail-toggle:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }

.rail-nav { display: flex; flex-direction: column; gap: 2px; padding: .25rem .5rem; }
.rail-link {
  display: flex; align-items: center; gap: .7rem;
  padding: .55rem .6rem; border-radius: 9px;
  color: var(--text-2); text-decoration: none; font-size: .9rem;
  transition: background .12s ease, color .12s ease;
  white-space: nowrap;
}
.rail-collapsed .rail-link { justify-content: center; padding: .55rem 0; }
.rail-link:hover { background: var(--panel-2); color: var(--text); }
.rail-link.active { background: var(--accent-soft); color: var(--accent-2); font-weight: 700; box-shadow: inset 3px 0 0 var(--accent); }
.rail-label { overflow: hidden; }

/* ----------------------------------------------------------------- main */
.app-main { flex: 1 1 auto; display: flex; flex-direction: column; min-width: 0; }
.topbar {
  display: flex; align-items: center; gap: .75rem;
  padding: .5rem 1rem; min-height: 52px;
  background: rgba(17, 24, 39, .85); backdrop-filter: blur(8px); border-bottom: 1px solid var(--line);
  /* backdrop-filter creates a stacking context, so the menu's z-index
     only competes inside the bar. Without this the bar itself sat at
     auto and the open menu rendered beneath the page's cards — present
     in the DOM, styled correctly, and invisible. The user's report was
     "there is no logout". */
  position: relative; z-index: 1040;
}
.spacer { flex: 1 1 auto; }
.app-content {
  flex: 1 1 auto;
  min-width: 0;
  /* The views assume their container supplies the gutter — the old
     layout wrapped them in Bootstrap's `p-4` and I dropped it when
     rewriting. Without it every page's heading ran under the rail and
     the toolbar sat flush against the topbar.
     Caught by opening the page in a browser, which is what should have
     happened before shipping the rewrite rather than after. */
  padding: 1.25rem 1.5rem;
}

/* ------------------------------------------------------------ user menu */
.user-menu { position: relative; }
.user-chip {
  display: flex; align-items: center; gap: .5rem;
  padding: .3rem .55rem; border-radius: 9px;
  border: 1px solid transparent; background: transparent; cursor: pointer;
  color: var(--text); font-size: .88rem;
  transition: background .12s ease, border-color .12s ease;
}
.user-chip:hover { background: var(--panel-2); border-color: var(--line); }
.user-chip:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
.avatar {
  display: inline-flex; align-items: center; justify-content: center;
  width: 28px; height: 28px; border-radius: 50%;
  background: var(--accent); color: var(--text); font-weight: 700; font-size: .82rem;
}
.avatar.lg { width: 46px; height: 46px; font-size: 1.15rem; }
.user-name { font-weight: 600; }
.chev { color: var(--text-3); transition: transform .15s ease; }
.chev.up { transform: rotate(180deg); }

.menu {
  position: absolute; right: 0; top: calc(100% + 6px);
  min-width: 226px; background: var(--panel); border: 1px solid var(--line);
  border-radius: 12px; box-shadow: 0 10px 28px rgba(16,57,75,.14);
  padding: .35rem; z-index: 1050;
}
.menu-head { padding: .55rem .6rem .5rem; border-bottom: 1px solid var(--line); margin-bottom: .3rem; }
.menu-name { font-weight: 700; font-size: .9rem; color: var(--text); }
.menu-mail { font-size: .76rem; color: var(--text-3); word-break: break-all; }
.menu-item {
  display: flex; align-items: center; gap: .6rem; width: 100%;
  padding: .5rem .6rem; border: 0; border-radius: 8px;
  background: transparent; color: var(--text); font-size: .88rem;
  cursor: pointer; text-align: left;
}
.menu-item:hover { background: var(--panel-2); }
.menu-item.danger { color: var(--bad); }
.menu-item.danger:hover { background: var(--bad-soft); }
.menu-sep { height: 1px; background: var(--line); margin: .3rem .2rem; }

/* -------------------------------------------------------------- dialogs */
.backdrop {
  position: fixed; inset: 0; background: rgba(16,57,75,.42);
  display: flex; align-items: center; justify-content: center;
  padding: 1rem; z-index: 1100;
}
.dialog {
  width: 100%; max-width: 480px; background: var(--panel);
  border-radius: 14px; box-shadow: 0 18px 48px rgba(16,57,75,.24);
  overflow: hidden;
}
.dialog.sm { max-width: 380px; }
/* After .dialog so max-width wins; the settings panel has a five-column table. */
.dialog.dialog-wide { max-width: min(1080px, calc(100vw - 2rem)); }
.dialog-body { max-height: 70vh; overflow: auto; }
.dialog-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: .85rem 1rem; border-bottom: 1px solid var(--line);
}
.dialog-head h2 { margin: 0; font-size: 1rem; font-weight: 700; color: var(--text); }
.dialog-body { padding: 1rem; }
.dialog-foot {
  display: flex; justify-content: flex-end; gap: .5rem;
  padding: .75rem 1rem; border-top: 1px solid var(--line); background: var(--panel);
}
.icon-btn {
  display: inline-flex; align-items: center; justify-content: center;
  width: 30px; height: 30px; border: 0; border-radius: 8px;
  background: transparent; color: var(--text-3); cursor: pointer;
}
.icon-btn:hover { background: var(--panel-2); color: var(--text); }

.profile-top { display: flex; align-items: center; gap: .85rem; margin-bottom: 1rem; }
.profile-name { font-weight: 700; font-size: 1.02rem; color: var(--text); }
.profile-mail { font-size: .82rem; color: var(--text-3); }

.kv {
  display: grid; grid-template-columns: 5rem 1fr;
  gap: .45rem .75rem; margin: 0 0 1rem; font-size: .86rem;
}
.kv dt { color: var(--text-3); font-weight: 400; }
.kv dd { margin: 0; color: var(--text); }
.chip {
  display: inline-block; padding: .1rem .45rem; margin-right: .25rem;
  border-radius: 6px; background: var(--accent-soft); color: var(--accent);
  font-size: .76rem; font-weight: 600;
}
.muted { color: var(--text-3); }

.warn {
  display: flex; gap: .6rem; align-items: flex-start;
  padding: .7rem .8rem; margin-bottom: 1rem;
  background: var(--warn-soft); border: 1px solid var(--warn); border-radius: 10px;
  color: var(--text); font-size: .82rem; line-height: 1.45;
}
.warn :deep(svg) { color: var(--warn); margin-top: .1rem; }

.pw {
  display: flex; align-items: center; justify-content: space-between; gap: 1rem;
  padding: .8rem; background: transparent; border: 1px solid var(--line); border-radius: 10px;
}
.pw-title { font-weight: 700; font-size: .9rem; color: var(--text); }
.pw-sub { font-size: .78rem; color: var(--text-3); }

.btn {
  display: inline-flex; align-items: center; gap: .4rem;
  padding: .45rem .85rem; border-radius: 9px;
  border: 1px solid var(--line-2); background: var(--panel); color: var(--text);
  font-size: .86rem; font-weight: 600; cursor: pointer;
  white-space: nowrap;
}
.btn:hover { background: var(--panel-2); }
.btn.primary { background: var(--accent); border-color: var(--accent); color: var(--text); }
.btn.primary:hover { background: var(--accent-2); }
.btn.danger { background: var(--bad); border-color: var(--bad); color: var(--text); }
.btn.danger:hover { background: var(--bad); }
.mb-1 { margin-bottom: .4rem; }
.mb-0 { margin-bottom: 0; }
@media (max-width: 640px) {
  .rail, .rail-collapsed .rail { width:56px; flex-basis:56px; padding-left:4px; padding-right:4px; position:sticky; top:0; height:100dvh; overflow-y:auto; }
  .brand, .rail-label, .rail-toggle { display:none; }
  .rail-head { min-height:16px; }
  .rail-link { justify-content:center; padding:12px 8px; }
  .topbar { padding-left:.5rem; padding-right:.5rem; }
  .user-name { max-width:180px; overflow:hidden; text-overflow:ellipsis; }
  .app-content { padding:.75rem; overflow-x:auto; }
}
</style>

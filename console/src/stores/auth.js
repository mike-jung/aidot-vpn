/**
 * Console auth — a session cookie and three calls.
 *
 * Until 1.8.0 this file was 278 lines of OIDC: PKCE, token exchange,
 * refresh timers, backoff, id_token_hint. All of it existed to talk to
 * Keycloak, which served console login and nothing else. The controller
 * now keeps sessions itself (internal/adminauth); the browser holds an
 * HttpOnly cookie it never reads, and this store holds who is signed in.
 *
 * Refresh: none. The session slides on the server with each request.
 * Logout: one POST; the server deletes the row. No redirect, no hint,
 * no "We're sorry".
 */
import { apiMessage } from '../i18n/index.js'
import { computed, ref } from 'vue'

const _admin = ref(null)
const _checked = ref(false)

export const claims = computed(() => _admin.value ? {
  email: _admin.value.email,
  name: _admin.value.display_name,
  preferred_username: _admin.value.email,
  realm_access: { roles: _admin.value.role === 'admin' ? ['aidotvpn-admin', 'aidotvpn-user'] : ['aidotvpn-user'] },
} : null)
export const admin = computed(() => _admin.value)
export const isAuthenticated = computed(() => !!_admin.value)
export const mustChangePassword = computed(() => !!_admin.value?.must_change_password)

/** Kept for callers that still import it; there is no token any more. */
export const accessToken = computed(() => null)
export async function ensureFresh () {}
export async function refreshForRetry () { return false }


async function call (method, path, body) {
  const resp = await fetch(`/api${path}`, {
    method,
    credentials: 'include',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  })
  let data = null
  try { data = await resp.json() } catch { /* 204 */ }
  return { ok: resp.ok, status: resp.status, data }
}

/** Ask the server who we are. Called once at startup. */
export async function loadSession () {
  const r = await call('GET', '/auth/me')
  _admin.value = r.ok ? r.data.admin : null
  _checked.value = true
  return _admin.value
}
export const sessionChecked = computed(() => _checked.value)

export async function login (email, password, code = '') {
  const r = await call('POST', '/auth/login', { email, password, code })
  if (!r.ok) throw Object.assign(new Error(apiMessage(r.data?.error, r.status)), {status: r.status})
  _admin.value = r.data.admin
  return _admin.value
}

/**
 * 30분 무동작 자동 로그아웃.
 *
 * The server expires an idle session in thirty minutes. Without a timer
 * here the browser keeps showing a console it can no longer use, and the
 * operator finds out when a click fails. Watching real interaction —
 * pointer, key, scroll — rather than a heartbeat is the point: a tab
 * left open on a ward workstation logs itself out, which is the case
 * this exists for.
 */
export const IDLE_MS = 30 * 60 * 1000

export async function logout () {
  await call('POST', '/auth/logout')
  _admin.value = null
}

/** Called by the API client on a 401 during use; the client shows the dialog. */
export function sessionEnded () { _admin.value = null }

/** beginLogin used to redirect to Keycloak; now it is the login route. */
export function beginLogin (returnTo = '/') {
  const target = `/login${returnTo && returnTo !== '/' ? `?next=${encodeURIComponent(returnTo)}` : ''}`
  if (window.location.pathname !== '/login') window.location.assign(target)
}

export async function changePassword (current, next) {
  const r = await call('POST', '/auth/password', { current, new: next })
  if (!r.ok) throw new Error(apiMessage(r.data?.error, r.status))
  if (_admin.value) _admin.value = { ..._admin.value, must_change_password: false }
}

export async function listSessions () {
  const r = await call('GET', '/auth/sessions')
  return r.ok ? r.data.sessions : []
}
export async function revokeSession (id) {
  await call('DELETE', `/auth/sessions/${id}`)
}

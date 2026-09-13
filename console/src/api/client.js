// API client for talking to the AidotVpn controller.
//
// All requests go through `/api/*` which the dev Vite server (and prod
// Express server) proxies to the controller. We add the Bearer token
// from the auth store on every call.
//
// We keep this file deliberately tiny — no axios, no SWR, no React Query
// equivalent. The admin console is small enough that fetch + a few
// composables are easier to read than a layered abstraction.
import { apiMessage } from '../i18n/index.js'
import { sessionEnded } from '@/stores/auth.js'

let sessionExpiredHandler = null

/** Registered by the app shell; called once per expiry, not per request. */
export function setSessionExpiredHandler(fn) { sessionExpiredHandler = fn }

let expiredFired = false
function onSessionExpired() {
  // Once. A dashboard firing four parallel requests would otherwise
  // redirect four times and lose the return path.
  if (expiredFired) return
  expiredFired = true
  sessionExpiredHandler?.()
}

class APIError extends Error {
  constructor (status, message, body) {
    super(apiMessage(message, status))
    this.status = status
    this.body = body
  }
}

async function request (method, path, body = null) {
  const headers = {
    'Accept': 'application/json',
  }
  // The session rides in an HttpOnly cookie; nothing to attach.
  const init = { method, headers }
  if (body !== null) {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(body)
  }

  init.credentials = 'include'
  const resp = await fetch(`/api${path}`, init)
  if (!resp.ok) {
    let errBody = null
    try { errBody = await resp.json() } catch { /* ignore */ }
    // A 401 means the session ended, not that this request was wrong.
    //
    // Every view reported it as its own failure — "노드를 불러오지
    // 못했습니다" on a page that was fine — and the console knew the
    // expiry the whole time without looking at it. Sending the operator
    // back to sign in is the only action that helps, and it is the one
    // thing none of those messages offered.
    if (resp.status === 401) {
      // One refresh, one retry, before declaring the session over. A
      // 401 can be an access token that expired seconds ago while the
      // refresh token is perfectly good; ending the session on that
      // told a working admin to log in again for no reason.
      sessionEnded()
      onSessionExpired()
    }
    // The server's own message when it gave one. resp.statusText is
    // "Bad Request" for every 400 — the sentence that says *why*
    // ("가상 주소는 10.79.0.0/16 안에 있어야 합니다") is in the body,
    // and every screen was discarding it for the generic one.
    const reason = errBody && typeof errBody.error === 'string' && errBody.error
      ? errBody.error
      : resp.statusText
    throw new APIError(resp.status, reason, errBody)
  }
  // Some endpoints (DELETE/Revoke) return empty bodies.
  if (resp.status === 204 || resp.headers.get('content-length') === '0') {
    return null
  }
  return resp.json()
}

// Methods are organised by resource. The names mirror the proto RPCs
// (DeviceService.ListMyDevices → devices.list) so it's obvious which
// server-side handler each call hits.
export const devices = {
  list: () => request('GET', '/devices'),
  revoke: (id, reason) => request('POST', `/devices/${id}/revoke`, { reason }),
  // mode ∈ 'off' | 'include' | 'exclude'; packages = array of Android applicationIds.
  // When mode = 'off', packages is wiped server-side regardless of what we send.
  updateAppFilter: (id, mode, packages) =>
    request('PUT', `/devices/${id}/app-filter`, { mode, packages }),
}


export const enrollmentRequests = {
  list: () => request('GET', '/enrollment-requests'),
  approve: (id, policyId) =>
    request('POST', `/enrollment-requests/${id}/approve`,
      { policy_id: policyId || undefined }),
  reject: (id) => request('POST', `/enrollment-requests/${id}/reject`),
  getPassword: () => request('GET', '/enrollment-password'),
  setPassword: (password) => request('PUT', '/enrollment-password', { password }),
}

export const nodes = {
  list: () => request('GET', '/nodes'),
}

export const policies = {
  list: () => request('GET', '/policies'),
  get: (id) => request('GET', `/policies/${id}`),
  create: (name, description) => request('POST', '/policies', { name, description }),
  update: (id, name, description, enabled) =>
    request('PUT', `/policies/${id}`, { name, description, enabled }),
  delete: (id) => request('DELETE', `/policies/${id}`),
  addAllowedIP: (policyId, cidr, description) =>
    request('POST', `/policies/${policyId}/allowed-ips`, { cidr, description }),
  removeAllowedIP: (policyId, allowedIpId) =>
    request('DELETE', `/policies/${policyId}/allowed-ips/${allowedIpId}`),
  /** How this policy's devices reach the gateway, and source NAT. */
  /** Virtual destinations: the phone is told one address, the gateway rewrites it. */
  listVirtualHosts: (id) => request('GET', `/policies/${id}/virtual-hosts`),
  addVirtualHost: (id, virtualIp, realIp, description) =>
    request('POST', `/policies/${id}/virtual-hosts`,
      { virtual_ip: virtualIp, real_ip: realIp, description }),
  removeVirtualHost: (id, hostId) =>
    request('DELETE', `/policies/${id}/virtual-hosts/${hostId}`),
  updateTransport: (id, endpointMode, sourceNat, controlChannel) =>
    request('PUT', `/policies/${id}/transport`, {
      endpoint_mode: endpointMode,
      source_nat: sourceNat,
      control_channel: controlChannel,
    }),
  assignToDevice: (deviceId, policyId) =>
    request('PUT', `/devices/${deviceId}/policy`, { policy_id: policyId || '' }),

  // --- Tunnel shaping (0.16.0) ---------------------------------------
  //
  // route_scope and the DNS fields existed in the schema and the
  // enforcement path since 0.11.0/0.15.0 but had no API until now, so
  // they were configurable only by editing the database.
  //
  // getSettings also returns dns_scope_warning: a non-empty string means
  // this policy pushes DNS to devices whose app filter is 'off', which on
  // Android captures the WHOLE device's DNS rather than only tunnelled
  // traffic. Show it verbatim.
  getSettings: (id) => request('GET', `/policies/${id}/settings`),
  updateSettings: (id, { routeScope, dnsServers, searchDomains }) =>
    request('PUT', `/policies/${id}/settings`, {
      route_scope: routeScope,
      dns_servers: dnsServers,
      dns_search_domains: searchDomains,
    }),

  // --- Hostname rules -------------------------------------------------
  //
  // guardCidr bounds what a resolution may return. Entries without one
  // come back with unguarded=true — whoever controls the DNS answer
  // controls the ACL, so the UI marks them.
  listHostnames: (id) => request('GET', `/policies/${id}/hostnames`),
  addHostname: (id, { hostname, guardCidr, description }) =>
    request('POST', `/policies/${id}/hostnames`, {
      hostname,
      guard_cidr: guardCidr || '',
      description: description || '',
    }),
  removeHostname: (id, hostnameId) =>
    request('DELETE', `/policies/${id}/hostnames/${hostnameId}`),
}

/** The reach map — device groups, policies, CIDRs, and what overlaps. */
export const reach = {
  get: () => request('GET', '/reach'),
}

/** The port map the running controller read from .env. */
/** The signed-in admin's own password, changed through the controller. */
export const account = {
  changePassword: (current, next) => request('POST', '/account/password', { current, new: next }),
}

/** One device's history: audit entries and gateway reports, in order. */
export const trace = {
  device: (id) => request('GET', `/devices/${id}/trace`),
  policy: (id) => request('GET', `/policies/${id}/trace`),
  actor: (id) => request('GET', `/audit/actor/${id}/trace`),
}

/** Dashboard numbers and series. */
/** 그룹 — a policy applied to many devices at once. */
/** 접속 기한 — days from now, 0 clears it. */
export const expiry = {
  setDevice: (id, days) => request('POST', `/devices/${id}/expiry`, { days }),
  setDefault: (days) => request('POST', '/settings/device-expiry', { days }),
}

/** 접근 규칙 — the two tenant-wide settings. */
/** 2단계 인증. */
export const totp = {
  setup: () => request('POST', '/auth/totp/setup'),
  enable: (code) => request('POST', '/auth/totp/enable', { code }),
  disable: (password) => request('POST', '/auth/totp/disable', { password }),
}

export const accessRules = {
  get: () => request('GET', '/settings/access'),
  setMinOS: (sdk) => request('POST', '/settings/min-os', { sdk }),
}

export const groups = {
  list: () => request('GET', '/groups'),
  create: (name, description, policyId) =>
    request('POST', '/groups', { name, description, policy_id: policyId || '' }),
  setPolicy: (id, policyId) =>
    request('PATCH', `/groups/${id}`, { policy_id: policyId || '' }),
  rename: (id, name, description) =>
    request('PATCH', `/groups/${id}`, { name, description }),
  remove: (id) => request('DELETE', `/groups/${id}`),
  assign: (deviceId, groupId) =>
    request('POST', `/devices/${deviceId}/group`, { group_id: groupId || '' }),
}

export const stats = {
  overview: () => request('GET', '/stats/overview'),
}

export const settingsPorts = {
  get: () => request('GET', '/settings/ports'),
}

export const audit = {
  list: (params = {}) => {
    const q = new URLSearchParams()
    if (params.limit) q.set('limit', String(params.limit))
    if (params.cursor) q.set('cursor', params.cursor)
    if (params.from) q.set('from', params.from)
    if (params.to) q.set('to', params.to)
    const suffix = q.toString() ? `?${q}` : ''
    return request('GET', `/audit${suffix}`)
  },
  verifyChain: () => request('GET', '/audit/verify'),
}

export { APIError }

export const consoleConnection = { get: () => request('GET', '/console/settings'), save: (settings) => request('PUT', '/console/settings', settings) }

export const ha = { status: () => request('GET', '/ha/status') }

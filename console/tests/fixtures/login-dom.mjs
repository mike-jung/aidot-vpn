// Execute the production bundle in a DOM with explicit, non-production API fixtures.
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { JSDOM, ResourceLoader, VirtualConsole } from 'jsdom'

const scenario = process.argv[2]
const root = fileURLToPath(new URL('../../dist/', import.meta.url))
const html = await fs.readFile(path.join(root, 'index.html'), 'utf8')
class Assets extends ResourceLoader {
  fetch(url) {
    const name = new URL(url).pathname.slice(1)
    if (scenario === 'missing-dashboard' && /OverviewView-.*\.(css|js)$/.test(name)) {
      return Promise.reject(new Error('Dashboard chunk removed by a deployment'))
    }
    return fs.readFile(path.join(root, name))
  }
}
const errors = []
const virtualConsole = new VirtualConsole()
virtualConsole.on('jsdomError', error => { if (error.type !== 'css parsing') errors.push(error.message) })
const initialURL = scenario === 'protected-redirect' ? '/devices' : '/login'
const dom = new JSDOM(html.replace(/<script[^>]*><\/script>/g, ''), {
  url: `http://console.test${initialURL}`, pretendToBeVisual: true, resources: new Assets(), virtualConsole,
})
for (const name of ['window', 'document', 'history', 'location', 'localStorage', 'sessionStorage', 'MutationObserver', 'Element', 'SVGElement', 'HTMLElement', 'Document', 'Node', 'Event']) {
  globalThis[name] = dom.window[name]
}
Object.defineProperty(globalThis, 'navigator', { configurable: true, value: dom.window.navigator })
globalThis.addEventListener = dom.window.addEventListener.bind(dom.window)
window.scrollTo = () => {}
let session = scenario === 'existing-session'
const calls = []
globalThis.fetch = async (url, options = {}) => {
  const route = String(url).split('?')[0]
  if (!route.startsWith('/api/')) return new Response('')
  calls.push([options.method || 'GET', route])
  const admin = { id: 'test-admin', email: 'admin', display_name: 'Test administrator', role: 'admin', must_change_password: scenario === 'must-change' }
  let body = {}, status = 200
  if (route === '/api/auth/me') { body = { admin }; if (!session) status = 401 }
  else if (route === '/api/auth/login') {
    await new Promise(resolve => setTimeout(resolve, 20))
    if (scenario === 'invalid-credentials') { status = 401; body = { error: '이메일 또는 비밀번호가 맞지 않습니다' } }
    else if (scenario === 'mfa' && !JSON.parse(options.body).code) { status = 428; body = { error: '인증 앱의 6자리 숫자를 입력하세요.' } }
    else { session = true; body = { admin } }
  }
  else if (route === '/api/devices') body = { devices: [] }
  else if (route === '/api/policies') body = { policies: [] }
  else if (route === '/api/nodes') body = { nodes: [] }
  else if (route === '/api/enrollment-requests') body = { requests: [] }
  else if (route === '/api/audit') body = { entries: [] }
  else if (route === '/api/console/settings') body = { bindHost: '127.0.0.1', port: 9111, publicURL: 'http://localhost:9111', https: { enabled: false }, managedByEnvironment: [] }
  else if (route === '/api/settings/ports') body = { ports: [], note: '' }
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}
console.error = (...args) => errors.push(args.map(String).join(' '))
process.on('unhandledRejection', error => errors.push(String(error)))
const entry = html.match(/src="(\/assets\/index-[^"]+\.js)"/)[1]
await import(pathToFileURL(path.join(root, entry.slice(1))))
async function until(predicate) {
  for (let count = 0; count < 150; count++) { if (predicate()) return; await new Promise(resolve => setTimeout(resolve, 20)) }
  throw new Error(`Timed out in ${scenario} at ${location.pathname}; ${errors.join('; ')}`)
}
function fill(selector, value) {
  const field = document.querySelector(selector)
  field.value = value
  field.dispatchEvent(new Event('input', { bubbles: true }))
}
let valid = true, busyAfterSubmit = false, mfaStayedOnLogin = false
if (!session) {
  await until(() => document.querySelector('#email'))
  fill('#email', scenario === 'email' ? 'test@example.com' : 'admin')
  fill('#password', 'fixture-only-password')
  await new Promise(resolve => setTimeout(resolve, 0))
  valid = document.querySelector('form').checkValidity()
  document.querySelector('form').requestSubmit()
  if (scenario === 'double-submit') document.querySelector('form').requestSubmit()
  await new Promise(resolve => setTimeout(resolve, 0))
  busyAfterSubmit = document.querySelector('button[type="submit"]')?.disabled === true
  if (scenario === 'mfa') {
    await until(() => document.querySelector('input[autocomplete="one-time-code"]'))
    mfaStayedOnLogin = location.pathname === '/login' && !session
    fill('input[autocomplete="one-time-code"]', '123456')
    await new Promise(resolve => setTimeout(resolve, 0))
    document.querySelector('form').requestSubmit()
  }
}
if (scenario === 'invalid-credentials') await until(() => document.querySelector('[role="alert"]'))
else await until(() => document.querySelector('.app-shell') && !document.querySelector('.landing'))
await new Promise(resolve => setTimeout(resolve, 40))
console.log(JSON.stringify({
  scenario, valid, session, busyAfterSubmit, mfaStayedOnLogin,
  path: location.pathname + location.search,
  loginVisible: !!document.querySelector('.landing'),
  dashboardVisible: !!document.querySelector('.app-shell'),
  settingsVisible: !!document.querySelector('#settings-language'),
  alert: document.querySelector('[role="alert"]')?.textContent || '',
  loginCalls: calls.filter(([, route]) => route === '/api/auth/login').length,
  errors,
}))
dom.window.close()
process.exit(0)

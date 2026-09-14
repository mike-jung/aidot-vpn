import test from 'node:test'
import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import http from 'node:http'
import { once } from 'node:events'
import { createConsoleApp } from '../app.js'
import { loginDestination, navigateAfterLogin, recoverLoginAssets } from '../src/router/login-navigation.js'

const execute = promisify(execFile)
for (const scenario of ['username', 'email', 'missing-dashboard', 'must-change', 'protected-redirect', 'mfa', 'double-submit', 'invalid-credentials', 'existing-session']) {
  test(`production login DOM: ${scenario}`, async () => {
    const { stdout } = await execute(process.execPath, [fileURLToPath(new URL('./fixtures/login-dom.mjs', import.meta.url)), scenario], { timeout: 15_000 })
    const result = JSON.parse(stdout.trim())
    assert.deepEqual(result.errors, [])
    assert.equal(result.valid, true)
    if (scenario === 'invalid-credentials') {
      assert.equal(result.session, false)
      assert.equal(result.path, '/login')
      assert.equal(result.loginVisible, true)
      assert.ok(result.alert)
    } else {
      assert.equal(result.session, true)
      assert.equal(result.loginVisible, false)
      assert.equal(result.dashboardVisible, true)
      assert.equal(result.path, scenario === 'must-change' ? '/?changePassword=1' : scenario === 'protected-redirect' ? '/devices' : '/')
    }
    if (scenario !== 'existing-session') assert.equal(result.busyAfterSubmit, true)
    assert.equal(result.loginCalls, scenario === 'existing-session' ? 0 : scenario === 'mfa' ? 2 : 1)
    if (scenario === 'mfa') assert.equal(result.mfaStayedOnLogin, true)
    if (scenario === 'must-change') assert.equal(result.settingsVisible, true)
  })
}

test('login waits for navigation and reports an aborted transition', async () => {
  let resolve, complete = false
  const router = { replace: () => new Promise(done => { resolve = done }), currentRoute: { value: { name: 'login' } }, resolve: () => ({ fullPath: '/' }) }
  const navigation = navigateAfterLogin(router, '/', undefined).then(() => { complete = true })
  await Promise.resolve()
  assert.equal(complete, false)
  resolve(undefined)
  await navigation
  router.replace = async () => new Error('Navigation aborted')
  await assert.rejects(navigateAfterLogin(router, '/', undefined), /로그인 후 화면/)
})

test('stale assets recover once without reloading for unrelated failures', async () => {
  const stored = new Map(), replaced = []
  const browser = { sessionStorage: { getItem: key => stored.get(key), setItem: (key, value) => stored.set(key, value) }, location: { replace: value => replaced.push(value) } }
  const error = new Error('Failed to fetch dynamically imported module: /assets/old.js')
  const router = { replace: async () => { throw error }, resolve: () => ({ fullPath: '/devices?status=active' }) }
  await navigateAfterLogin(router, '/devices?status=active', browser)
  assert.deepEqual(replaced, ['/devices?status=active'])
  await assert.rejects(navigateAfterLogin(router, '/devices?status=active', browser), /로그인 후 화면/)
  assert.equal(replaced.length, 1)
  assert.equal(recoverLoginAssets(new Error('Unrelated application error'), '/', browser), false)
  assert.equal(recoverLoginAssets(error, '//outside.example', browser), false)
  browser.sessionStorage.getItem = () => { throw new Error('Storage unavailable') }
  assert.equal(recoverLoginAssets(error, '/', browser), false)
})

test('login preserves protected return paths and rejects invalid destinations', () => {
  const router = { resolve: value => ({ name: value === '/login' ? 'login' : value === '/devices?state=active' ? 'devices' : 'unknown', fullPath: value, meta: { requiresAuth: value === '/devices?state=active' } }) }
  assert.equal(loginDestination(router, '/devices?state=active', false), '/devices?state=active')
  for (const value of [undefined, ['/devices'], '/login', '/unknown', 'https://outside.example', '//outside.example', '/\\outside.example', '/\noutside.example']) {
    assert.deepEqual(loginDestination(router, value, false), { name: 'overview' })
  }
  assert.deepEqual(loginDestination(router, '/devices?state=active', true), { name: 'overview', query: { changePassword: '1' } })
})

test('HTML entry points are revalidated while hashed assets remain immutable', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'aidot-login-cache-'))
  await fs.mkdir(path.join(directory, 'assets'))
  await fs.writeFile(path.join(directory, 'index.html'), '<html>Console</html>')
  await fs.writeFile(path.join(directory, 'assets', 'test-123.js'), 'export const value = 1')
  const server = http.createServer(createConsoleApp({ distDir: directory, controllerURL: 'http://127.0.0.1:1' }))
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  try {
    for (const route of ['/index.html', '/login', '/']) {
      const response = await fetch(`http://127.0.0.1:${server.address().port}${route}`)
      assert.equal(response.status, 200)
      assert.equal(response.headers.get('cache-control'), 'no-cache')
      await response.text()
    }
    const response = await fetch(`http://127.0.0.1:${server.address().port}/assets/test-123.js`)
    assert.match(response.headers.get('cache-control'), /immutable/)
    await response.text()
  } finally {
    server.closeAllConnections()
    await new Promise(resolve => server.close(resolve))
    await fs.rm(directory, { recursive: true, force: true })
  }
})

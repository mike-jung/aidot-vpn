// Shared by source and SEA builds. No private key is returned by the settings API.
import fs from 'node:fs'
import path from 'node:path'
import http from 'node:http'
import https from 'node:https'
import { randomUUID } from 'node:crypto'
import { createConsoleApp } from './app.js'

import { configFrom, validateConfig, defaults, keys } from './listener-config.js'
export { configFrom, validateConfig, defaults } from './listener-config.js'
function atomicJSON(file, value) {
  fs.mkdirSync(path.dirname(file), {recursive: true, mode: 0o700})
  const temp = `${file}.${randomUUID()}.tmp`
  try { fs.writeFileSync(temp, JSON.stringify(value, null, 2) + '\n', {flag: 'wx', mode: 0o600}); fs.renameSync(temp, file) }
  finally { fs.rmSync(temp, {force: true}) }
}
export async function startConsole({ base = {}, stateFile, env = process.env, certificateBaseDir, ...assets }) {
  let saved = {}
  try { saved = JSON.parse(fs.readFileSync(stateFile, 'utf8').replace(/^\uFEFF/, '')) } catch (e) { if (e.code !== 'ENOENT') throw e }
  let cfg = configFrom(base, saved, env, certificateBaseDir), checked = validateConfig(cfg), server, applying = false
  const managed = Object.keys(keys).filter(k => env[k] !== undefined && env[k] !== '')
  const view = () => ({ bindHost: cfg.bindHost, port: cfg.port, publicURL: checked.url, https: cfg.https, certificate: checked.certificate, managedByEnvironment: managed })
  const listen = (c, v) => new Promise((resolve, reject) => {
    const s = v.options ? https.createServer(v.options, app) : http.createServer(app)
    s.requestTimeout = 30000; s.headersTimeout = 15000; s.keepAliveTimeout = 5000
    s.once('error', reject)
    s.listen(c.port, c.bindHost, () => { s.removeListener('error', reject); s.on('error', e => console.error('Listener error:', e.code)); resolve(s) })
  })
  const retire = s => { s.close(); s.closeIdleConnections(); setTimeout(() => s.closeAllConnections(), 10000).unref() }
  const publish = () => { if (env.AIDOTVPN_ENDPOINT_FILE) atomicJSON(env.AIDOTVPN_ENDPOINT_FILE, { url: checked.url }) }
  const apply = async body => {
    if (applying) throw Object.assign(Error('settings_busy'), {status: 409})
    if (!body || typeof body !== 'object' || Object.keys(body).some(k => !['bindHost', 'port', 'publicURL', 'https'].includes(k))) throw Error('invalid_console_settings')
    if (body.https && Object.keys(body.https).some(k => !['enabled', 'certFile', 'keyFile'].includes(k))) throw Error('invalid_console_settings')
    applying = true
    const previous = cfg, previousChecked = checked, old = server
    let replacement, closed = false
    try {
      const next = configFrom(base, body, env, certificateBaseDir)
      for (const name of managed) {
        const field = keys[name], tlsField = ['enabled','certFile','keyFile'].includes(field)
        const requested = tlsField ? body.https?.[field] : body[field]
        if (requested !== undefined && requested !== (tlsField ? next.https[field] : next[field])) throw Object.assign(Error('settings_managed_by_environment'), {status:409})
      }
      const valid = validateConfig(next)
      // Same address needs a brief rebind; active responses may drain on the old listener.
      if (next.port === cfg.port) { old.close(); closed = true }
      replacement = await listen(next, valid)
      atomicJSON(stateFile, { bindHost: next.bindHost, port: next.port, publicURL: valid.url, https: next.https })
      cfg = next; checked = valid; server = replacement
      retire(old)
      try { publish() } catch { console.error('Console endpoint descriptor could not be updated') }
      return { ...view(), reconnectURL: checked.url + '/?settings=1' }
    } catch (e) {
      if (replacement) retire(replacement)
      if (closed) server = await listen(previous, previousChecked)
      throw e
    } finally { applying = false }
  }
  const app = createConsoleApp({...assets, controllerURL: cfg.controllerURL, consoleSettings: {get: view, apply}})
  server = await listen(cfg, checked)
  try { publish() } catch (e) { server.closeAllConnections();server.close();throw e }
  console.log(JSON.stringify({msg: 'console listening', url: checked.url}))
  return { get server() { return server }, getConfig: view, async close() { server.closeAllConnections(); await new Promise(r => server.close(r)) } }
}

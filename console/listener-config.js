// Shared TLS/config validation; built-ins only so deployment preflight works before npm ci.
import fs from 'node:fs'
import path from 'node:path'
import tls from 'node:tls'
import net from 'node:net'
import { X509Certificate } from 'node:crypto'
export const defaults = { bindHost: '127.0.0.1', port: 9111, controllerURL: 'http://127.0.0.1:10030', publicURL: '', https: { enabled: false, certFile: '', keyFile: '' } }
export const keys = { CONSOLE_BIND_HOST: 'bindHost', CONSOLE_PORT: 'port', CONSOLE_PUBLIC_URL: 'publicURL', CONSOLE_HTTPS_ENABLED: 'enabled', CONSOLE_TLS_CERT_FILE: 'certFile', CONSOLE_TLS_KEY_FILE: 'keyFile' }
export function configFrom(base = {}, saved = {}, env = process.env, certificateBaseDir) {
  const cfg = { ...defaults, ...base, ...saved, https: { ...defaults.https, ...base.https, ...saved.https } }
  for (const [name, key] of Object.entries(keys)) if (env[name] !== undefined && env[name] !== '') {
    let value = env[name]
    if (key === 'enabled') { if (!['true', 'false', '1', '0'].includes(value)) throw Error('invalid_https_enabled'); value = ['true', '1'].includes(value) }
    if (key === 'port') value = Number(value)
    if (['enabled', 'certFile', 'keyFile'].includes(key)) cfg.https[key] = value
    else cfg[key] = value
  }
  if (env.CONTROLLER_URL) cfg.controllerURL = env.CONTROLLER_URL
  if (certificateBaseDir) for (const key of ['certFile', 'keyFile']) {
    const value = cfg.https[key]
    if (typeof value !== 'string' || !value.trim()) continue
    // C:cert.pem depends on a per-drive working directory and is never portable.
    if (/^[a-z]:[^\\/]/i.test(value) || /^[a-z]:$/i.test(value)) throw Error('certificate_paths_must_be_absolute')
    if (process.platform !== 'win32' && path.win32.isAbsolute(value) && !path.isAbsolute(value)) throw Error('certificate_paths_must_be_absolute')
    cfg.https[key] = path.resolve(certificateBaseDir, value)
  }
  return cfg
}
export function validateConfig(cfg) {
  if (!Number.isInteger(cfg.port) || cfg.port < 1 || cfg.port > 65535) throw Error('invalid_console_port')
  if (typeof cfg.bindHost !== 'string' || !/^[a-zA-Z0-9.:%_-]+$/.test(cfg.bindHost)) throw Error('invalid_bind_host')
  const upstream = new URL(cfg.controllerURL)
  if (!['http:', 'https:'].includes(upstream.protocol) || upstream.username || upstream.password || upstream.pathname !== '/' || upstream.search || upstream.hash) throw Error('invalid_controller_url')
  if (upstream.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(upstream.hostname)) throw Error('remote_controller_requires_https')
  if (typeof cfg.https?.enabled !== 'boolean') throw Error('invalid_https_enabled')
  const host = ['0.0.0.0', '::'].includes(cfg.bindHost) ? 'localhost' : cfg.bindHost
  const fallback = `${cfg.https.enabled ? 'https' : 'http'}://${net.isIP(host) === 6 ? `[${host}]` : host}:${cfg.port}`
  const url = new URL(cfg.publicURL || fallback)
  if (url.protocol !== (cfg.https.enabled ? 'https:' : 'http:') || Number(url.port || (cfg.https.enabled ? 443 : 80)) !== cfg.port || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw Error('invalid_public_url')
  let options, certificate
  if (cfg.https.enabled) {
    if (![cfg.https.certFile, cfg.https.keyFile].every(f => typeof f === 'string' && f.trim())) throw Error('certificate_paths_missing')
    for (const f of [cfg.https.certFile, cfg.https.keyFile]) if (typeof f !== 'string' || !path.isAbsolute(f)) throw Error('certificate_paths_must_be_absolute')
    try {
      const cert = fs.readFileSync(cfg.https.certFile), key = fs.readFileSync(cfg.https.keyFile)
      const x509 = new X509Certificate(cert)
      if (Date.now() < Date.parse(x509.validFrom) || Date.now() >= Date.parse(x509.validTo)) throw Error('certificate_expired_or_not_yet_valid')
      const hostname = url.hostname.replace(/^\[|\]$/g, '')
      if (!(net.isIP(hostname) ? x509.checkIP(hostname) : x509.checkHost(hostname))) throw Error('certificate_hostname_mismatch')
      options = { cert, key, minVersion: 'TLSv1.2' }
      tls.createSecureContext(options) // also checks that key and certificate match
      certificate = { expiresAt: x509.validTo, fingerprint: x509.fingerprint256 }
    } catch (error) {
      if (error.code === 'ENOENT') throw Error('certificate_file_not_found')
      if (['EACCES', 'EPERM', 'EISDIR'].includes(error.code)) throw Error('certificate_file_not_readable')
      if (['certificate_expired_or_not_yet_valid', 'certificate_hostname_mismatch'].includes(error.message)) throw error
      throw Error('certificate_or_key_invalid')
    }
  }
  return { options, certificate, url: url.origin }
}

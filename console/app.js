// Production console HTTP application; authentication uses controller session cookies.
import express from 'express'
import compression from 'compression'
import { createProxyMiddleware } from 'http-proxy-middleware'
import path from 'node:path'
import fs from 'node:fs'
import http from 'node:http'
import https from 'node:https'

export function createConsoleApp(cfg) {
const app = express()

// Trust the first proxy in front of us (e.g., a load balancer setting
// X-Forwarded-* headers). If you don't have a proxy, this is a no-op.
app.set('trust proxy', cfg.trustProxy || false)

app.disable('x-powered-by')
app.use(compression())

// Health endpoint — the LB uses this. Cheap and fast; never logged.
app.get('/healthz', (req, res) => {
  res.type('text/plain').send('ok\n')
})

// Host-wide settings require a current controller administrator session.
if (cfg.consoleSettings) {
  app.use('/api/console/settings', async (req, res, next) => {
    res.set('Cache-Control', 'no-store')
    if (!['GET', 'PUT'].includes(req.method)) return res.sendStatus(405)
    if (req.method === 'PUT') {
      const origin = `${req.protocol}://${req.get('host')}`
      if (req.get('origin') !== origin || !req.is('application/json')) return res.status(403).json({error: 'same_origin_json_required'})
    }
    try {
      const auth = await new Promise((resolve, reject) => {
        const url = new URL('/auth/me', cfg.controllerURL)
        const upstream = (url.protocol === 'https:' ? https : http).get(url, {headers: {cookie: req.headers.cookie || ''}, timeout: 5000}, r => {
          let body = ''; r.on('data', c => { body += c; if (body.length > 65536) upstream.destroy(Error('response_too_large')) })
          r.on('end', () => { try { resolve({status: r.statusCode, data: JSON.parse(body)}) } catch { reject(Error('invalid_auth_response')) } })
        })
        upstream.on('timeout', () => upstream.destroy(Error('auth_timeout'))); upstream.on('error', reject)
      })
      if (auth.status !== 200) return res.status(auth.status === 401 ? 401 : 503).json({error: 'authentication_required'})
      if (auth.data?.admin?.role !== 'admin' || auth.data.admin.must_change_password) return res.status(403).json({error: 'administrator_required'})
      next()
    } catch { res.status(503).json({error: 'controller_unreachable'}) }
  })
  app.get('/api/console/settings', (req, res) => res.json(cfg.consoleSettings.get()))
  app.put('/api/console/settings', express.json({limit: '16kb'}), async (req, res) => {
    res.set('Connection', 'close')
    try { res.json(await cfg.consoleSettings.apply(req.body)) }
    catch (e) { res.status(e.status || 400).json({error: /^[a-z_]+$/.test(e.message) ? e.message : 'console_settings_apply_failed'}) }
  })
}

// Proxy /api/* → controller, preserving the bearer token. We strip the
// /api prefix on the way through because the controller mounts at /.
//
// Note on http-proxy-middleware v3: event hooks moved off top-level
// options into an `on` object. Top-level `onProxyReq` / `onError` from
// v2 are silently ignored on v3, which means the previous version of
// this file looked correct but the cookie scrub never ran and proxy
// errors fell through to Express's default 500 page.
app.use('/api', createProxyMiddleware({
  target: cfg.controllerURL,
  changeOrigin: true,
  pathRewrite: { '^/api': '' },
  // Don't follow redirects: an upstream redirect leaving the controller
  // origin would expose us to SSRF-like surprises.
  followRedirects: false,
  on: {
    proxyReq(proxyReq, req) {
      // Never forward spoofable protocol/IP headers from the browser.
      proxyReq.setHeader('X-Forwarded-Proto', req.protocol)
      proxyReq.setHeader('X-Forwarded-For', req.ip)
    },
    error (err, req, res) {
      console.error('proxy error:', err.message)
      if (res && !res.headersSent) {
        res.status(502).type('application/json').send(JSON.stringify({
          error: 'controller_unreachable',
          message: 'Controller unavailable',
        }))
      }
    },
  },
}))

// Embedded assets are immutable program resources, never user-writable data.
if (cfg.readAsset) {
  app.use((req, res, next) => {
    if (!['GET', 'HEAD'].includes(req.method)) return next()
    let key
    try { key = decodeURIComponent(req.path).replace(/^\//, '') } catch { return res.sendStatus(400) }
    if (key === 'api' || key.startsWith('api/')) return res.sendStatus(404)
    const asset = cfg.readAsset(key || 'index.html')
    if (asset) {
      res.set('Cache-Control', key.startsWith('assets/') ? 'public, max-age=31536000, immutable' : 'no-cache')
      return res.type(path.extname(key || 'index.html')).send(asset)
    }
    if (key.startsWith('assets/') || path.extname(key)) return res.sendStatus(404)
    res.set('Cache-Control', 'no-cache').type('html').send(cfg.readAsset('index.html'))
  })
} else if (fs.existsSync(cfg.distDir)) {
  app.use('/assets', express.static(path.join(cfg.distDir, 'assets'), {maxAge: '1y', immutable: true}))
  app.use(express.static(cfg.distDir, {
    maxAge: '5m', index: false,
    setHeaders(res, file) {
      if (path.extname(file) === '.html') res.setHeader('Cache-Control', 'no-cache')
    },
  }))
  app.use((req, res, next) => {
    if (!['GET', 'HEAD'].includes(req.method)) return next()
    if (req.path === '/api' || req.path.startsWith('/api/') || path.extname(req.path)) return res.sendStatus(404)
    res.set('Cache-Control', 'no-cache').sendFile(path.join(cfg.distDir, 'index.html'))
  })
} else {
  app.use((req, res) => res.status(503).type('text/plain').send('Console build not found.\n'))
}
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error)
  const status = error.type === 'entity.too.large' ? 413 : error.type === 'entity.parse.failed' ? 400 : 500
  res.status(status).json({error: status === 500 ? 'internal_error' : 'invalid_json_body'})
})
return app
}

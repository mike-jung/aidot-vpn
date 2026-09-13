// Source entry points share the same env-file anchor, regardless of their cwd.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseEnv } from 'node:util'
import { configFrom } from './listener-config.js'
export const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
export function readSourceConfig({ root = sourceRoot, inherited = process.env, forceHTTPS = false } = {}) {
  const envFile = path.resolve(root, inherited.AIDOTVPN_CONSOLE_ENV_FILE || '.env')
  let local = {}, saved = {}
  try { local = parseEnv(fs.readFileSync(envFile, 'utf8').replace(/^\uFEFF/, '')) }
  catch (e) { if (e.code !== 'ENOENT') throw e }
  const env = { ...local, ...inherited }
  if (forceHTTPS) env.CONSOLE_HTTPS_ENABLED = 'true'
  const stateFile = path.join(path.resolve(root, env.AIDOTVPN_DATA_DIR || '.local/console'), 'console-settings.json')
  try { saved = JSON.parse(fs.readFileSync(stateFile, 'utf8').replace(/^\uFEFF/, '')) }
  catch (e) { if (e.code !== 'ENOENT') throw e }
  const certificateBaseDir = path.dirname(envFile)
  const base = { port: Number(env.PORT || 6193), bindHost: env.BIND_HOST || '127.0.0.1' }
  const cfg = configFrom(base, saved, env, certificateBaseDir)
  return { cfg, env, envFile, stateFile, certificateBaseDir, base }
}

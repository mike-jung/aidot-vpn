import fs from 'node:fs'
import path from 'node:path'
import { getAsset } from 'node:sea'
import { startConsole, defaults } from '../../console/listener.js'
import { dataPaths } from './paths.mjs'

export async function main() {
  const paths = dataPaths()
  if (process.argv.includes('--version')) { console.log(AIDOT_BUILD_VERSION); return }
  if (process.argv.includes('--paths')) { console.log(JSON.stringify(paths)); return }
  for (const dir of [paths.data, paths.config, paths.logs, paths.exports, paths.backups]) fs.mkdirSync(dir, {recursive: true, mode: 0o700})
  const file = path.join(paths.config, 'console.json')
  if (process.argv.includes('--init')) {
    try { fs.writeFileSync(file, JSON.stringify(defaults, null, 2) + '\n', {flag: 'wx', mode: 0o600}) }
    catch (e) { if (e.code !== 'EEXIST') throw e }
    console.log(`Configuration: ${file}`); return
  }
  const cfg = JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''))
  try { process.loadEnvFile(process.env.AIDOTVPN_CONSOLE_ENV_FILE || path.join(paths.config, 'console.env')) } catch (e) { if (e.code !== 'ENOENT') throw e }
  const assets = JSON.parse(getAsset('asset-manifest', 'utf8'))
  const running = await startConsole({base: cfg, stateFile: path.join(paths.data, 'console-settings.json'), readAsset(key) { return Object.hasOwn(assets, key) ? Buffer.from(getAsset(assets[key])) : null }})
  const stop = async () => { await running.close(); process.exit(0) }
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, stop)
  if (process.env.AIDOTVPN_SERVICE_STDIN === '1') {
    process.stdin.setEncoding('utf8')
    let input = ''
    process.stdin.on('data', c => { input += c; if (input.split(/\r?\n/).some(line => line.trim() === 'shutdown')) stop() })
    process.stdin.on('end', stop)
  }
}

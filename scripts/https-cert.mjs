import fs from 'node:fs'
import path from 'node:path'
import net from 'node:net'
import { spawnSync } from 'node:child_process'
import { X509Certificate, randomUUID } from 'node:crypto'
import { pathToFileURL } from 'node:url'
import { parseEnv } from 'node:util'
import { readSourceConfig, sourceRoot } from '../console/source-config.js'
import { validateConfig } from '../console/listener-config.js'

const tlsKeys = ['CONSOLE_HTTPS_ENABLED', 'CONSOLE_PUBLIC_URL', 'CONSOLE_TLS_CERT_FILE', 'CONSOLE_TLS_KEY_FILE']
export function updateEnvText(original, values) {
  const newline = original.includes('\r\n') ? '\r\n' : '\n'
  const bom = original.startsWith('\uFEFF') ? '\uFEFF' : ''
  const lines = original.replace(/^\uFEFF/, '').split(/\r?\n/), seen = new Set()
  const result = lines.flatMap(line => {
    const match = /^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=/.exec(line)
    if (!match || !tlsKeys.includes(match[1])) return [line]
    if (seen.has(match[1])) return []
    seen.add(match[1]); return [`${match[1]}=${quote(values[match[1]])}`]
  })
  while (result.at(-1) === '') result.pop()
  for (const key of tlsKeys) if (!seen.has(key)) result.push(`${key}=${quote(values[key])}`)
  const text = bom + result.join(newline) + newline
  const parsed = parseEnv(text.replace(/^\uFEFF/, ''))
  for (const key of tlsKeys) if (parsed[key] !== values[key]) throw Error('Could not safely write the HTTPS environment values')
  // Do not silently alter unrelated multiline values.
  for (const [key, value] of Object.entries(parseEnv(original.replace(/^\uFEFF/, '')))) if (!tlsKeys.includes(key) && parsed[key] !== value) throw Error(`Preserving ${key} requires a manual .env edit`)
  return text
}
function quote(value) {
  if (/["\r\n\0]/.test(value)) throw Error('Certificate paths and URLs cannot contain quotes or line breaks')
  return `"${value}"`
}
function run(command, args) {
  const result = spawnSync(command, args, { shell:false, windowsHide:true, encoding:'utf8', timeout:120000 })
  if (result.error || result.status !== 0) throw Error(`${path.basename(command)} failed: ${result.error?.message || result.stderr?.trim() || result.stdout?.trim()}`)
  return result.stdout
}
function secureDirectory(dir) {
  fs.mkdirSync(dir, {recursive:true, mode:0o700})
  if (fs.lstatSync(dir).isSymbolicLink()) throw Error('Certificate output cannot be a symbolic link')
  if (process.platform === 'win32') {
    const sid = run('whoami.exe', ['/user','/fo','csv','/nh']).match(/S-1-5-(?:\d+-)*\d+/)?.[0]
    if (!sid) throw Error('Could not determine the Windows account for private-key permissions')
    run('icacls.exe', [dir, '/inheritance:r', '/grant:r', `*${sid}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F'])
  } else fs.chmodSync(dir, 0o700)
}
function atomicWrite(file, text) {
  const temp = file + '.' + randomUUID() + '.tmp'
  try { fs.writeFileSync(temp, text, {flag:'wx', mode:0o600}); fs.renameSync(temp,file) }
  finally { fs.rmSync(temp,{force:true}) }
}
export function generateCertificate(args = [], { root = sourceRoot, inherited = process.env } = {}) {
  const options = { hosts:[], days:365 }
  for (let i=0; i<args.length; i++) {
    const key = args[i]
    if (key === '--renew') options.renew = true
    else if (['--url','--host','--out-dir','--env-file','--days'].includes(key)) {
      const value = args[++i]; if (!value || value.startsWith('--')) throw Error(`${key} needs a value`)
      if (key === '--host') options.hosts.push(value); else options[key.slice(2)] = value
    } else if (key === '--help' || key === '-h') return { help:'npm run https:cert [-- --url https://HOST:PORT --host OTHER_HOST --renew]\nOptions: --env-file PATH, --out-dir PATH, --days 1..365. No trust store is changed.' }
    else throw Error(`Unknown option: ${key}`)
  }
  const days = Number(options.days)
  if (!Number.isInteger(days) || days < 1 || days > 365) throw Error('--days must be an integer from 1 to 365')
  const input = { ...inherited }
  if (options['env-file']) input.AIDOTVPN_CONSOLE_ENV_FILE = options['env-file']
  const { cfg, envFile } = readSourceConfig({root,inherited:input})
  const url = new URL(options.url || cfg.publicURL?.replace(/^http:/,'https:') || `https://localhost:${cfg.port}`)
  const port = Number(url.port || 443)
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash || port !== cfg.port) throw Error(`Use an HTTPS origin with the configured console port ${cfg.port}; set CONSOLE_PORT first to change it`)
  const hosts = [...new Set(['localhost','127.0.0.1','::1',url.hostname.replace(/^\[|\]$/g,''),...options.hosts].map(h=>h.toLowerCase()))].sort()
  for (const host of hosts) if (!net.isIP(host) && (!/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host) || host.split('.').some(label=>!label || label.length>63 || label.startsWith('-') || label.endsWith('-')))) throw Error(`Invalid certificate hostname: ${host}`)
  if (hosts.some(h=>['0.0.0.0','::'].includes(h))) throw Error('Use a reachable hostname or IP in the certificate, not a wildcard bind address')
  const directory = path.resolve(path.dirname(envFile), options['out-dir'] || '.local/https')
  const currentFile = path.join(directory,'current.json')
  if (fs.existsSync(directory) && !fs.existsSync(currentFile) && fs.readdirSync(directory).length) throw Error('Use an empty output directory or an existing AidotVPN certificate directory')
  secureDirectory(directory)
  const lock = path.join(directory,'.generate.lock')
  let handle
  try { handle = fs.openSync(lock,'wx',0o600) } catch (e) { if (e.code==='EEXIST') throw Error('Another certificate generation is in progress (.generate.lock)'); throw e }
  let stage
  try {
    let current, bundle, reused = false
    if (fs.existsSync(currentFile)) {
      current = JSON.parse(fs.readFileSync(currentFile,'utf8'))
      if (current.format !== 'aidotvpn-local-ca-v1' || !/^[a-z0-9-]+$/.test(current.bundle)) throw Error('Invalid local certificate metadata')
      bundle = path.join(directory,current.bundle)
      if (fs.lstatSync(bundle).isSymbolicLink()) throw Error('Certificate bundle cannot be a symbolic link')
      const ca = new X509Certificate(fs.readFileSync(path.join(bundle,'ca-cert.pem')))
      if (ca.fingerprint256 !== current.caFingerprint || !ca.ca || !ca.verify(ca.publicKey)) throw Error('The existing CA has changed; review it before creating certificates')
      if (!options.renew) {
        const cert = new X509Certificate(fs.readFileSync(path.join(bundle,'cert.pem')))
        if (hosts.some(h=>!(net.isIP(h)?cert.checkIP(h):cert.checkHost(h))) || Date.parse(cert.validTo) <= Date.now()+86400000) throw Error('The certificate needs renewal or additional hostnames. Run npm run https:cert -- --renew with the desired --url/--host')
        reused = true
      }
    }
    if (!reused) {
      stage = fs.mkdtempSync(path.join(directory,'.new-'))
      const go = inherited.AIDOT_GO || 'go'
      run(go, ['run',path.join(root,'scripts/certs/main.go'),'-out',stage,...(bundle?['-ca',bundle]:[]),'-hosts',hosts.join(','),'-days',String(days)])
      const name = 'bundle-' + randomUUID()
      const next = path.join(directory,name)
      fs.renameSync(stage,next); stage = undefined; bundle = next
    }
    const certFile = path.join(bundle,'fullchain.pem'), keyFile = path.join(bundle,'privkey.pem')
    const checked = validateConfig({...cfg,publicURL:url.origin,https:{enabled:true,certFile,keyFile}})
    const ca = new X509Certificate(fs.readFileSync(path.join(bundle,'ca-cert.pem')))
    const values = {CONSOLE_HTTPS_ENABLED:'true',CONSOLE_PUBLIC_URL:checked.url,CONSOLE_TLS_CERT_FILE:process.platform==='win32'?certFile.replaceAll('\\','/'):certFile,CONSOLE_TLS_KEY_FILE:process.platform==='win32'?keyFile.replaceAll('\\','/'):keyFile}
    for (const key of tlsKeys) if (inherited[key] && inherited[key] !== values[key]) throw Error(`${key} is set in the parent environment and would override .env. Clear that override and retry`)
    let original = ''
    try { if(fs.lstatSync(envFile).isSymbolicLink()) throw Error('.env cannot be a symbolic link'); original=fs.readFileSync(envFile,'utf8') } catch(e) { if(e.code!=='ENOENT') throw e }
    const text = updateEnvText(original,values)
    if (text !== original) {
      if (original) fs.writeFileSync(path.join(directory,`env-backup-${randomUUID()}.txt`),original,{flag:'wx',mode:0o600})
      fs.mkdirSync(path.dirname(envFile),{recursive:true}); atomicWrite(envFile,text)
    }
    atomicWrite(currentFile,JSON.stringify({format:'aidotvpn-local-ca-v1',bundle:path.basename(bundle),caFingerprint:ca.fingerprint256},null,2)+'\n')
    return {reused,url:checked.url,envFile,certFile,keyFile,caFile:path.join(bundle,'ca-cert.pem'),caFingerprint:ca.fingerprint256,expiresAt:checked.certificate.expiresAt}
  } finally { if(stage)fs.rmSync(stage,{recursive:true,force:true}); fs.closeSync(handle); fs.rmSync(lock,{force:true}) }
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const result = generateCertificate(process.argv.slice(2))
    if(result.help)console.log(result.help)
    else { console.log(JSON.stringify(result,null,2));console.log('HTTPS configured. Run npm run check:https, then npm run start:https.\nThe local CA is not automatically trusted. See docs/https.md for optional trust setup.') }
  } catch(e) { console.error(`HTTPS certificate setup failed: ${e.message}`);console.error('Go must be installed (recommended: Go 1.27.1). Use npm run https:cert -- --help for options.');process.exitCode=1 }
}

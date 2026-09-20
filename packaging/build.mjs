import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { build } from 'esbuild'
import { inject } from 'postject'
import { assertBuildHost, requiredNodeVersion } from '../scripts/toolchain.mjs'
import { ensureNodeRuntime } from './node-runtime.mjs'
import { ensureGoToolchain } from './go-toolchain.mjs'
const require = createRequire(import.meta.url)
const here = path.dirname(fileURLToPath(import.meta.url))
const root = path.dirname(here)
assertBuildHost()
if (!['linux', 'win32'].includes(process.platform) || process.arch !== 'x64') throw new Error('This release supports native Linux/Windows x64 builders')
const version = fs.readFileSync(path.join(root, 'VERSION'), 'utf8').trim()
const edition = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).aidotEdition
if (!['public', 'full'].includes(edition)) throw Error('Build requires explicit public/full edition metadata')
const out = path.join(here, 'out', `${process.platform}-x64`)
const work = path.join(here, '.work', `${process.platform}-x64`)
fs.rmSync(out, {recursive: true, force: true}); fs.mkdirSync(out, {recursive: true}); fs.mkdirSync(work, {recursive: true})
const run = (exe, args, opts = {}) => execFileSync(exe, args, {stdio: 'inherit', ...opts})
// The runtime the installer embeds is downloaded and checksum-verified, never taken from PATH.
// Bytecode, the SEA blob and the base executable must all come from this one binary.
const runtime = await ensureNodeRuntime({version: requiredNodeVersion(root), platform: process.platform, arch: process.arch})
run(process.execPath, [path.join(root, 'console/node_modules/vite/bin/vite.js'), 'build'], {cwd: path.join(root, 'console')})
const app = path.join(work, 'app.cjs')
await build({entryPoints: [path.join(here, 'runtime/entry.mjs')], outfile: app, bundle: true, platform: 'node', format: 'cjs', target: 'node24', minify: true, sourcemap: false, legalComments: 'none', define: {AIDOT_BUILD_VERSION: JSON.stringify(version)}})
const bytecode = path.join(work, 'app.jsc')
run(runtime.execPath, [path.join(here, 'compile-bytecode.cjs'), app, bytecode])
const loader = path.join(work, 'loader.cjs')
const loaderText = `const {getAsset}=require('node:sea');
const bytenode=require(${JSON.stringify(require.resolve('bytenode'))});
const path=require('node:path');
const {isBuiltin}=require('node:module');
if(process.version!==${JSON.stringify('v' + runtime.version)} || process.arch!==${JSON.stringify(process.arch)} || process.platform!==${JSON.stringify(process.platform)}) throw Error('Runtime mismatch');
const fn=bytenode.runBytecode(Buffer.from(getAsset('server-bytecode')));
const mod={exports:{}};
function builtinOnly(id){if(!isBuiltin(id))throw Error('External modules disabled: '+id);return require(id)}
fn(mod.exports,builtinOnly,mod,process.execPath,path.dirname(process.execPath));
`
await build({stdin: {contents: loaderText, resolveDir: here, sourcefile: 'loader.cjs'}, outfile: loader, bundle: true, platform: 'node', format: 'cjs', target: 'node24', external: ['electron'], minify: true, legalComments: 'none'})
const assets = {'server-bytecode': bytecode}
const manifest = {}
function addAssets(dir, prefix = '') {
  for (const ent of fs.readdirSync(dir, {withFileTypes: true})) {
    const rel = prefix + ent.name
    if (ent.isDirectory()) addAssets(path.join(dir, ent.name), rel + '/')
    else {
      if (rel.endsWith('.map')) throw Error('Source map in customer assets')
      manifest[rel] = `ui/${rel}`; assets[manifest[rel]] = path.join(dir, ent.name)
    }
  }
}
addAssets(path.join(root, 'console/dist'))
const manifestPath = path.join(work, 'assets.json'); fs.writeFileSync(manifestPath, JSON.stringify(manifest)); assets['asset-manifest'] = manifestPath
const blob = path.join(work, 'sea.blob')
const config = path.join(work, 'sea.json')
fs.writeFileSync(config, JSON.stringify({main: loader, output: blob, disableExperimentalSEAWarning: true, useSnapshot: false, useCodeCache: false, execArgvExtension: 'none', assets}))
run(runtime.execPath, ['--experimental-sea-config', config])
const exe = path.join(out, process.platform === 'win32' ? 'aidotvpn-console.exe' : 'aidotvpn-console')
fs.copyFileSync(runtime.execPath, exe)
await inject(exe, 'NODE_SEA_BLOB', fs.readFileSync(blob), {sentinelFuse: 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2'})
fs.chmodSync(exe, 0o755)
// Pinned by the toolchain directive in server/go.mod, downloaded and checksum-verified when the
// build machine does not already have that exact compiler.
const go = (await ensureGoToolchain()).execPath
for (const name of ['controller', 'migrate', 'relay', ...(process.platform === 'linux' ? ['gateway-agent'] : [])]) {
  run(go, ['build', '-trimpath', '-buildvcs=false', '-ldflags', `-s -w -X main.agentVersion=${version}`, '-o', path.join(out, `aidotvpn-${name}${process.platform === 'win32' ? '.exe' : ''}`), `./cmd/${name}`], {cwd: path.join(root, 'server'), env: {...process.env, CGO_ENABLED: '0'}})
}
if (process.platform === 'win32') {
  const csc = process.env.AIDOT_BUILD_CSC || path.join(process.env.WINDIR, 'Microsoft.NET/Framework64/v4.0.30319/csc.exe')
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw Error('Invalid Windows assembly version')
  const assemblyInfo = path.join(work, 'AssemblyInfo.cs')
  fs.writeFileSync(assemblyInfo, `using System.Reflection;\n[assembly: AssemblyProduct("aidot-vpn")]\n[assembly: AssemblyVersion("${version}.0")]\n[assembly: AssemblyFileVersion("${version}.0")]\n[assembly: AssemblyInformationalVersion("${version}")]\n`)
  run(csc, ['/nologo', '/target:exe', '/platform:x64', '/optimize+', '/r:System.ServiceProcess.dll', `/out:${path.join(out, 'aidotvpn-service.exe')}`, path.join(here, 'windows/ServiceHost.cs'), assemblyInfo])
  run(csc, ['/nologo', '/target:winexe', '/platform:x64', '/optimize+', '/r:System.Windows.Forms.dll', '/r:System.Drawing.dll', '/r:System.ServiceProcess.dll', '/r:System.Web.Extensions.dll', `/win32icon:${path.join(here, 'windows/aidotvpn.ico')}`, `/win32manifest:${path.join(here, 'windows/app.manifest')}`, `/out:${path.join(out, 'aidotvpn-tray.exe')}`, path.join(here, 'windows/Tray.cs'), path.join(here, 'windows/ServiceControl.cs'), assemblyInfo])
}
// Preserve redistribution notices for every bundled third-party component.
let notices = 'AidotVPN distribution notices\n\n'
for (const name of ['LICENSE', 'NOTICE', 'LICENSE-SCOPE.md']) notices += `\n--- AidotVPN ${name} ---\n${fs.readFileSync(path.join(root, name), 'utf8')}\n`
function licenses(dir) {
 for (const e of fs.readdirSync(dir, {withFileTypes: true})) {
   const f = path.join(dir, e.name)
   if (e.isDirectory()) licenses(f)
   else if (/^(license|licence|copying|notice)(\.|$)/i.test(e.name)) notices += `\n--- ${path.relative(root, f)} ---\n${fs.readFileSync(f, 'utf8')}\n`
 }
}
licenses(path.join(root, 'console/node_modules')); licenses(path.join(here, 'node_modules'))
// Default to the LICENSE shipped inside the very distribution we embedded, so the notice cannot
// drift from the binary. An explicit AIDOT_BUILD_NODE_LICENSE still wins.
const nodeLicense = process.env.AIDOT_BUILD_NODE_LICENSE || runtime.licensePath
if (!nodeLicense || !fs.existsSync(nodeLicense)) throw new Error('AIDOT_BUILD_NODE_LICENSE must point to the matching Node distribution LICENSE')
notices += '\n--- Node.js ---\n' + fs.readFileSync(nodeLicense, 'utf8')
const modules = execFileSync(go, ['list', '-buildvcs=false', '-deps', '-f', '{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{.Module.Dir}}{{end}}', './cmd/...'], {cwd: path.join(root, 'server'), encoding: 'utf8'}).trim().split('\n')
for (const line of new Set(modules)) {
  const [name, modVersion, dir] = line.split('|')
  if (!modVersion) continue
  const files = fs.readdirSync(dir).filter(x => /^(LICENSE|COPYING|NOTICE)(\.|$)/i.test(x))
  if (!files.length) throw Error('Missing dependency license: ' + name)
  for (const file of files) notices += `\n--- ${name}@${modVersion}/${file} ---\n${fs.readFileSync(path.join(dir, file), 'utf8')}`
}
const goroot = execFileSync(go, ['env', 'GOROOT'], {encoding: 'utf8'}).trim()
notices += '\n--- Go ---\n' + fs.readFileSync(path.join(goroot, 'LICENSE'), 'utf8')
fs.writeFileSync(path.join(out, 'THIRD-PARTY-NOTICES.txt'), notices)
const hashes = {}
for (const name of fs.readdirSync(out)) hashes[name] = createHash('sha256').update(fs.readFileSync(path.join(out, name))).digest('hex')
fs.writeFileSync(path.join(out, 'build-manifest.json'), JSON.stringify({version, edition, node: process.version, v8: process.versions.v8, platform: process.platform, arch: process.arch, nodeBinarySHA256: createHash('sha256').update(fs.readFileSync(process.execPath)).digest('hex'), bytenode: require('bytenode/package.json').version, go: execFileSync(go, ['version'], {encoding: 'utf8'}).trim(), signed: false, hashes}, null, 2))
// Keep proprietary intermediate source/bytecode out of distributable directories.
fs.rmSync(work, {recursive: true, force: true})
console.log(`Built ${out}`)

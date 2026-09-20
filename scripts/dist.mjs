import fs from 'node:fs'
import path from 'node:path'
import {fileURLToPath} from 'node:url'
import {spawnSync} from 'node:child_process'
import {assertBuildHost} from './toolchain.mjs'
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const target=process.argv[2]
if (!['windows','linux'].includes(target)) throw Error('Use npm run dist:windows or npm run dist:linux')
// Bytecode and the SEA blob must be produced by a Node of the target platform, and dpkg-deb is
// Linux-only, so this artifact cannot be cross-built. scripts/build-edition.mjs explains the way out.
if(process.platform !== (target==='windows'?'win32':'linux')) throw Error(`Build ${target} on its native OS; this machine runs ${process.platform}. For Linux on Windows, run the same command inside WSL Ubuntu.`)
assertBuildHost() // The runtime the installer embeds is downloaded by packaging/build.mjs.
function run(cmd,args){const r=spawnSync(cmd,args,{cwd:root,stdio:'inherit',env:process.env});if(r.error)throw r.error;if(r.status!==0)throw Error(`${cmd} failed (${r.status})`)}
if(target==='windows'){
 const args=['-NoProfile','-File',path.join(root,'packaging/windows/build.ps1')]
 if(process.env.AIDOT_BUILD_ISCC)args.push('-Iscc',process.env.AIDOT_BUILD_ISCC)
 run('powershell.exe',args)
}else{
 run('npm',['--prefix','console','ci'])
 run('npm',['--prefix','packaging','ci','--ignore-scripts'])
 run(process.execPath,['packaging/build.mjs'])
 run(process.execPath,['--test','packaging/tests/paths.test.mjs'])
 run(process.execPath,['--test','packaging/tests/node-runtime.test.mjs'])
 run(process.execPath,['--test','packaging/tests/build-tools.test.mjs'])
 run(process.execPath,['--test','console/tests/i18n.test.mjs'])
 run(process.execPath,['packaging/tests/smoke.mjs'])
 run('python3',['packaging/linux/package.py'])
}
const version=fs.readFileSync(path.join(root,'VERSION'),'utf8').trim()
const name=target==='windows'?`AidotVPN-Server-${version}-windows-x64-setup.exe`:`aidotvpn-server_${version}_amd64.deb`
const source=path.join(root,'packaging/installers',name)
const dest=path.join(root,'dist',version);fs.mkdirSync(dest,{recursive:true});fs.copyFileSync(source,path.join(dest,name))
console.log(`Installer: ${path.join(dest,name)} (unsigned)`)

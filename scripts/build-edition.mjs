import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { assertBuildHost } from './toolchain.mjs'
const projectRoot=path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const sha256=data=>createHash('sha256').update(data).digest('hex')
function nativeOsMessage(target,root){
 const wsl=root.replace(/^([A-Za-z]):/,(m,drive)=>`/mnt/${drive.toLowerCase()}`).replace(/\\/g,'/')
 return [
  `\`npm run dist:${target}\` builds on ${target==='windows'?'Windows':'Linux'}; this machine runs ${process.platform}.`,
  '',
  'This one cannot be cross-built. The console server is shipped as V8 bytecode inside a single-file',
  'executable: the bytecode and the SEA blob have to be produced by a Node of the target platform, and',
  'the Debian package is assembled by dpkg-deb. Go is the only part that cross-compiles.',
  '',
  ...(process.platform==='win32'&&target==='linux'?[
   'On this Windows machine, run it inside WSL Ubuntu, which reaches the same folder:',
   '',
   '  wsl -d Ubuntu',
   `  cd ${wsl}`,
   '  npm run dist:linux',
   '',
   'WSL needs Node (the floor in package.json engines) and dpkg-deb; the pinned Node runtime, Go',
   'toolchain and every other build tool are still downloaded and checksum-verified by the build.',
   '',
   `[ko] 리눅스 .deb 는 윈도우에서 만들 수 없습니다. 바이트코드와 SEA 블롭은 대상 OS 의 Node 가 만들어야 하고`,
   '     dpkg-deb 도 리눅스 전용입니다. 위 명령처럼 WSL Ubuntu 안에서 같은 폴더로 들어가 실행하세요.',
   '     윈도우 설치본은 이 PC 에서 `npm run dist:windows` 로 그대로 만들 수 있습니다.'
  ]:[])
 ].join('\n')
}
const args=process.argv.slice(2),target=args[0]
if(!['electron','windows','linux'].includes(target)||args.slice(1).some(a=>!['--full','--dir','--dry-run'].includes(a)))throw Error('Use a documented dist command, optionally with -- --dry-run')
// Check the build host before exporting a Public snapshot to a temporary directory, so an
// unusable Node fails in under a second instead of after the copy.
assertBuildHost()
// A .deb cannot be produced from Windows: the console bytecode and the SEA blob must be made by a
// Linux Node, and dpkg-deb is Linux-only. Say so here, before the Public export is copied anywhere.
if(['windows','linux'].includes(target)&&process.platform!==(target==='windows'?'win32':'linux'))throw Error(nativeOsMessage(target,projectRoot))
const pkg=JSON.parse(fs.readFileSync(path.join(projectRoot,'package.json'),'utf8'))
const full=args.includes('--full')
if(full&&pkg.aidotEdition!=='full')throw Error('Enterprise source is not present in the Public edition')
const edition=full?'full':'public',version=pkg.version
let root=projectRoot,sourceManifest
if(!full&&pkg.aidotEdition==='full') {
  const { exportPublic } = await import('./public-export.mjs')
  const result=exportPublic({});root=result.directory;sourceManifest=fs.readFileSync(path.join(root,'PUBLIC_MANIFEST.json'))
} else if(!full)sourceManifest=fs.readFileSync(path.join(root,'PUBLIC_MANIFEST.json'))
const output=path.join(projectRoot,'dist',version,full?'enterprise':'public')
const command=target==='electron'?['scripts/electron.mjs',...(args.includes('--dir')?['--dir']:[])]:['scripts/dist.mjs',target]
if(args.includes('--dry-run')){console.log(JSON.stringify({edition,source:root,output,command:[process.execPath,...command],sourceManifestSHA256:sourceManifest?sha256(sourceManifest):null},null,2));process.exit(0)}
const result=spawnSync(process.execPath,command,{cwd:root,stdio:'inherit',env:process.env,shell:false})
if(result.error||result.status!==0)throw Error(`Build failed (${result.status}): ${result.error?.message||'see log'}`)
if(args.includes('--dir')){console.log(`Unpacked ${edition} application: ${path.join(root,'dist',version,'electron/win-unpacked')}`);process.exit(0)}
const name=target==='electron'?`AidotVPN-Desktop-${version}-windows-x64-setup.exe`:target==='windows'?`AidotVPN-Server-${version}-windows-x64-setup.exe`:`aidotvpn-server_${version}_amd64.deb`
const input=path.join(root,'dist',version,...(target==='electron'?['electron']:[]),name)
const file=full?name.replace(version,version+'-full'):name.replace(version,version+'-public')
fs.mkdirSync(output,{recursive:true});fs.copyFileSync(input,path.join(output,file))
const bytes=fs.readFileSync(path.join(output,file))
const artifact={file,bytes:bytes.length,sha256:sha256(bytes),edition,version,sourceManifestSHA256:sourceManifest?sha256(sourceManifest):null,signing:'Verify the platform signature before distribution'}
const manifestFile=path.join(output,full?'enterprise-artifacts.json':'public-artifacts.json')
let manifest={edition,version,artifacts:[]}
if(fs.existsSync(manifestFile)){manifest=JSON.parse(fs.readFileSync(manifestFile));if(manifest.edition!==edition||manifest.version!==version)throw Error('Conflicting artifact manifest')}
manifest.artifacts=manifest.artifacts.filter(a=>a.file!==file);manifest.artifacts.push(artifact)
fs.writeFileSync(manifestFile,JSON.stringify(manifest,null,2)+'\n')
if(sourceManifest)fs.writeFileSync(path.join(output,'SOURCE_PUBLIC_MANIFEST.json'),sourceManifest)
console.log(JSON.stringify({...artifact,path:path.join(output,file)},null,2))

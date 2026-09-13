import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import http from 'node:http'
import {once} from 'node:events'
import {spawn,execFileSync} from 'node:child_process'
import {fileURLToPath} from 'node:url'
const here=path.dirname(fileURLToPath(import.meta.url))
const exe=path.resolve(process.argv[2] || path.join(here,'../out',`${process.platform}-x64`,`aidotvpn-console${process.platform==='win32'?'.exe':''}`))
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'aidotvpn 설치 검증 '))
const env={...process.env,AIDOTVPN_DATA_DIR:dir,AIDOTVPN_CONFIG_DIR:path.join(dir,'config'),AIDOTVPN_SCOPE:'user',NODE_OPTIONS:'--require=/must-not-load.js'}
let child;let upstream;const checks=[]
function pass(name){checks.push(name)}
try{
 const paths=JSON.parse(execFileSync(exe,['--paths'],{env,cwd:os.tmpdir(),encoding:'utf8'}));assert.equal(paths.data,dir);pass('isolated Unicode path and NODE_OPTIONS ignored')
 execFileSync(exe,['--init'],{env,cwd:os.tmpdir()})
 const file=path.join(dir,'config/console.json');const cfg=JSON.parse(fs.readFileSync(file,'utf8'))
 upstream=http.createServer((req,res)=>{
  if(req.url==='/auth/login'){res.setHeader('Set-Cookie','aidot_session=smoke; HttpOnly; SameSite=Strict; Path=/');res.end('{"ok":true}');return}
  if(req.url==='/auth/me'){res.statusCode=req.headers.cookie==='aidot_session=smoke'?200:401;res.end(JSON.stringify({authorized:res.statusCode===200}));return}
  res.statusCode=404;res.end()
 });upstream.listen(0,'127.0.0.1');await once(upstream,'listening')
 const portProbe=http.createServer();portProbe.listen(0,'127.0.0.1');await once(portProbe,'listening');cfg.port=portProbe.address().port;await new Promise(r=>portProbe.close(r))
 cfg.controllerURL=`http://127.0.0.1:${upstream.address().port}`;fs.writeFileSync(file,JSON.stringify(cfg))
 const original=fs.readFileSync(file,'utf8');execFileSync(exe,['--init'],{env});assert.equal(fs.readFileSync(file,'utf8'),original);pass('initialization preserves existing configuration')
 // Run with no source tree/node_modules/current-directory assets available.
 child=spawn(exe,[],{env,cwd:dir,stdio:['ignore','pipe','pipe']});let log='';child.stdout.on('data',b=>log+=b);child.stderr.on('data',b=>log+=b)
 const base=`http://127.0.0.1:${cfg.port}`;let ready=false
 for(let i=0;i<100;i++){try{ready=(await fetch(base+'/healthz')).ok;if(ready)break}catch{}await new Promise(r=>setTimeout(r,100))}
 assert.ok(ready,log);pass('SEA starts without Node/npm/source installation')
 const html=await (await fetch(base+'/')).text();assert.match(html,/<html/);pass('embedded SPA')
 const js=html.match(/src="([^"]+\.js)"/)[1];const asset=await fetch(base+js);assert.equal(asset.status,200);assert.match(asset.headers.get('content-type'),/javascript/);pass('embedded browser JavaScript MIME')
 assert.equal((await fetch(base+js+'.map')).status,404);pass('source maps unavailable')
 const login=await fetch(base+'/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});assert.equal(login.status,200);assert.match(login.headers.get('set-cookie'),/HttpOnly/)
 assert.equal((await fetch(base+'/api/auth/me')).status,401)
 assert.equal((await fetch(base+'/api/auth/me',{headers:{Cookie:'aidot_session=smoke'}})).status,200);pass('session cookie roundtrip through production proxy')
 assert.equal((await fetch(base+'/api/notfound')).status,404);pass('unknown API does not return SPA')
 assert.equal((await fetch(base+'/devices')).status,200);pass('SPA deep link')
 await new Promise(r=>upstream.close(r));upstream=null
 const bad=await fetch(base+'/api/auth/me');assert.equal(bad.status,502);assert.equal((await bad.json()).message,'Controller unavailable');pass('upstream failure gives sanitized 502')
 const exit=once(child,'exit');child.kill('SIGTERM');const [code]=await exit;if(process.platform!=='win32')assert.equal(code,0);child=null;pass(process.platform==='win32'?'process termination (Windows forced stop)':'graceful shutdown')
 console.log(JSON.stringify({platform:process.platform,checks,passed:checks.length},null,2))
}finally{if(child)child.kill();if(upstream)await new Promise(r=>upstream.close(r));fs.rmSync(dir,{recursive:true,force:true})}

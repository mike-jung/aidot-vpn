import {test} from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import http from 'node:http'
import https from 'node:https'
import {execFileSync} from 'node:child_process'
import {once} from 'node:events'
import {startConsole,configFrom,validateConfig,defaults} from '../listener.js'
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'aidot-https-'))
process.on('exit',()=>fs.rmSync(dir,{recursive:true,force:true}))
const key=path.join(dir,'key.pem'),cert=path.join(dir,'cert.pem')
execFileSync(process.env.AIDOT_OPENSSL || 'openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'],{stdio:'ignore'})
const request=(url,{method='GET',body,headers={}}={})=>new Promise((resolve,reject)=>{
 const r=(url.startsWith('https:')?https:http).request(url,{method,agent:false,ca:fs.readFileSync(cert),headers:{...headers,...(body?{'Content-Type':'application/json'}:{})}},res=>{let b='';res.on('data',c=>b+=c);res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:b,data:()=>JSON.parse(b)}))});r.on('error',reject);r.end(body?JSON.stringify(body):undefined)
})
async function freePort(){const s=http.createServer();s.listen(0,'127.0.0.1');await once(s,'listening');const p=s.address().port;await new Promise(r=>s.close(r));return p}
test('HTTPS configuration fails closed for invalid certificate, hostname and remote plaintext upstream',()=>{
 const cfg=configFrom({port:9111,publicURL:'https://localhost:9111',https:{enabled:true,certFile:cert,keyFile:key}},{},{})
 assert.ok(validateConfig(cfg).options)
 assert.throws(()=>validateConfig({...cfg,publicURL:'https://wrong.example:9111'}),/hostname_mismatch/)
 assert.throws(()=>validateConfig({...cfg,https:{...cfg.https,keyFile:cert}}),/certificate_or_key_invalid/)
 assert.throws(()=>validateConfig({...defaults,controllerURL:'http://remote.example:10030'}),/remote_controller/)
 assert.throws(()=>configFrom({}, {}, {CONSOLE_HTTPS_ENABLED:'yes'}),/invalid_https/)
})
test('authenticated live HTTP→HTTPS switch, cookie security, conflict rollback, restart persistence',async()=>{
 let role='admin',forced=false
 const auth=http.createServer((req,res)=>{
  res.setHeader('Content-Type','application/json')
  if(req.url==='/auth/me') {res.statusCode=req.headers.cookie==='aidot_session=test'?200:401;res.end(JSON.stringify({admin:{role,must_change_password:forced}}))}
  else if(req.url==='/auth/login'){res.setHeader('Set-Cookie',`aidot_session=test; HttpOnly; SameSite=Strict; Path=/; ${req.headers['x-forwarded-proto']==='https'?'Secure':''}`);res.end('{}')}
  else res.end('{}')
 });auth.listen(0,'127.0.0.1');await once(auth,'listening')
 const port=await freePort(),stateFile=path.join(dir,'console-settings.json'),base={port,controllerURL:`http://127.0.0.1:${auth.address().port}`}
 let running=await startConsole({base,stateFile,env:{},readAsset:k=>k==='index.html'?Buffer.from('<html>test</html>'):null})
 const httpURL=`http://127.0.0.1:${port}`,httpsURL=`https://127.0.0.1:${port}`,cookie={Cookie:'aidot_session=test'}
 try {
  assert.equal((await request(httpURL+'/api/console/settings')).status,401)
  role='viewer';assert.equal((await request(httpURL+'/api/console/settings',{headers:cookie})).status,403)
  role='admin';forced=true;assert.equal((await request(httpURL+'/api/console/settings',{headers:cookie})).status,403);forced=false
  const body={bindHost:'127.0.0.1',port,publicURL:httpsURL,https:{enabled:true,certFile:cert,keyFile:key}}
  assert.equal((await request(httpURL+'/api/console/settings',{method:'PUT',headers:{...cookie,Origin:'https://attacker.example'},body})).status,403)
  const saved=await request(httpURL+'/api/console/settings',{method:'PUT',headers:{...cookie,Origin:httpURL},body});assert.equal(saved.status,200,saved.body)
  assert.equal((await request(httpsURL+'/healthz')).status,200)
  assert.match((await request(httpsURL+'/api/auth/login',{method:'POST',body:{},headers:{'X-Forwarded-Proto':'http'}})).headers['set-cookie'][0],/Secure/)
  try { assert.notEqual((await request(httpURL+'/healthz')).status,200) } catch(e) { if(e.code!=='ECONNRESET')throw e }
  const occupied=http.createServer();occupied.listen(0,'127.0.0.1');await once(occupied,'listening');const busy=occupied.address().port
  assert.equal((await request(httpsURL+'/api/console/settings',{method:'PUT',headers:{...cookie,Origin:httpsURL},body:{...body,port:busy,publicURL:`https://localhost:${busy}`}})).status,400)
  assert.equal((await request(httpsURL+'/healthz')).status,200)
  await new Promise(r=>occupied.close(r))
  assert.ok(!JSON.stringify((await request(httpsURL+'/api/console/settings',{headers:cookie})).data()).includes('PRIVATE KEY'))
  await running.close();running=await startConsole({base,stateFile,env:{CONSOLE_PORT:String(port)},readAsset:()=>null});assert.equal((await request(httpsURL+'/healthz')).status,200)
  const locked=await request(httpsURL+'/api/console/settings',{method:'PUT',headers:{...cookie,Origin:httpsURL},body:{...body,port:port+1,publicURL:`https://localhost:${port+1}`}})
  assert.equal(locked.status,409);assert.equal(locked.data().error,'settings_managed_by_environment')
  // A port override must not prevent a separate HTTPS field from being changed.
  const plain=await request(httpsURL+'/api/console/settings',{method:'PUT',headers:{...cookie,Origin:httpsURL},body:{...body,publicURL:httpURL,https:{...body.https,enabled:false}}})
  assert.equal(plain.status,200,plain.body);assert.equal((await request(httpURL+'/healthz')).status,200)
 } finally {await running.close();auth.closeAllConnections();await new Promise(r=>auth.close(r))}
})
test('environment values take precedence over saved defaults',()=>{
 const c=configFrom({port:9111},{port:9555},{CONSOLE_PORT:'9888',CONSOLE_HTTPS_ENABLED:'false'});assert.equal(c.port,9888);assert.equal(c.https.enabled,false)
})

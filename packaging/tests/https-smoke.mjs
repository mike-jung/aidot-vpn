// Actual installed/SEA binary TLS probe. Test certificate supplied explicitly; no global trust changes.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import http from 'node:http'
import https from 'node:https'
import {spawn,execFileSync} from 'node:child_process'
import {once} from 'node:events'
const [exe,certFile,keyFile]=process.argv.slice(2)
if(!exe || !certFile || !keyFile)throw Error('Usage: node https-smoke.mjs <console executable> <test PEM certificate> <test PEM key>')
const root=fs.mkdtempSync(path.join(os.tmpdir(),'aidotvpn-tls-'))
const env={...process.env,AIDOTVPN_DATA_DIR:root,AIDOTVPN_CONFIG_DIR:path.join(root,'config'),AIDOTVPN_SCOPE:'user',AIDOTVPN_SERVICE_STDIN:'1'}
let child,upstream
const checks=[]
try {
 upstream=http.createServer((req,res)=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify({forwardedProtocol:req.headers['x-forwarded-proto']}))});upstream.listen(0,'127.0.0.1');await once(upstream,'listening')
 const probe=http.createServer();probe.listen(0,'127.0.0.1');await once(probe,'listening');const port=probe.address().port;await new Promise(r=>probe.close(r))
 execFileSync(exe,['--init'],{env})
 const file=path.join(root,'config','console.json'),cfg=JSON.parse(fs.readFileSync(file,'utf8'));cfg.port=port;cfg.controllerURL=`http://127.0.0.1:${upstream.address().port}`;fs.writeFileSync(file,JSON.stringify(cfg))
 fs.writeFileSync(path.join(root,'config','console.env'),`CONSOLE_HTTPS_ENABLED=true\nCONSOLE_PUBLIC_URL=https://localhost:${port}\nCONSOLE_TLS_CERT_FILE=${path.resolve(certFile)}\nCONSOLE_TLS_KEY_FILE=${path.resolve(keyFile)}\n`)
 child=spawn(exe,[],{env,cwd:root,stdio:['pipe','pipe','pipe']});let output='';child.stdout.on('data',c=>output+=c);child.stderr.on('data',c=>output+=c)
 const get=()=>new Promise((resolve,reject)=>{https.get(`https://localhost:${port}/api/probe`,{ca:fs.readFileSync(certFile),agent:false,headers:{'X-Forwarded-Proto':'http'}},r=>{let s='';r.on('data',c=>s+=c);r.on('end',()=>resolve({status:r.statusCode,...JSON.parse(s)}))}).on('error',reject)})
 let result;for(let i=0;i<100;i++){try{result=await get();break}catch{}await new Promise(r=>setTimeout(r,100))}
 assert.equal(result?.status,200,output);checks.push('SEA loads console.env and serves verified TLS')
 assert.equal(result.forwardedProtocol,'https');checks.push('Spoofed protocol header replaced with actual TLS protocol')
 const exited=once(child,'exit');child.stdin.write('shutdown\r\n');const timeout=setTimeout(()=>child?.kill(),10000);const [code]=await exited;clearTimeout(timeout);assert.equal(code,0);child=null;checks.push('Service stdin CRLF shuts down SEA cleanly')
 console.log(JSON.stringify({platform:process.platform,passed:checks.length,checks},null,2))
}finally{if(child)child.kill();if(upstream){upstream.closeAllConnections();await new Promise(r=>upstream.close(r))}fs.rmSync(root,{recursive:true,force:true})}

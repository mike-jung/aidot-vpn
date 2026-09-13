import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import https from 'node:https'
import http from 'node:http'
import { once } from 'node:events'
import { spawnSync, spawn } from 'node:child_process'
import { X509Certificate } from 'node:crypto'
import { parseEnv } from 'node:util'
import { generateCertificate, updateEnvText } from '../https-cert.mjs'
import { readSourceConfig, sourceRoot } from '../../console/source-config.js'
import { configFrom, validateConfig } from '../../console/listener-config.js'

test('missing, relative, drive-relative and unreadable certificate paths are distinguished', () => {
  const cfg = configFrom({port:6193,https:{enabled:true}}, {}, {})
  assert.throws(()=>validateConfig(cfg), /certificate_paths_missing/)
  assert.throws(()=>validateConfig({...cfg,https:{enabled:true,certFile:'cert.pem',keyFile:'key.pem'}}),/certificate_paths_must_be_absolute/)
  assert.throws(()=>configFrom({}, {}, {CONSOLE_TLS_CERT_FILE:'D:cert.pem'},sourceRoot),/certificate_paths_must_be_absolute/)
  const normalized = configFrom({}, {}, {CONSOLE_TLS_CERT_FILE:'certs/cert.pem',CONSOLE_TLS_KEY_FILE:'certs/key.pem'}, sourceRoot)
  assert.equal(normalized.https.certFile,path.join(sourceRoot,'certs/cert.pem'))
  assert.throws(()=>validateConfig({...cfg,https:{...normalized.https,enabled:true}}), /certificate_file_not_found/)
})
test('env update preserves comments, BOM, CRLF and unrelated quoted/multiline secrets',()=>{
  const source='\uFEFF# keep this\r\nDB_PASSWORD="a # secret"\r\nMULTI="first\nsecond"\r\nCONSOLE_PUBLIC_URL="http://localhost:6193"\r\nCONSOLE_PUBLIC_URL=old\r\n'
  const values={CONSOLE_HTTPS_ENABLED:'true',CONSOLE_PUBLIC_URL:'https://localhost:6193',CONSOLE_TLS_CERT_FILE:'D:/한글 폴더/fullchain.pem',CONSOLE_TLS_KEY_FILE:'D:/한글 폴더/privkey.pem'}
  const changed=updateEnvText(source,values)
  assert.ok(changed.startsWith('\uFEFF# keep this\r\n'))
  assert.equal(parseEnv(changed).DB_PASSWORD,'a # secret')
  assert.equal(parseEnv(changed).MULTI,'first\nsecond')
  assert.equal(parseEnv(changed).CONSOLE_TLS_CERT_FILE,values.CONSOLE_TLS_CERT_FILE)
  assert.equal(changed.match(/CONSOLE_PUBLIC_URL=/g).length,1)
  assert.equal(updateEnvText(changed,values),changed)
})
const go = process.env.AIDOT_GO || 'go'
const hasGo = spawnSync(go,['version'],{encoding:'utf8'}).status===0
test('real private CA generation, reuse, renewal, Windows-compatible paths and HTTPS source entry', {skip:!hasGo && 'Go unavailable; run this integration test on the Go build host'},async()=>{
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'Aidot HTTPS 한글 '))
  const inherited={...process.env,AIDOT_GO:go}
  for(const key of Object.keys(inherited)) if(/^(CONSOLE_|AIDOTVPN_CONSOLE_ENV_FILE|AIDOTVPN_DATA_DIR|PORT$|BIND_HOST$|CONTROLLER_URL$)/.test(key))delete inherited[key]
  const envFile=path.join(temp,'.env'), helper=path.join(temp,'scripts/certs')
  fs.mkdirSync(helper,{recursive:true});fs.copyFileSync(path.join(sourceRoot,'scripts/certs/main.go'),path.join(helper,'main.go'))
  const probe=http.createServer();probe.listen(0,'127.0.0.1');await once(probe,'listening');const port=probe.address().port;await new Promise(r=>probe.close(r))
  const original=`# preserve this\r\nCONSOLE_PORT=${port}\r\nDB_PASSWORD="keep # quoted"\r\n`
  fs.writeFileSync(envFile,original)
  let child
  const request=(url,ca)=>new Promise((resolve,reject)=>{
    const req=https.get(url,{ca,agent:false},res=>{res.resume();res.on('end',()=>resolve(res.statusCode))});req.on('error',reject)
  })
  try {
    const first=generateCertificate([],{root:temp,inherited})
    const cert=new X509Certificate(fs.readFileSync(first.certFile)),ca=new X509Certificate(fs.readFileSync(first.caFile))
    assert.equal(cert.ca,false);assert.equal(ca.ca,true);assert.ok(cert.verify(ca.publicKey));assert.ok(cert.checkHost('localhost'));assert.ok(cert.checkIP('127.0.0.1'));assert.ok(cert.checkIP('::1'))
    assert.equal(parseEnv(fs.readFileSync(envFile,'utf8')).DB_PASSWORD,'keep # quoted')
    assert.equal(generateCertificate([],{root:temp,inherited}).certFile,first.certFile)
    assert.throws(()=>generateCertificate(['--host','other.example'],{root:temp,inherited}),/renewal/)
    const next=generateCertificate(['--renew','--host','other.example'],{root:temp,inherited})
    assert.notEqual(next.certFile,first.certFile);assert.equal(next.caFingerprint,first.caFingerprint)
    assert.ok(new X509Certificate(fs.readFileSync(next.certFile)).checkHost('other.example'))
    assert.ok(fs.existsSync(first.keyFile),'renewal preserves the preceding certificate bundle')
    // Make the real preflight and child server resolve paths from a custom env file.
    const relative=fs.readFileSync(envFile,'utf8').replaceAll(next.certFile.replaceAll('\\','/'),path.relative(temp,next.certFile).replaceAll('\\','/')).replaceAll(next.keyFile.replaceAll('\\','/'),path.relative(temp,next.keyFile).replaceAll('\\','/'))
    fs.writeFileSync(envFile,relative)
    const childEnv={...inherited,AIDOTVPN_CONSOLE_ENV_FILE:envFile}
    const preflight=spawnSync(process.execPath,[path.join(sourceRoot,'scripts/start-https.mjs'),'--check'],{cwd:os.tmpdir(),env:childEnv,encoding:'utf8'})
    assert.equal(preflight.status,0,preflight.stderr)
    const parsed=readSourceConfig({root:temp,inherited:childEnv});assert.equal(parsed.cfg.https.certFile,next.certFile)
    child=spawn(process.execPath,[path.join(sourceRoot,'console/server.js')],{cwd:os.tmpdir(),env:childEnv,stdio:['ignore','pipe','pipe']})
    let output='';child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>output+=b)
    let healthy=false
    for(let i=0;i<100;i++) {
      if(child.exitCode!==null)throw Error(output)
      try { healthy=await request(`https://localhost:${port}/healthz`,fs.readFileSync(next.caFile))===200; if(healthy)break }catch{}
      await new Promise(r=>setTimeout(r,100))
    }
    assert.ok(healthy,output)
    await assert.rejects(request(`https://localhost:${port}/healthz`),/certificate|issuer|self-signed/i)
  } finally { if(child && child.exitCode===null){child.kill();await once(child,'exit')} fs.rmSync(temp,{recursive:true,force:true}) }
})

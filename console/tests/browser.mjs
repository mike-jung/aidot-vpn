// Real browser rendering with explicit API fixtures; does not claim live VPN/DB coverage.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import http from 'node:http'
import {once} from 'node:events'
import {createRequire} from 'node:module'
import {fileURLToPath} from 'node:url'
import {startConsole} from '../listener.js'
const require=createRequire(import.meta.url)
const {chromium}=require(process.env.AIDOT_TEST_PLAYWRIGHT || 'playwright')
const here=path.dirname(fileURLToPath(import.meta.url)),out=process.env.AIDOT_TEST_OUTPUT || path.join(here,'../../verification/browser-1.18.0')
fs.mkdirSync(out,{recursive:true})
const data=fs.mkdtempSync(path.join(os.tmpdir(),'aidot-browser-'))
const now=new Date().toISOString(),device={id:'d'.repeat(32),display_name:'Test Android',platform:'android',status:'active',ipv4:'10.78.0.2',policy_name:'Office',created_at:now,last_handshake_at:now,app_filter_mode:'off',device_mode:'standalone'}
const policy={id:'a'.repeat(32),name:'Office',description:'Test policy',enabled:true,allowed_ips:[{id:'b'.repeat(32),cidr:'10.20.0.0/24',description:'Business network'}]}
const admin={email:'test@example.com',display_name:'Test administrator',role:'admin',must_change_password:false}
const upstream=http.createServer(async(req,res)=>{
 let raw='';for await(const c of req)raw+=c;const body=raw?JSON.parse(raw):{}
 res.setHeader('Content-Type','application/json')
 const route=req.url.split('?')[0]
 let value={}
 if(route==='/auth/login') {
  if(body.code!=='123456'){res.statusCode=428;value={error:'인증 앱의 6자리 숫자를 입력하세요.'}}
  else {res.setHeader('Set-Cookie','aidot_session=browser; HttpOnly; SameSite=Strict; Path=/');value={admin}}
 } else if(route==='/auth/me') {if(!req.headers.cookie?.includes('aidot_session=browser'))res.statusCode=401;value={admin}}
 else if(route==='/devices')value={devices:[device]}
 else if(route==='/policies')value={policies:[policy]}
 else if(route==='/policies/'+policy.id)value=policy
 else if(route==='/policies/'+policy.id+'/settings')value={tunnel_mode:'split',dns_servers:[],dns_search_domains:[]}
 else if(route==='/groups')value={groups:[]}
 else if(route==='/nodes')value={nodes:[{id:'c'.repeat(32),hostname:'Test gateway',last_report_at:now,wg_interface_up:true,wg_backend:'kernel',responder_up:true,tunnel_address:'10.78.0.1',agent_version:'1.18.0',online_devices:1,total_devices:1,public_endpoints:[]}]}
 else if(route==='/enrollment-password')value={password:'test-password',is_default:false}
 else if(route==='/settings/ports')value={ports:[{name:'컨트롤러 API',port:10030,proto:'TCP',env:'CONTROLLER_HTTP_LISTEN',reason:'등록·정책·폐기 통보',scope:'admin'}],note:'.env 의 변수를 고치고 npm start 를 다시 실행하면 바뀝니다'}
 else if(route==='/settings/access')value={device_expiry_days:0,min_os_sdk:0}
 else if(route==='/audit')value={entries:[]}
 else if(route==='/reach')value={edges:[],overlaps:{},unbound:0}
 res.end(JSON.stringify(value))
})
upstream.listen(0,'127.0.0.1');await once(upstream,'listening')
const probe=http.createServer();probe.listen(0,'127.0.0.1');await once(probe,'listening');const port=probe.address().port;await new Promise(r=>probe.close(r))
const server=await startConsole({base:{port,controllerURL:`http://127.0.0.1:${upstream.address().port}`},stateFile:path.join(data,'console-settings.json'),env:{},distDir:path.resolve(here,'../dist')})
const browser=await chromium.launch({headless:true,...(process.env.AIDOT_TEST_BROWSER_CHANNEL?{channel:process.env.AIDOT_TEST_BROWSER_CHANNEL}:{})})
const errors=[],checks=[]
const context=await browser.newContext({locale:'en-US',viewport:{width:1440,height:1100}}),page=await context.newPage()
page.on('pageerror',e=>errors.push(e.message))
function pass(name){checks.push(name)}
async function noKorean(name){
 const texts=await page.locator('body').innerText()
 const cleaned=texts.replaceAll('Language / 언어','').replaceAll('한국어','')
 const leaks=cleaned.split('\n').filter(t=>/[가-힣]/.test(t))
 assert.deepEqual(leaks,[],`${name}: untranslated text`)
}
try {
 const url=`http://127.0.0.1:${port}`
 await page.goto(url+'/login?next=%2F%3Fsettings%3D1');await page.waitForLoadState('networkidle')
 await noKorean('login');await page.locator('#login-language').selectOption('ko');assert.equal(await page.locator('html').getAttribute('lang'),'ko')
 await page.screenshot({path:path.join(out,'login-ko.png'),fullPage:true})
 await page.locator('#email').fill('test@example.com');await page.locator('#password').fill('test-password')
 await page.getByRole('button',{name:'로그인',exact:true}).click()
 await page.locator('input[autocomplete="one-time-code"]').waitFor({state:'visible'})
 assert.equal(await page.locator('form input[autocomplete="one-time-code"]').count(),1)
 await page.locator('input[autocomplete="one-time-code"]').fill('123456');await page.getByRole('button',{name:'로그인',exact:true}).click()
 await page.locator('#settings-language').waitFor({state:'visible'});pass('Korean login, 428 challenge, two-factor input inside form, settings deep link')
 await page.locator('#console-bind').fill('127.0.0.2')
 await page.locator('#settings-language').selectOption('en');await noKorean('settings');assert.equal(await page.locator('#console-bind').inputValue(),'127.0.0.2');pass('Live language switch preserves unsaved settings and translates server port descriptions')
 await page.screenshot({path:path.join(out,'settings-en.png'),fullPage:true})
 await page.reload();await page.locator('#settings-language').waitFor();assert.equal(await page.locator('#settings-language').inputValue(),'en');pass('Language persists after reload')
 for(const route of ['/','/devices','/nodes','/groups','/policies','/reach','/enrollment-requests','/trace','/audit']) {
  await page.goto(url+route);await page.waitForLoadState('networkidle');await noKorean(route)
  if(route==='/policies'){await page.locator('.list-group-item').filter({hasText:'Office'}).click();await page.waitForLoadState('networkidle');await noKorean('policy details')}
  pass('English '+route)
 }
 await page.goto(url+'/?settings=1');await page.locator('#settings-language').waitFor();await page.locator('#settings-language').selectOption('ko');assert.ok((await page.locator('body').innerText()).includes('콘솔 접속 · HTTPS'))
 await page.screenshot({path:path.join(out,'settings-ko.png'),fullPage:true});pass('Switch back to Korean')
 await page.setViewportSize({width:390,height:844});await page.screenshot({path:path.join(out,'settings-mobile-ko.png'),fullPage:true})
 assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1),'Mobile page overflows horizontally');pass('390px viewport without horizontal page overflow')
 assert.deepEqual(errors,[]);pass('No browser runtime errors')
} finally {await browser.close();await server.close();upstream.closeAllConnections();await new Promise(r=>upstream.close(r));fs.rmSync(data,{recursive:true,force:true});fs.writeFileSync(path.join(out,'results.json'),JSON.stringify({checks,errors,passed:checks.length,fixtureAPI:true},null,2))}
console.log(JSON.stringify({checks,errors,passed:checks.length,fixtureAPI:true},null,2))

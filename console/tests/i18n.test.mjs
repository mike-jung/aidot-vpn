import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import {fileURLToPath} from 'node:url'
import {parse as sfc} from '@vue/compiler-sfc'
import {parse as html} from '@vue/compiler-dom'
import {translate as tr,locale,apiMessage} from '../src/i18n/index.js'
const catalog=JSON.parse(fs.readFileSync(new URL('../src/i18n/en.json',import.meta.url)))
test('all English messages preserve interpolation parameters and contain no untranslated Korean',()=>{
 for(const [ko,en] of Object.entries(catalog)) {
  assert.ok(en.trim(),ko);assert.ok(!/[가-힣]/.test(en),ko)
  assert.deepEqual([...ko.matchAll(/\{\d+\}/g)].map(m=>m[0]).sort(),[...en.matchAll(/\{\d+\}/g)].map(m=>m[0]).sort(),ko)
 }
})
test('locale updates existing messages, parameters and API errors without translating unknown data',()=>{
 locale.value='en';assert.equal(tr('설정'),'Settings');assert.equal(tr('{0}분 전',[3]),'3 minutes ago');assert.equal(tr('3분 전'),'3 minutes ago')
 assert.equal(tr('고객 고유 장비명'),'고객 고유 장비명');assert.equal(tr(apiMessage('certificate_hostname_mismatch',400)),'The certificate does not cover the hostname in the browser address.')
 locale.value='ko';assert.equal(tr('설정'),'설정');assert.equal(tr('{0}분 전',[3]),'3분 전');assert.equal(tr('aidotvpn-admin'),'관리자')
})
test('Vue templates have no hard-coded Korean display text outside the bilingual language selector',()=>{
 const missing=[]
 const walkDir=dir=>{for(const ent of fs.readdirSync(dir,{withFileTypes:true})){
  const file=path.join(dir,ent.name);if(ent.isDirectory()){walkDir(file);continue}
  if(!file.endsWith('.vue')||ent.name==='LanguageSelect.vue')continue
  const {descriptor}=sfc(fs.readFileSync(file,'utf8'));if(!descriptor.template)continue
  const visit=n=>{
   if(n.type===2 && /[가-힣]/.test(n.content))missing.push(file+': '+n.content)
   for(const p of n.props||[])if(p.type===6&&p.value&&/[가-힣]/.test(p.value.content))missing.push(file+': '+p.value.content)
   for(const c of n.children||[])visit(c)
  };visit(html(descriptor.template.content))
 }};walkDir(fileURLToPath(new URL('../src', import.meta.url)));assert.deepEqual(missing,[])
})

import {test} from 'node:test'
import assert from 'node:assert/strict'
import {dataPaths} from '../runtime/paths.mjs'
test('Windows user paths preserve Korean and spaces without cwd dependency', () => {
 const p=dataPaths({LOCALAPPDATA:'D:\\사용자 공간\\AppData\\Local'}, 'win32')
 assert.equal(p.config,'D:\\사용자 공간\\AppData\\Local\\AidotVPN\\config')
 assert.equal(p.exports,'D:\\사용자 공간\\AppData\\Local\\AidotVPN\\exports')
})
test('Windows system data never uses installing user profile', () => {
 const p=dataPaths({AIDOTVPN_SCOPE:'system',ProgramData:'C:\\ProgramData',LOCALAPPDATA:'C:\\Users\\admin\\AppData\\Local'}, 'win32')
 assert.equal(p.data,'C:\\ProgramData\\AidotVPN')
})
test('Missing Windows profile fails instead of writing into installation folder', () => assert.throws(()=>dataPaths({},'win32'),/LOCALAPPDATA/))
test('relative override is rejected', () => assert.throws(()=>dataPaths({AIDOTVPN_DATA_DIR:'relative'},'linux'),/absolute/))
test('Linux system paths follow service filesystem layout',()=>{
 const p=dataPaths({AIDOTVPN_SCOPE:'system'},'linux')
 assert.equal(p.data,'/var/lib/aidotvpn');assert.equal(p.config,'/etc/aidotvpn')
})
test('Linux user respects XDG state directory',()=>assert.equal(dataPaths({XDG_STATE_HOME:'/custom/state'},'linux').data,'/custom/state/aidotvpn'))

import { ref, computed, watch } from 'vue'
import english from './en.json' with { type: 'json' }
const storageKey = 'aidotvpn.locale'
let stored
try { stored = localStorage.getItem(storageKey) } catch {}
export const locale = ref(['ko', 'en'].includes(stored) ? stored : (globalThis.navigator?.language?.startsWith('ko') ? 'ko' : 'en'))
export const localeTag = computed(() => locale.value === 'ko' ? 'ko-KR' : 'en-US')
export function setLocale(value) { if (['ko', 'en'].includes(value)) locale.value = value }
const normalize = s => s.replace(/\s+/g, ' ').trim()
const escape = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const patterns = Object.entries(english).filter(([k]) => /\{\d+\}/.test(k)).sort(([a],[b])=>b.length-a.length).map(([ko,en]) => ({ ko, en, regex: new RegExp('^'+ko.split(/(\{\d+\})/).map(s=>/^\{\d+\}$/.test(s)?'(.+?)':escape(s)).join('')+'$'), order:[...ko.matchAll(/\{(\d+)\}/g)].map(m=>Number(m[1])) }))
export function translate(value, parameters) {
  if (typeof value !== 'string') return value
  const key = normalize(value)
  const prefixed = key.match(/^(?:Error: |[0-9]{3}[: ]+)(.+)$/)
  if (prefixed && /[가-힣]/.test(prefixed[1])) return translate(prefixed[1], parameters)
  let message = locale.value === 'en' ? (english[key] || key) : ({'aidotvpn-admin':'관리자','aidotvpn-user':'사용자'}[key] || key)
  if (!parameters && locale.value === 'en' && !english[key] && /[가-힣]/.test(key)) {
    for (const p of patterns) { const m = p.regex.exec(key); if (m) { const values=[];p.order.forEach((slot,i)=>values[slot]=m[i+1]);return p.en.replace(/\{(\d+)\}/g,(_,i)=>values[Number(i)] ?? '') } }
    // Controller descriptions sometimes concatenate separately authored sentences.
    for (const [ko,en] of Object.entries(english).sort(([a],[b])=>b.length-a.length)) if (ko.length > 8 && !/\{\d+\}/.test(ko)) message=message.replaceAll(ko,en)
  }
  return parameters ? message.replace(/\{(\d+)\}/g, (_,i) => parameters[Number(i)] ?? '') : message
}
export function apiMessage(raw, status) {
  if (typeof raw === 'string' && english[normalize(raw)]) return normalize(raw)
  if (typeof raw === 'string' && /[가-힣]/.test(raw)) return raw
  const key = {
    invalid_console_port:'포트는 1부터 65535 사이의 정수여야 합니다.', invalid_bind_host:'수신 주소를 확인하세요.',
    invalid_public_url:'접속 주소의 프로토콜과 포트를 확인하세요.', certificate_paths_must_be_absolute:'인증서와 개인키는 서버의 절대 경로로 지정하세요.',
    certificate_paths_missing:'인증서와 개인키를 설정하거나 npm run https:cert를 실행하세요.',
    certificate_file_not_found:'인증서 또는 개인키 파일이 없습니다. 설정 경로를 확인하세요.',
    certificate_file_not_readable:'콘솔 실행 계정이 인증서와 개인키 파일을 읽을 수 있어야 합니다.',
    certificate_or_key_invalid:'인증서 또는 개인키를 읽을 수 없거나 서로 일치하지 않습니다.', certificate_hostname_mismatch:'인증서에 접속 주소의 호스트 이름이 없습니다.',
    certificate_expired_or_not_yet_valid:'인증서가 만료되었거나 아직 유효하지 않습니다.', settings_busy:'다른 설정을 적용 중입니다. 잠시 후 다시 시도하세요.',
    settings_managed_by_environment:'환경 변수로 관리 중입니다. console.env 또는 .env를 수정한 뒤 서버를 다시 시작하세요.',
    console_settings_apply_failed:'설정을 적용하지 못했습니다. 포트 사용 여부와 파일 권한을 확인하세요.',
    controller_unreachable:'컨트롤러에 연결할 수 없습니다. 서버 실행 상태를 확인하세요.', administrator_required:'비밀번호를 변경한 관리자 계정이 필요합니다.',
    authentication_required:'로그인이 필요합니다', same_origin_json_required:'이 콘솔 화면에서 설정을 다시 저장하세요.',
  }[raw]
  return key || `요청 실패 (HTTP ${status})`
}
watch(locale, value => {
  try { localStorage.setItem(storageKey, value) } catch {}
  if (globalThis.document) { document.documentElement.lang=value;document.title=value==='ko'?'AidotVPN 관리 콘솔':'AidotVPN Admin Console' }
}, {immediate:true})
if (globalThis.addEventListener) addEventListener('storage', event => { if(event.key===storageKey && ['ko','en'].includes(event.newValue))locale.value=event.newValue })

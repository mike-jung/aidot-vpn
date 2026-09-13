/**
 * 동작 코드 → 우리말.
 *
 * Shared, because 개요's 최근 기록 printed raw codes — policy.assign with
 * no name and no subject — while 감사 로그 three clicks away showed the
 * same event in Korean. One dictionary is the only way those two stay
 * in agreement.
 */
export const ACTIONS = {
  'admin.login': ['관리자 로그인', 'ok'],
  'admin.login_failed': ['관리자 로그인 실패', 'bad'],
  'admin.logout': ['관리자 로그아웃', 'muted'],
  'admin.password_changed': ['관리자 비밀번호 변경', 'warn'],
  'device.register': ['단말 등록', 'ok'],
  'device.revoke': ['단말 폐기', 'bad'],
  'device.rotate_key': ['단말 키 교체', 'warn'],
  'policy.create': ['정책 만들기', 'ok'],
  'policy.update': ['정책 수정', 'warn'],
  'policy.delete': ['정책 삭제', 'bad'],
  'policy.assign': ['정책을 단말에 적용', 'ok'],
  'policy.transport': ['접속 방식 변경', 'warn'],
  // The list is the whole set the server can write, checked against the
  // Go source rather than remembered: an action with no entry falls
  // back to its machine code, which is exactly the thing this table
  // exists to avoid, and a missing one is invisible until it happens.
  'policy.allowed_ip.add': ['갈 수 있는 주소 추가', 'ok'],
  'policy.allowed_ip.remove': ['갈 수 있는 주소 삭제', 'warn'],
  'policy.hostname.add': ['호스트 이름 추가', 'ok'],
  'policy.hostname.remove': ['호스트 이름 삭제', 'warn'],
  'policy.virtual_host.add': ['가상 주소 추가', 'ok'],
  'policy.virtual_host.remove': ['가상 주소 삭제', 'warn'],
  'policy.settings.update': ['정책 설정 변경', 'warn'],
  'device.app_filter.update': ['앱 필터 변경', 'warn'],
}

export const actionLabel = (a) => ACTIONS[a]?.[0] || a
export const actionTone = (a) => ({
  ok: 'text-success', warn: 'text-warning', bad: 'text-danger', muted: 'text-muted',
}[ACTIONS[a]?.[1] || 'muted'])

#!/usr/bin/env node
// AidotVpn client for Linux and Windows.
//
// ## Why this exists
//
// The Android app is the only client, and there is no Android runtime
// where this code is verified — so for weeks "does the app connect" has
// been answered by a user pressing a button on a phone. Three defects in
// a row were things that only that button could find.
//
// This client performs the same sequence as the Android app, against
// the same endpoints, and it can be run here. When the two disagree,
// one of them is wrong, and now there is something to compare against.
//
// It is also a real client. A Linux or Windows machine with WireGuard
// installed can enrol with it, write the config it produces, and bring
// the tunnel up with `wg-quick`.
//
// ## Steps, and where each one is in the Android app
//
//   enroll     EnrollmentRequestClient.request()     POST /enrollment-requests
//   (wait)     EnrollmentRequestClient.awaitDecision  GET  /enrollment-requests/{id}/status
//   register   RegistrationFlow.register()            POST /devices/attestation-challenge
//                                                     POST /devices/register
//   status     DeviceStateClient.fetch()              GET  /devices/{id}/state
//   probe      Reachability.probe()                   GET  <url>
//
// Keys are a real X25519 pair from node:crypto, so the config it writes
// is one WireGuard will accept.

import { generateKeyPairSync, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const STATE_DIR = process.env.AIDOT_STATE_DIR
  || path.join(os.homedir(), '.aidotvpn');
const STATE = path.join(STATE_DIR, 'device.json');

// ---------------------------------------------------------------------------
// State on disk. Same shape the Android app keeps in CoreStorage, so the
// two can be compared field for field.
function load() {
  try { return JSON.parse(fs.readFileSync(STATE, 'utf8')); }
  catch { return null; }
}
function save(state) {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.writeFileSync(STATE, JSON.stringify(state, null, 2), { mode: 0o600 });
}

// ---------------------------------------------------------------------------
// WireGuard keys. X25519 raw public key is 32 bytes; WireGuard wants both
// halves base64. node:crypto exports them as DER-wrapped, so the raw
// bytes are the last 32 of each.
function newKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const priv = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32);
  return { publicKey: pub.toString('base64'), privateKey: priv.toString('base64') };
}

// ---------------------------------------------------------------------------
async function http(method, url, { body, token, timeoutMs = 10_000 } = {}) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(url, {
      method,
      headers: {
        ...(body ? { 'Content-Type': 'application/json' } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: ctl.signal,
    });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON */ }
    return { status: r.status, json, text };
  } finally {
    clearTimeout(t);
  }
}

function fail(msg, detail) {
  console.error(`  ✗ ${msg}`);
  if (detail) console.error(`    ${String(detail).slice(0, 200)}`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
/**
 * Finish enrolment once a grant is in hand, whichever way it came:
 * an approved request, or an enrolment token an admin made in the
 * console. Everything from the attestation challenge on is identical,
 * so it lives here instead of twice.
 */
async function registerWithGrant(controller, grant, name, installId, keys) {
  // 3. Register — two calls, the challenge first. RegistrationFlow.kt:66
  //    tolerates 404/501 on the challenge; so does this.
  const ch = await http('POST', `${controller}/devices/attestation-challenge`,
    { body: {}, token: grant });
  if (![200, 404, 501].includes(ch.status)) fail(`challenge: HTTP ${ch.status}`, ch.text);

  const reg = await http('POST', `${controller}/devices/register`, {
    body: {
      install_id: installId, display_name: name, platform: os.platform(),
      // The machine, so 디바이스 can tell one laptop from another. A MAC
      // would be the obvious identifier and is useless on phones, so
      // both clients report the same kind of string instead.
      model: `${os.type()} ${os.release()} ${os.arch()}`,
      device_public_key: keys.publicKey,
    },
    token: grant,
  });
  if (reg.status !== 200 && reg.status !== 201) fail(`register: HTTP ${reg.status}`, reg.text);

  const a = reg.json.allocation;
  const state = {
    controller,
    deviceId: reg.json.device.id,
    installId,
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
    ipv4: a.ipv4_addr, ipv6: a.ipv6_addr,
    psk: a.psk,
    stateToken: a.state_token || "",
    allowedIps: a.allowed_ips || [],
    policyBound: !!a.policy_bound,
    routeScope: a.route_scope || 'policy',
    dnsServers: a.dns_servers || [],
    appFilterMode: a.app_filter_mode || 'off',
    appFilterPackages: a.app_filter_packages || [],
    // Present only when the policy says 감추기.
    controllerTunnelUrl: a.controller_tunnel_url || '',
    nodes: reg.json.nodes || [],
    registeredAt: new Date().toISOString(),
  };
  save(state);

  console.log(`  등록 완료.  기기 ${state.deviceId.slice(0, 8)}…  주소 ${state.ipv4}`);
  console.log(`  정책: ${state.policyBound ? state.allowedIps.join(', ') : '없음 — 연결이 거부됩니다'}`);
  if (state.controllerTunnelUrl) console.log(`  터널 안 컨트롤러: ${state.controllerTunnelUrl}`);
  console.log(`  저장: ${STATE}`);
}

// enroll <controller> <password> [name]
//
// Mirrors: EnrollmentRequestClient.request → awaitDecision →
//          RegistrationFlow.register
async function enroll(controller, password, name = os.hostname()) {
  if (!controller || !password) fail('usage: enroll <controller> <password> [name]');

  const keys = newKeyPair();
  // The API stores install IDs in VARCHAR(36); hostnames can exceed it.
  const installId = randomUUID();

  // 1. Request. The six-digit code is what the admin compares.
  const req = await http('POST', `${controller}/enrollment-requests`, {
    body: {
      password, install_id: installId, display_name: name,
      device_public_key: keys.publicKey,
    },
  });
  if (req.status !== 201 && req.status !== 200) fail(`enrollment request: HTTP ${req.status}`, req.text);
  const { id, verification_code: code } = req.json;
  console.log(`  요청 보냄. 관리자에게 이 숫자를 보여주세요:  ${code}`);
  console.log('  승인을 기다리는 중…');

  // 2. Wait. Long-poll, exactly as the app does.
  let grant = null;
  for (let i = 0; i < 40 && !grant; i++) {
    const st = await http('GET', `${controller}/enrollment-requests/${id}/status?wait=30`,
      { timeoutMs: 45_000 });
    if (st.json?.status === 'rejected') fail('관리자가 거절했습니다');
    if (st.json?.enrollment_token) grant = st.json.enrollment_token;
  }
  if (!grant) fail('승인을 기다리다 시간이 지났습니다 (10분)');
  console.log('  승인됨. 등록하는 중…');

  await registerWithGrant(controller, grant, name, installId, keys);
}

// ---------------------------------------------------------------------------
// status — DeviceStateClient.fetch
//
// Uses the tunnel-side address when one was given and --tunnel-up is
// passed, the bootstrap address otherwise. Same rule as
// CoreStorage.controllerUrlFor.
async function status({ tunnelUp = false } = {}) {
  const s = load();
  if (!s) fail('등록된 기기가 없습니다. 먼저 enroll 하세요.');
  const base = tunnelUp && s.controllerTunnelUrl ? s.controllerTunnelUrl : s.controller;
  if (!s.stateToken) fail('상태 인증 정보가 없습니다. 클라이언트 업데이트 후 다시 enroll 하세요.');
  const r = await http('GET', `${base}/devices/${s.deviceId}/state`, { token: s.stateToken });
  if (r.status !== 200) fail(`state: HTTP ${r.status}`, r.text);
  const d = r.json;
  console.log(`  물어본 곳: ${base}`);
  console.log(`  상태: ${d.status}   정책: ${d.policy_bound ? '있음' : '없음'}`);
  console.log(`  갈 수 있는 곳: ${(d.allowed_ips || []).join(', ') || '(없음)'}`);
  // Keep the local copy current, as the app's refresh does.
  s.allowedIps = d.allowed_ips || [];
  s.policyBound = !!d.policy_bound;
  s.routeScope = d.route_scope || s.routeScope;
  s.status = d.status;
  s.dnsServers = d.dns_servers ?? s.dnsServers;
  s.appFilterMode = d.app_filter_mode ?? s.appFilterMode;
  s.appFilterPackages = d.app_filter_packages ?? s.appFilterPackages;
  if (d.nodes?.length) s.nodes = d.nodes;
  save(s);
  return d;
}

// ---------------------------------------------------------------------------
// wg-config [out] — a real wg-quick file from the allocation.
//
// Same decisions TunnelManager makes when it builds the Config:
//   - address /32
//   - AllowedIPs = policy list, or 0.0.0.0/0 for route_scope=full
//   - PersistentKeepalive 25
//   - the controller's own host excluded from AllowedIPs (1.6.9)
function wgConfig(out) {
  const s = load();
  if (!s) fail('등록된 기기가 없습니다.');
  if (!s.policyBound || s.status === 'revoked') fail('유효한 정책이 없거나 폐기된 단말입니다. status로 갱신하세요.');
  if (s.appFilterMode && s.appFilterMode !== 'off') fail('wg-quick은 앱별 VPN 정책을 지원하지 않습니다. 전체 단말용 정책을 지정하세요.');
  const node = s.nodes[0];
  if (!node) fail('컨트롤러가 노드를 알려주지 않았습니다.');

  // Endpoint selection, in the order TunnelManager.kt:700 uses:
  // a direct WireGuard endpoint first, the relay if that is all there
  // is, then whatever comes first.
  //
  // My first draft read node.endpoint_host, which does not exist —
  // the field is endpoints[].public_host. The wg-config came out as
  // "Endpoint = undefined:undefined", which is exactly the kind of
  // disagreement this client is for: the Android app reads the right
  // field, so the client was wrong, and now they match.
  const ep = node.endpoints?.find((e) => e.mode === 'wg')
    || node.endpoints?.find((e) => e.mode === 'wss_relay')
    || node.endpoints?.[0];
  if (!ep) fail('노드에 접속 지점이 없습니다.');

  if (ep.mode !== 'wg') fail('wg-quick은 WSS 릴레이를 직접 지원하지 않습니다. UDP 접속 지점이 필요합니다.');

  const ctlHost = (() => { try { return new URL(s.controller).hostname; } catch { return ''; } })();
  const allowed = s.routeScope === 'full'
    ? ['0.0.0.0/0', '::/0']
    : s.allowedIps.filter((c) => c.split('/')[0] !== ctlHost);

  if (!allowed.length) fail('허용 CIDR이 없어 설정을 생성할 수 없습니다.');
  const endpointHost = ep.public_host.includes(':') && !ep.public_host.startsWith('[') ? `[${ep.public_host}]` : ep.public_host;
  const lines = [
    '[Interface]',
    `PrivateKey = ${s.privateKey}`,
    `Address = ${s.ipv4}/32${s.ipv6 ? `, ${s.ipv6}/128` : ''}`,
    ...(s.dnsServers.length ? [`DNS = ${s.dnsServers.join(', ')}`] : []),
    '',
    '[Peer]',
    `PublicKey = ${node.public_key}`,
    ...(s.psk ? [`PresharedKey = ${s.psk}`] : []),
    `Endpoint = ${endpointHost}:${ep.public_port}`,
    `AllowedIPs = ${allowed.join(', ') || '(정책 없음 — 연결 거부)'}`,
    'PersistentKeepalive = 25',
    '',
  ];
  const text = lines.join('\n');
  if (out) {
    fs.writeFileSync(out, text, { mode: 0o600 });
    console.log(`  ${out} 에 썼습니다.  sudo wg-quick up ${path.basename(out, '.conf')}`);
  } else {
    process.stdout.write(text);
  }
}

// ---------------------------------------------------------------------------
// probe <url> — Reachability.probe, same three outcomes.
async function probe(url) {
  if (!url) fail('usage: probe <url>');
  const t0 = Date.now();
  try {
    const r = await http('GET', url, { timeoutMs: 4_000 });
    const ms = Date.now() - t0;
    // Any HTTP answer is proof the packet arrived and came back.
    console.log(`  연결됨 · ${ms}ms  (서버가 HTTP ${r.status} 로 응답)`);
    return 'REACHED';
  } catch (e) {
    const ms = Date.now() - t0;
    if (e.name === 'AbortError') { console.log(`  응답 없음 · ${ms}ms`); return 'TIMEOUT'; }
    console.log(`  거부됨 · ${e.cause?.code || e.message}`);
    return 'REFUSED';
  }
}

// ---------------------------------------------------------------------------
const [cmd, ...args] = process.argv.slice(2);
const flags = new Set(args.filter((a) => a.startsWith('--')));
const pos = args.filter((a) => !a.startsWith('--'));

switch (cmd) {
  case 'enroll':       await enroll(pos[0], pos[1], pos[2]); break;
  case 'status':    await status({ tunnelUp: flags.has('--tunnel-up') }); break;
  case 'wg-config': wgConfig(pos[0]); break;
  case 'probe':     await probe(pos[0]); break;
  case 'show': {
    const state = load();
    if (state && !flags.has('--secrets')) {
      for (const key of ['privateKey', 'psk', 'stateToken']) if (state[key]) state[key] = '[redacted]';
    }
    console.log(JSON.stringify(state, null, 2));
    break;
  }
  default:
    console.log(`AidotVpn client

  enroll <controller> <password> [name]        등록 요청 → 승인 대기 → 등록
  status [--tunnel-up]                    컨트롤러에 내 상태 물어보기
  wg-config [out.conf]                    wg-quick 용 설정 파일 만들기
  probe <url>                             도달성 시험
  show [--secrets]                        저장된 기기 정보 (기본: 비밀값 숨김)`);
}

#!/usr/bin/env node
/**
 * AidotVpn — 노트북용 화면.
 *
 * 폰에는 앱이 있고 노트북에는 명령줄뿐이었습니다. 간호사에게
 * `node aidot-client.mjs enroll …` 을 시킬 수는 없습니다. 이 프로그램은
 * 브라우저 화면 하나를 띄워, 폰 앱과 똑같은 네 단계를 보여줍니다:
 *
 *   등록 요청 → 관리자 승인 → 정책 적용 → 연결
 *
 * 실제 작업은 aidot-client.mjs 를 그대로 부릅니다. 로직이 두 벌이 되면
 * 한쪽만 고쳐지는 날이 오고, 이 프로젝트에서 그런 일이 이미 여러 번
 * 있었습니다. CLI 검증이 곧 이 화면의 검증입니다.
 *
 *   node aidot-gui.mjs            # 화면을 띄웁니다 (기본 127.0.0.1:7690)
 *   node aidot-gui.mjs --port 8000
 *
 * 127.0.0.1 에만 묶습니다. 이 컴퓨터를 쓰는 사람만 볼 수 있고, 같은
 * 사무실의 다른 컴퓨터에서는 열리지 않습니다.
 */
import http from 'node:http';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, 'aidot-client.mjs');
const STATE_DIR = process.env.AIDOT_STATE_DIR
  || path.join(os.homedir(), '.aidotvpn');
const args = process.argv.slice(2);
const PORT = Number(args[args.indexOf('--port') + 1]) || 7690;

/** Run the CLI and collect its output. Never throws; the caller reads ok. */
function cli(cmdArgs, timeoutMs = 60_000) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [CLI, ...cmdArgs], {
      env: { ...process.env, AIDOT_STATE_DIR: STATE_DIR },
    });
    let out = '';
    let err = '';
    const timer = setTimeout(() => { p.kill(); }, timeoutMs);
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    p.on('close', (code) => {
      clearTimeout(timer);
      resolve({ ok: code === 0, code, out: out.trim(), err: err.trim() });
    });
  });
}

function device() {
  try {
    return JSON.parse(fs.readFileSync(path.join(STATE_DIR, 'device.json'), 'utf8'));
  } catch { return null; }
}

/** wg-quick is not on Windows; there the config is opened in the app. */
const isWindows = process.platform === 'win32';

function json(res, code, body) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  try { return JSON.parse(Buffer.concat(chunks).toString() || '{}'); } catch { return {}; }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === 'GET' && url.pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(PAGE);
    return;
  }

  // 지금 어디까지 왔나: 등록 전 / 등록됨 / 연결됨
  if (req.method === 'GET' && url.pathname === '/api/state') {
    const d = device();
    if (!d) { json(res, 200, { stage: 'new', platform: process.platform }); return; }
    const st = await cli(['status'], 15_000);
    const connected = /연결됨|latest handshake/.test(st.out);
    json(res, 200, {
      stage: connected ? 'connected' : 'registered',
      platform: process.platform,
      name: d.displayName || os.hostname(),
      address: d.ipv4,
      allowed: d.allowedIps || [],
      controller: d.controller,
      detail: st.out,
    });
    return;
  }

  // 등록 요청 → 승인 대기 → 등록. CLI 의 enroll 이 전부 합니다.
  if (req.method === 'POST' && url.pathname === '/api/enroll') {
    const b = await readBody(req);
    if (!b.controller || !b.password) {
      json(res, 400, { error: '서버 주소와 기관 비밀번호가 필요합니다' });
      return;
    }
    const r = await cli(['enroll', b.controller, b.password, b.name || os.hostname()], 120_000);
    if (!r.ok) { json(res, 400, { error: (r.err || r.out || '등록 실패').split('\n').pop() }); return; }
    json(res, 200, { ok: true, detail: r.out });
    return;
  }

  // 확인번호. enroll 이 화면에 찍은 여섯 자리를 그대로 읽습니다.
  if (req.method === 'GET' && url.pathname === '/api/code') {
    const d = device();
    json(res, 200, { code: d?.pendingCode || null });
    return;
  }

  // 터널 올리기 / 내리기
  if (req.method === 'POST' && (url.pathname === '/api/connect' || url.pathname === '/api/disconnect')) {
    const conf = path.join(STATE_DIR, 'aidot0.conf');
    if (url.pathname === '/api/connect') {
      const g = await cli(['wg-config', conf], 20_000);
      if (!g.ok) { json(res, 400, { error: '설정 파일을 만들지 못했습니다' }); return; }
      if (isWindows) {
        // WireGuard for Windows 가 터널을 관리합니다. 파일 위치를 알려주고
        // 사용자가 [터널 가져오기] 로 불러오게 합니다 — 관리자 권한을
        // 이 프로그램이 요구하지 않아도 되는 방법입니다.
        json(res, 200, { manual: true, conf });
        return;
      }
      const up = await new Promise((resolve) => {
        const p = spawn('sudo', ['wg-quick', 'up', conf]);
        let e = ''; p.stderr.on('data', (d) => { e += d; });
        p.on('close', (c) => resolve({ ok: c === 0, err: e.trim() }));
      });
      if (!up.ok) { json(res, 400, { error: `터널을 올리지 못했습니다: ${up.err.split('\n').pop()}` }); return; }
      json(res, 200, { ok: true });
      return;
    }
    await new Promise((resolve) => {
      spawn('sudo', ['wg-quick', 'down', conf]).on('close', resolve);
    });
    json(res, 200, { ok: true });
    return;
  }

  // 어디에 갈 수 있는지 시험 — 폰 앱의 [세 곳 모두 확인하기] 와 같은 것
  if (req.method === 'POST' && url.pathname === '/api/probe') {
    const b = await readBody(req);
    const r = await cli(['probe', b.url || ''], 20_000);
    json(res, 200, { detail: r.out || r.err });
    return;
  }

  res.writeHead(404); res.end('not found');
});

const PAGE = `<!doctype html>
<html lang="ko"><head><meta charset="utf-8" />
<title>AidotVpn</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
    font-family:'Malgun Gothic','Apple SD Gothic Neo',system-ui,sans-serif;
    background:radial-gradient(900px 500px at 15% -10%,rgba(34,211,238,.18),transparent 60%),
               radial-gradient(700px 450px at 100% 10%,rgba(114,57,234,.14),transparent 55%),
               linear-gradient(180deg,#0a0f1c,#0b1120); color:#e6ebf5; }
  .card { width:min(460px,calc(100vw - 2rem)); padding:2rem; border-radius:22px;
    background:rgba(17,24,39,.6); border:1px solid rgba(255,255,255,.08);
    box-shadow:0 30px 60px rgba(0,0,0,.45); backdrop-filter:blur(16px); }
  h1 { margin:0 0 .2rem; font-size:1.5rem; letter-spacing:-.02em; }
  .sub { color:#9aa7c2; font-size:.88rem; margin:0 0 1.4rem; }
  .steps { display:flex; gap:.4rem; margin-bottom:1.4rem; }
  .step { flex:1; height:4px; border-radius:2px; background:#1f2a44; }
  .step.on { background:#22d3ee; }
  .step-labels { display:flex; gap:.4rem; margin:-1.1rem 0 1.2rem; }
  .step-labels span { flex:1; font-size:.68rem; color:#6b7896; text-align:center; }
  label { display:block; font-size:.78rem; font-weight:600; color:#9aa7c2; margin:.7rem 0 .3rem; }
  input { width:100%; box-sizing:border-box; padding:.7rem .9rem; border-radius:12px;
    background:#0f172a; border:1px solid rgba(255,255,255,.1); color:#e6ebf5; font:inherit; }
  input:focus { outline:none; border-color:#22d3ee; box-shadow:0 0 0 3px rgba(34,211,238,.2); }
  button { width:100%; margin-top:1.2rem; padding:.85rem; border:0; border-radius:14px;
    font:inherit; font-weight:700; color:#061018;
    background:linear-gradient(135deg,#22d3ee,#1b84ff); cursor:pointer; }
  button:disabled { opacity:.55; cursor:default; }
  button.ghost { background:transparent; border:1px solid rgba(255,255,255,.15); color:#e6ebf5; }
  .code { font-size:2.4rem; letter-spacing:.35em; text-align:center; margin:1.2rem 0 .4rem;
    font-family:'D2Coding',Consolas,monospace; color:#22d3ee; }
  .note { font-size:.8rem; color:#9aa7c2; line-height:1.6; }
  .err { color:#fb7185; font-size:.84rem; margin-top:.8rem; }
  .row { display:flex; align-items:center; gap:.5rem; }
  .dot { width:10px; height:10px; border-radius:50%; background:#34d399; box-shadow:0 0 0 4px rgba(52,211,153,.2); }
  code { background:#0f172a; padding:.1rem .35rem; border-radius:6px; font-size:.82rem; }
  ul { margin:.6rem 0 0; padding-left:1.1rem; color:#9aa7c2; font-size:.82rem; line-height:1.8; }
</style></head><body><div class="card" id="app">불러오는 중…</div>
<script>
const $ = (h) => { document.getElementById('app').innerHTML = h; };
const api = async (m, p, b) => (await fetch(p, { method:m,
  headers:b?{'Content-Type':'application/json'}:{}, body:b?JSON.stringify(b):undefined })).json();
const bar = (n) => '<div class="steps">' + [1,2,3,4].map(i =>
  '<div class="step' + (i<=n?' on':'') + '"></div>').join('') + '</div>' +
  '<div class="step-labels"><span>등록 요청</span><span>관리자 승인</span><span>정책 적용</span><span>연결</span></div>';

async function render() {
  const s = await api('GET','/api/state');
  if (s.stage === 'new') {
    $(bar(0) + '<h1>AidotVpn</h1><p class="sub">기관 밖에서 안전한 터널을 통해 데이터를 주고 받습니다.</p>' +
      '<label>서버 주소</label><input id=c placeholder="http://192.168.0.11:10030">' +
      '<label>기관 비밀번호</label><input id=p type=password>' +
      '<label>이 컴퓨터 이름</label><input id=n placeholder="간호사실 노트북">' +
      '<button id=go>등록 요청</button><div class=err id=e></div>');
    document.getElementById('go').onclick = async () => {
      const btn = document.getElementById('go');
      btn.disabled = true; btn.textContent = '관리자 승인을 기다리는 중…';
      const r = await api('POST','/api/enroll',{ controller:document.getElementById('c').value,
        password:document.getElementById('p').value, name:document.getElementById('n').value });
      if (r.error) { document.getElementById('e').textContent = r.error;
        btn.disabled = false; btn.textContent = '등록 요청'; return; }
      render();
    };
    return;
  }
  if (s.stage === 'registered') {
    $(bar(3) + '<h1>등록됨</h1><p class="sub">' + s.name + ' · ' + s.address + '</p>' +
      '<p class="note">이제 [연결] 을 누르면 터널이 열립니다. 아래 주소들만 병원 안으로 갑니다:</p>' +
      '<ul>' + (s.allowed.length ? s.allowed.map(a=>'<li><code>'+a+'</code></li>').join('') :
        '<li>아직 정책이 없습니다 — 관리자에게 문의하세요</li>') + '</ul>' +
      '<button id=go>연결</button><div class=err id=e></div>');
    document.getElementById('go').onclick = async () => {
      const btn = document.getElementById('go'); btn.disabled = true; btn.textContent = '여는 중…';
      const r = await api('POST','/api/connect');
      if (r.manual) { document.getElementById('e').innerHTML =
        'WireGuard 앱에서 [터널 가져오기] 로 이 파일을 여세요:<br><code>' + r.conf + '</code>';
        btn.disabled = false; btn.textContent = '연결'; return; }
      if (r.error) { document.getElementById('e').textContent = r.error;
        btn.disabled = false; btn.textContent = '연결'; return; }
      render();
    };
    return;
  }
  $(bar(4) + '<h1><span class=row><span class=dot></span>연결됨</span></h1>' +
    '<p class="sub">' + s.name + ' · ' + s.address + '</p>' +
    '<p class="note">병원 안 주소는 터널로, 그 밖은 평소 인터넷으로 갑니다.</p>' +
    '<ul>' + s.allowed.map(a=>'<li><code>'+a+'</code> — 터널로</li>').join('') +
    '<li>그 밖의 모든 곳 — 평소 인터넷으로</li></ul>' +
    '<button class=ghost id=off>연결 끊기</button>');
  document.getElementById('off').onclick = async () => { await api('POST','/api/disconnect'); render(); };
}
render(); setInterval(render, 10000);
</script></body></html>`;

server.listen(PORT, '127.0.0.1', () => {
  console.log(`  AidotVpn 화면:  http://127.0.0.1:${PORT}`);
  console.log('  브라우저에서 위 주소를 여세요. 끄려면 Ctrl+C.');
});

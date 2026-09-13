#!/usr/bin/env node
/**
 * `npm start` — bring the whole AidotVpn stack up with one command.
 *
 * The problem this solves: starting the stack by hand meant remembering
 * six steps in the right order, and skipping one produced a failure that
 * looked like a different problem. Forgetting `npm install` after a
 * dependency change surfaced as a Vite error about a missing module;
 * forgetting `migrate up` surfaced as a controller that started and then
 * 500'd on the first request.
 *
 * So every step here is *conditional on a fingerprint*. Nothing is
 * rebuilt because "it might have changed" — each stage hashes its own
 * inputs and skips when they match the last successful run. A warm start
 * does almost nothing and takes a second; a cold one does everything.
 *
 * Fingerprints live in .aidot-cache/. Deleting that directory forces a
 * full rebuild, which is what --clean does.
 *
 * Stages, in dependency order:
 *
 *   1. tools      are node/go/docker present and new enough
 *   2. env        is .env there, and does .env.example have keys it lacks
 *   3. deps       npm install where package-lock.json changed
 *   4. docker     compose up where the compose file or a Dockerfile changed
 *   5. migrate    schema up where migrations/ changed
 *   6. build      go build where server sources changed
 *   7. run        start controller + console, wait for health
 */

import { spawn, spawnSync } from 'node:child_process';
import net from 'node:net';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CACHE = path.join(ROOT, '.aidot-cache');
const PIDS = path.join(CACHE, 'pids.json');

const args = new Set(process.argv.slice(2));
const FLAGS = {
  clean: args.has('--clean'),
  noDocker: args.has('--no-docker'),
  stop: args.has('--stop'),
  status: args.has('--status'),
  ports: args.has('--ports'),
  logs: args.has('--logs'),
  dockerLogs: args.has('--docker-logs'),
};

// Ports, all shifted +1020 from their historical values so a second
// checkout or a stray Keycloak cannot collide. Kept here as the single
// place a reader can see the whole map.
// Ports come from .env, with these as defaults.
//
// They were fixed here while .env carried the same numbers, so editing
// .env changed the containers and not the checks that watch them: a
// user moving MariaDB to 4337 would see npm start wait on 4336 and give
// up. One source now. `npm run ports` prints the resolved map; the
// console shows the same under 설정.
//
// Read before anything else runs so every stage sees the same values.
const ENV0 = (() => {
  const out = {};
  try {
    for (const line of fs.readFileSync(path.join(ROOT, '.env'), 'utf8').split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
      if (m && !line.trim().startsWith('#')) out[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  } catch { /* first run — .env is created later from .env.example */ }
  return out;
})();
const envPort = (key, dflt) => {
  const v = process.env[key] || ENV0[key];
  const n = v ? parseInt(String(v).replace(/^.*:/, ''), 10) : NaN;
  return Number.isInteger(n) && n > 0 && n < 65536 ? n : dflt;
};
const savedConsole = (() => { try { return JSON.parse(fs.readFileSync(path.join(process.env.AIDOTVPN_DATA_DIR || ENV0.AIDOTVPN_DATA_DIR || path.join(ROOT, '.local/console'), 'console-settings.json'), 'utf8')) } catch { return {} } })();
const PORTS = {
  controllerHttp: envPort('CONTROLLER_HTTP_LISTEN', 10030),
  controllerGrpc: envPort('CONTROLLER_GRPC_LISTEN', 10021),
  mariadb: envPort('MARIADB_HOST_PORT', 4336),
  console: envPort('CONSOLE_PORT', savedConsole.port || 6193),
  gatewayHealth: envPort('GATEWAY_HEALTH_PORT', 10140),
  wireguard: envPort('WG_DATAPLANE_PORT', 52840),
};

// ---------------------------------------------------------------- output

const C = {
  reset: '\x1b[0m', dim: '\x1b[2m', bold: '\x1b[1m',
  green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m', cyan: '\x1b[36m',
};
let stepNo = 0;
const step = (msg) => console.log(`\n${C.bold}${C.cyan}[${++stepNo}] ${msg}${C.reset}`);
const ok = (msg) => console.log(`    ${C.green}✓${C.reset} ${msg}`);
const skip = (msg) => console.log(`    ${C.dim}·${C.reset} ${C.dim}${msg}${C.reset}`);
const warn = (msg) => console.log(`    ${C.yellow}!${C.reset} ${msg}`);
const fail = (msg) => console.log(`    ${C.red}✗${C.reset} ${msg}`);

function die(msg, hint) {
  fail(msg);
  if (hint) console.log(`\n      ${C.yellow}해결 방법:${C.reset} ${hint}`);
  process.exit(1);
}

// ---------------------------------------------------------- fingerprints

fs.mkdirSync(CACHE, { recursive: true });

/** Hash a set of files. Missing files contribute their absence, so
 *  deleting an input counts as a change. */
function fingerprint(files) {
  const h = createHash('sha256');
  for (const f of files.sort()) {
    h.update(f);
    try {
      h.update(fs.readFileSync(f));
    } catch {
      h.update('<missing>');
    }
  }
  return h.digest('hex').slice(0, 16);
}

function walk(dir, exts, out = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (e.isDirectory()) {
      if (['node_modules', '.git', 'dist', 'build', '.gradle', '.aidot-cache'].includes(e.name)) continue;
      walk(path.join(dir, e.name), exts, out);
    } else if (exts.some((x) => e.name.endsWith(x))) {
      out.push(path.join(dir, e.name));
    }
  }
  return out;
}

const stampPath = (name) => path.join(CACHE, `${name}.stamp`);
const lastStamp = (name) => {
  try { return fs.readFileSync(stampPath(name), 'utf8').trim(); } catch { return null; }
};
const writeStamp = (name, v) => fs.writeFileSync(stampPath(name), v);

/**
 * Run `work` only when `current` differs from the recorded stamp.
 *
 * The stamp is written *after* work succeeds, never before. A build that
 * fails halfway must not be remembered as done — that would make the
 * next run skip it and fail somewhere further along, which is the
 * hardest kind of problem to trace back.
 */
async function ifChanged(name, current, label, work, force = false) {
  if (!FLAGS.clean && !force && lastStamp(name) === current) {
    skip(`${label} — 변경 없음`);
    return false;
  }
  await work();
  // Record the *fingerprint*, never the reason we forced a run.
  //
  // An earlier version appended markers like "-nobin" to `current` when
  // an output was missing, and stored that. The next run found the
  // output present, computed the plain fingerprint, saw a mismatch, and
  // rebuilt — every warm start redid work it had just done. Separating
  // "why we ran" from "what we ran against" fixes it.
  writeStamp(name, current);
  ok(label);
  return true;
}

// ------------------------------------------------------------- exec helpers

const IS_WIN = process.platform === 'win32';

/**
 * Commands that are `.cmd`/`.ps1` shims on Windows rather than real
 * executables. `spawnSync` cannot launch those without a shell — it fails
 * with ENOENT, which reads as "the tool isn't installed" when it plainly
 * is.
 */
const NEEDS_SHELL = new Set(['npm', 'npx', 'docker', 'yarn', 'pnpm']);

/**
 * Should this command go through cmd.exe?
 *
 * Only on Windows, and only for the shims that require it. Enabling the
 * shell everywhere looked simpler and was wrong: with `shell: true` the
 * arguments are re-parsed by cmd.exe, so a path containing a space —
 * `D:\Users\Hong Gildong\project` — is split into two arguments.
 * `go build -o <that path>` then writes to the wrong place or fails with
 * a message about an unexpected argument.
 *
 * `go`, `git` and the built binaries are real executables, so they are
 * launched directly and their arguments reach them intact.
 */
const useShell = (cmd) => IS_WIN && NEEDS_SHELL.has(cmd);

/**
 * Quote one argument for cmd.exe.
 *
 * Node 22 deprecates passing an args array together with `shell: true`
 * (DEP0190) and says why: the arguments are concatenated, not escaped. It
 * is describing a real hazard, not a stylistic one — an argument
 * containing a space is split into two, which is the same class of bug
 * that removing `go` from NEEDS_SHELL fixed in 0.26.3.
 *
 * Silencing the warning would leave the hazard. Doing the quoting here
 * removes it: everything that needs a shell now goes through this, so
 * `npm install --prefix "C:\Users\Hong Gildong\app"` survives intact.
 *
 * Rules, per the Windows command-line parser: wrap in double quotes when
 * the value contains anything the shell would interpret; double any
 * backslashes that immediately precede a quote or the closing quote;
 * escape embedded quotes.
 */
function winQuote(arg) {
  const s = String(arg);
  if (s === '') return '""';
  if (!/[\s"&|<>^%()!,;=]/.test(s)) return s;
  const escaped = s
    .replace(/(\\*)"/g, '$1$1\\"')   // backslashes before a quote, then the quote
    .replace(/(\\*)$/, '$1$1');       // backslashes before the closing quote
  return `"${escaped}"`;
}

/** Build a single cmd.exe command line from a command and its arguments. */
const winCommandLine = (cmd, args) => [cmd, ...args].map(winQuote).join(' ');

/** Block for ms. Atomics.wait on a shared buffer: no busy loop, no async. */
function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function sh(cmd, cmdArgs, opts = {}) {
  // Every `go <verb>` gets -modfile when GO_MODFILE is set — build, run,
  // mod download, all of them. Done here rather than at each call so a
  // new call cannot forget it; 1.8.2 covered `go build` and missed `go
  // run ./cmd/migrate`, which then failed in the sandbox with "module
  // lookup disabled".
  if (cmd === 'go' && process.env.GO_MODFILE && !cmdArgs.includes('-modfile')) {
    const [verb, ...rest] = cmdArgs;
    cmdArgs = [verb, '-modfile', process.env.GO_MODFILE, ...rest];
  }
  // With a shell, pass ONE quoted string and no args array. That is what
  // avoids DEP0190, and — more to the point — it is what makes the
  // quoting ours rather than absent.
  const viaShell = useShell(cmd);
  const spawnCmd = viaShell ? winCommandLine(cmd, cmdArgs) : cmd;
  const spawnArgs = viaShell ? [] : cmdArgs;

  const r = spawnSync(spawnCmd, spawnArgs, {
    shell: viaShell,
    cwd: opts.cwd || ROOT,
    // 'inherit' streams straight to the terminal but leaves us nothing to
    // inspect afterwards. Docker's failures are the ones worth diagnosing,
    // so callers can ask for both: shown live AND captured.
    stdio: opts.quiet ? 'pipe' : (opts.capture ? 'pipe' : 'inherit'),
    encoding: 'utf8',
    env: { ...process.env, ...(opts.env || {}) },
  });
  // A missing binary is a failure like any other when the caller said
  // allowFail.
  //
  // r.error is set when the command cannot be spawned at all — ENOENT
  // for a tool that is not installed. Throwing regardless meant
  // `npm run status` died with a Node stack trace on a machine without
  // docker. allowFail should mean allow *this* to fail too.
  if (r.error) {
    if (!opts.allowFail) throw r.error;
    return { status: 127, stdout: '', stderr: String(r.error.message || r.error) };
  }
  if (opts.capture) {
    // Echo what we captured so the user still sees it in real order.
    if (r.stdout) process.stdout.write(r.stdout);
    if (r.stderr) process.stderr.write(r.stderr);
  }
  if (r.status !== 0 && !opts.allowFail) {
    if (opts.quiet && r.stderr) console.log(r.stderr.trim());
    const err = new Error(`${cmd} ${cmdArgs.join(' ')} → exit ${r.status}`);
    err.output = `${r.stdout || ''}\n${r.stderr || ''}`;
    throw err;
  }
  return r;
}

/**
 * Is `cmd` on PATH?
 *
 * Previously this ran `sh -c "command -v <cmd>"`, which does not exist on
 * Windows — so on PowerShell every probe failed and the script reported
 * that node was missing **while running inside node**. That is the bug
 * this function is written to make impossible.
 *
 * Two changes: the interpreter we are already running in is never probed
 * (process.execPath is proof enough), and the lookup uses each platform's
 * own resolver instead of a POSIX shell builtin.
 */
function has(cmd) {
  if (cmd === 'node') return true;

  // `where` is a real executable on Windows, so it needs no shell.
  // `command -v` is a POSIX shell builtin and has no other form — there
  // it is passed as one string, with no args array, for the same reason
  // as everything else here.
  const probe = IS_WIN
    ? spawnSync('where', [cmd], { stdio: 'pipe' })
    : spawnSync(`command -v ${JSON.stringify(cmd)}`, [], { stdio: 'pipe', shell: true });
  if (probe.status === 0) return true;

  // `where` and `command -v` both miss a tool that is only reachable
  // through a shim, so fall back to asking the tool itself. A non-zero
  // exit still counts as present — `docker --version` succeeds even when
  // the daemon is down, which is a different check entirely.
  const viaShell = useShell(cmd);
  const direct = viaShell
    ? spawnSync(winCommandLine(cmd, ['--version']), [], { stdio: 'pipe', shell: true })
    : spawnSync(cmd, ['--version'], { stdio: 'pipe' });
  return !direct.error;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Can something accept a TCP connection on this port? */
function portOpen(port, timeoutMs = 1000) {
  return new Promise((resolve) => {
    const sock = net.connect({ host: '127.0.0.1', port });
    const done = (v) => { sock.destroy(); resolve(v); };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => done(true));
    sock.once('timeout', () => done(false));
    sock.once('error', () => done(false));
  });
}

/**
 * Wait for a port to accept connections.
 *
 * Uses a real TCP connect rather than parsing `ss`/`netstat` output. That
 * removes the last platform dependency here, and it is the better test
 * anyway: a socket in LISTEN state that refuses connections would have
 * passed the old check.
 */
async function waitForPort(port, label, timeoutMs = 60000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await portOpen(port)) return true;
    await sleep(500);
  }
  warn(`${label} (:${port}) 가 ${timeoutMs / 1000}초 안에 열리지 않았습니다`);
  return false;
}

// ------------------------------------------------------------- stop/status

/**
 * Is this pid a live process?
 *
 * `process.kill(pid, 0)` sends no signal and only checks reachability. It
 * works on Windows too, where Node maps it onto an OpenProcess call.
 *
 * EPERM means the process exists but belongs to someone else — alive for
 * our purposes, since the question is whether the pid is in use.
 */
function isAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === 'EPERM';
  }
}

/** Wait for a pid to disappear, polling. Returns whether it did. */
async function waitForExit(pid, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!isAlive(pid)) return true;
    await sleep(100);
  }
  return !isAlive(pid);
}

function readPids() {
  try { return JSON.parse(fs.readFileSync(PIDS, 'utf8')); } catch { return {}; }
}

async function stopAll() {
  step('중지');
  const pids = readPids();
  for (const [name, pid] of Object.entries(pids)) {
    // Distinguish "was not running" from "could not be stopped".
    //
    // The previous version collapsed both into "이미 종료됨", which is how
    // a real defect stayed invisible: the services were dying when
    // `npm start` exited, and stop reported that as the normal case.
    if (!isAlive(pid)) {
      skip(`${name} (pid ${pid}) — 실행 중이 아니었습니다`);
      continue;
    }
    if (IS_WIN) {
      // With a shell the recorded pid is the cmd.exe shim, not the
      // service, so /T is required to reach the tree beneath it.
      // taskkill is a real executable and needs no shell of its own.
      const r = spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'pipe' });
      if (r.status === 0) ok(`${name} (pid ${pid}) 종료`);
      else fail(`${name} (pid ${pid}) 종료 실패: ${(r.stderr || '').toString().trim() || `exit ${r.status}`}`);
    } else {
      // Signal the process GROUP, not just the pid.
      //
      // `npx vite` is a launcher: npx exits almost immediately after
      // spawning the real vite process, so killing the recorded pid
      // leaves vite running and holding the port. The next `npm start`
      // then reports ":6193 이 이미 사용 중" — far from the cause.
      //
      // This is the POSIX twin of what `taskkill /T` does on Windows.
      // `detached: true` in bg() makes each service its own group leader,
      // so a negative pid reaches the whole tree.
      const signalGroup = (sig) => {
        try {
          process.kill(-pid, sig);
          return true;
        } catch (e) {
          if (e.code !== 'ESRCH') return false;
          try { process.kill(pid, sig); return true; } catch { return false; }
        }
      };

      if (!signalGroup('SIGTERM')) {
        fail(`${name} (pid ${pid}) 종료 실패`);
      } else {
        // Poll for the exit rather than waiting a fixed interval.
        //
        // SIGTERM is a request, not an instruction: the process runs its
        // shutdown and exits when it is done. A fixed 700ms wait declared
        // "종료되지 않았습니다" for services that were mid-shutdown and
        // gone a moment later — a false alarm, and the kind that teaches
        // people to ignore the output.
        //
        // Escalation still happens, just for something that really is
        // refusing rather than something merely taking its time.
        const exited = await waitForExit(pid, 5000);
        if (!exited) {
          signalGroup('SIGKILL');
          await waitForExit(pid, 2000);
        }
        if (isAlive(pid)) fail(`${name} (pid ${pid}) 가 종료되지 않았습니다`);
        else ok(`${name} (pid ${pid}) 종료${exited ? '' : ' (SIGKILL)'}`);
      }
    }
  }
  fs.rmSync(PIDS, { force: true });
  if (has('docker')) {
    sh('docker', ['compose', 'down'], { allowFail: true });
    ok('docker compose down');
  }
}

/** Print the resolved port map — the thing .env actually produced. */
function printPorts() {
  console.log(`\n  ${C.bold}포트 (.env 기준)${C.reset}`);
  const rows = [
    ['컨트롤러 API',  'CONTROLLER_HTTP_LISTEN', PORTS.controllerHttp, 'TCP', '폰·콘솔 → 여기'],
    ['컨트롤러 gRPC', 'CONTROLLER_GRPC_LISTEN', PORTS.controllerGrpc, 'TCP', '내부'],
    ['WireGuard',     'WG_DATAPLANE_PORT',      PORTS.wireguard,      'UDP', '폰 → 문지기 (밖에서 열기)'],
    ['관리실 화면',   'CONSOLE_PORT',           PORTS.console,        'TCP', '관리자 브라우저'],
    ['MariaDB',       'MARIADB_HOST_PORT',      PORTS.mariadb,        'TCP', '컨트롤러만 (127.0.0.1)'],
    ['문지기 상태',   'GATEWAY_HEALTH_PORT',    PORTS.gatewayHealth,  'TCP', '컨테이너 안'],
  ];
  for (const [name, key, port, proto, who] of rows) {
    console.log(`    ${name.padEnd(14)} ${String(port).padStart(5)}/${proto}  ${C.dim}${key.padEnd(24)} ${who}${C.reset}`);
  }
  console.log(`\n  ${C.dim}바꾸려면 .env 의 변수를 고치고 npm start 를 다시 실행하세요.${C.reset}\n`);
}

async function status() {
  step('상태');
  for (const [name, port] of Object.entries(PORTS)) {
    const up = await portOpen(port);
    console.log(`    ${up ? C.green + '●' : C.dim + '○'}${C.reset} ${name.padEnd(16)} :${port}`);
  }

  // A port being open does not mean OUR process opened it — a stale
  // service from a previous run holds the port just as well, and
  // waitForPort would report success while the new binary had already
  // exited on a bind error. Show the recorded pids separately.
  const pids = readPids();
  if (Object.keys(pids).length) {
    console.log('');
    for (const [name, pid] of Object.entries(pids)) {
      const alive = isAlive(pid);
      console.log(`    ${alive ? C.green + '●' : C.dim + '○'}${C.reset} ${name.padEnd(16)} pid ${pid}${alive ? '' : C.dim + ' (종료됨)' + C.reset}`);
    }
  }
  if (has('docker')) {
    console.log('');
    sh('docker', ['compose', 'ps'], { allowFail: true });
  }

  // The gateway too — it is the one component whose absence looks like
  // everything working.
  console.log('');
  warnAboutGateway();
}

// ------------------------------------------------------------------ stages

function checkTools() {
  step('도구 확인');
  const need = [
    ['node', 'https://nodejs.org 에서 설치하세요 (18 이상)'],
    ['go', 'https://go.dev/dl 에서 설치하세요 (1.27.1 권장, 최소 1.26)'],
  ];
  for (const [cmd, hint] of need) {
    if (!has(cmd)) die(`${cmd} 를 찾을 수 없습니다`, hint);
    ok(`${cmd} 있음`);
  }
  const major = Number(process.versions.node.split('.')[0]);
  if (major < 18) die(`Node ${process.versions.node} — 18 이상이 필요합니다`, 'nodejs.org 에서 최신 LTS 설치');

  if (!FLAGS.noDocker && !has('docker')) {
    warn('docker 없음 — MariaDB 는 직접 띄워야 합니다 (--no-docker 로 이 경고를 끕니다)');
    FLAGS.noDocker = true;
  } else if (!FLAGS.noDocker) {
    const up = sh('docker', ['info'], { quiet: true, allowFail: true }).status === 0;
    if (!up) die('docker 데몬이 실행 중이 아닙니다', 'Docker Desktop 을 켜거나 `sudo systemctl start docker`');
    ok('docker 있음');
  }
}

function checkEnv() {
  step('환경 설정');
  const envPath = path.join(ROOT, '.env');
  const examplePath = path.join(ROOT, '.env.example');

  if (!fs.existsSync(envPath)) {
    if (!fs.existsSync(examplePath)) die('.env 도 .env.example 도 없습니다');
    fs.copyFileSync(examplePath, envPath);
    ok('.env.example 을 복사해 .env 를 만들었습니다');
    warn('비밀번호와 키가 예시 값입니다. 실제 배포 전에 반드시 바꾸세요.');
    return;
  }

  // Keys that exist in the example but not in .env. This is the failure
  // that bites after a `git pull` adds a setting: the stack starts and
  // then behaves as if the feature were off, with no error anywhere.
  const keysOf = (p) => new Set(
    // Split on either line ending. A .env saved by a Windows editor is
    // CRLF, and while trim() removes the stray \r here, doing the split
    // properly means the same code is safe if a caller stops trimming.
    fs.readFileSync(p, 'utf8').split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#') && l.includes('='))
      .map((l) => l.split('=')[0].trim()),
  );
  // Generate the settings key when it is empty.
  //
  // Empty rather than absent in .env.example, so the copy above leaves a
  // blank that this fills — a shipped default key would be the same on
  // every install, which is no key at all.
  {
    const body = fs.readFileSync(envPath, 'utf8');
    if (/^SETTINGS_ENCRYPTION_KEY=\s*$/m.test(body)) {
      const key = randomBytes(32).toString('base64');
      fs.writeFileSync(envPath,
        body.replace(/^SETTINGS_ENCRYPTION_KEY=\s*$/m, `SETTINGS_ENCRYPTION_KEY=${key}`));
      ok('SETTINGS_ENCRYPTION_KEY 생성 (설정값 암호화용)');
    }
  }

  if (fs.existsSync(examplePath)) {
    const missing = [...keysOf(examplePath)].filter((k) => !keysOf(envPath).has(k));
    if (missing.length) {
      // Append them with the example's own values rather than only
      // warning. A warning the user must act on before the next stage
      // is just a failure with extra steps — and the values that matter
      // (passwords) are already in .env, so what is missing here is
      // almost always new optional settings.
      //
      // Only ever appends. An existing value is never touched, so a
      // customised .env survives.
      const exampleLines = fs.readFileSync(examplePath, 'utf8').split(/\r?\n/);
      const add = [];
      for (const key of missing) {
        const line = exampleLines.find((l) => l.trim().startsWith(`${key}=`));
        if (line) add.push(line.trim());
      }
      if (add.length) {
        fs.appendFileSync(envPath,
          `\n# --- ${new Date().toISOString().slice(0, 10)} 자동 추가 (.env.example 기준) ---\n` +
          add.join('\n') + '\n');
        ok(`.env 에 새 설정 ${add.length}개 추가: ${add.map((l) => l.split('=')[0]).join(', ')}`);
        console.log(`      ${C.dim}값은 .env.example 의 기본값입니다. 필요하면 직접 수정하세요.${C.reset}`);
      } else {
        warn(`.env 에 없는 설정 ${missing.length}개를 자동 추가하지 못했습니다: ${missing.join(', ')}`);
      }
    } else {
      ok('.env 최신');
    }
  }
}

async function installDeps() {
  step('의존성');
  const targets = [
    { name: 'console', dir: path.join(ROOT, 'console') },
  ];
  if (fs.existsSync(path.join(ROOT, 'package-lock.json'))) {
    targets.unshift({ name: 'root', dir: ROOT });
  }

  for (const t of targets) {
    const lock = path.join(t.dir, 'package-lock.json');
    const pkg = path.join(t.dir, 'package.json');
    if (!fs.existsSync(pkg)) continue;

    const fp = fingerprint([pkg, lock]);
    // A missing node_modules forces the install even when the lock
    // matches — a fresh clone can carry a stamp but never the modules.
    const missing = !fs.existsSync(path.join(t.dir, 'node_modules'));

    await ifChanged(`deps-${t.name}`, fp, `${t.name} npm install`, () => {
      const useCi = fs.existsSync(lock);
      sh('npm', [useCi ? 'ci' : 'install', '--no-audit', '--no-fund'], { cwd: t.dir });
    }, missing);
  }

  // Go modules: `go build` fetches on demand, but doing it here means a
  // network problem surfaces as "dependencies" rather than as a
  // confusing build error three stages later.
  const goMod = path.join(ROOT, 'server', 'go.mod');
  if (fs.existsSync(goMod)) {
    const fp = fingerprint([goMod, path.join(ROOT, 'server', 'go.sum')]);
    await ifChanged('deps-go', fp, 'go mod download', () => {
      sh('go', ['mod', 'download'], { cwd: path.join(ROOT, 'server') });
    });
  }
}

/**
 * Turn a docker failure into something actionable.
 *
 * Docker's own messages are accurate and, for the common failures, tell
 * the reader nothing they can do. "mkdir /run/desktop/mnt/host/d: file
 * exists" is a WSL2 mount-shim state problem with a well-known fix, and
 * printing it verbatim followed by "try again" — which is what this
 * script did — sends someone to a search engine.
 *
 * Each entry is a signature and the remedy that actually works.
 */
const DOCKER_HINTS = [
  {
    match: /mount source path|mkdir \/run\/desktop\/mnt\/host|mkdir \/host_mnt/i,
    title: 'Docker Desktop 의 파일 공유 상태가 꼬였습니다 (WSL2 알려진 문제)',
    steps: [
      'PowerShell 을 관리자로 열고:  wsl --shutdown',
      'Docker Desktop 을 완전히 종료했다가 다시 켜기',
      '그래도 안 되면 Docker Desktop → Settings → Resources → File sharing 에서 해당 드라이브가 공유되어 있는지 확인',
    ],
    note: '0.26.4 부터 이 프로젝트는 호스트 바인드 마운트를 쓰지 않습니다. ' +
      '이 오류가 계속 보인다면 예전 컨테이너가 남아 있는 것이니 `npm run start:clean` 후 ' +
      '`docker compose down -v` 를 한 번 실행하세요.',
  },
  {
    match: /Cannot connect to the Docker daemon|docker daemon is not running|pipe\/dockerDesktopLinuxEngine/i,
    title: 'Docker 데몬이 실행 중이 아닙니다',
    steps: ['Docker Desktop 을 켜고 고래 아이콘이 "Running" 이 될 때까지 기다리세요'],
  },
  {
    match: /port is already allocated|address already in use|Bind for .* failed/i,
    title: '포트가 이미 사용 중입니다',
    steps: [
      'npm run status  로 어떤 포트가 물려 있는지 확인',
      'npm stop        으로 이 프로젝트가 띄운 것을 정리',
      '그래도 남아 있으면 다른 프로그램이 쓰는 중입니다',
    ],
  },
  {
    match: /required variable .* is missing a value/i,
    title: '.env 에 필요한 값이 없습니다',
    steps: ['.env.example 과 비교해 빠진 항목을 채우세요', 'npm start 가 [2] 단계에서 알려준 항목을 확인하세요'],
  },
  {
    match: /no space left on device/i,
    title: '디스크 공간이 부족합니다',
    steps: ['docker system prune -a   (사용하지 않는 이미지·캐시 정리)'],
  },
  {
    // A package the base image does not have.
    //
    // Before this, `failed to solve` matched first and reported it as a
    // network problem — sending someone to check their proxy over a
    // package name that was simply wrong for that Alpine release. The
    // more specific pattern has to come first.
    match: /unable to select packages|no such package/i,
    title: '이미지 안에서 패키지를 찾지 못했습니다',
    steps: [
      '위 오류의 패키지 이름을 확인하세요 — 그 배포판에 없는 이름일 수 있습니다',
      '네트워크 문제가 아닙니다. 프록시를 확인할 필요 없습니다',
    ],
  },
  {
    match: /failed to fetch|TLS handshake timeout|i\/o timeout|dial tcp/i,
    title: '이미지를 받아오지 못했습니다 (네트워크)',
    steps: ['인터넷 연결과 프록시 설정을 확인하고 다시 시도하세요'],
  },
  {
    // Last, because it matches every build failure. Anything above is a
    // named cause; this one only says where to look.
    match: /failed to solve/i,
    title: '이미지 빌드가 실패했습니다',
    steps: [
      '위 출력에서 ERROR 로 시작하는 줄이 실제 원인입니다',
      'docker compose build wg-data-node 로 그 단계만 다시 돌려볼 수 있습니다',
    ],
  },
];

function explainDocker(output) {
  if (!output) return false;
  for (const h of DOCKER_HINTS) {
    if (!h.match.test(output)) continue;
    console.log(`\n    ${C.yellow}${C.bold}${h.title}${C.reset}`);
    h.steps.forEach((st, i) => console.log(`      ${i + 1}. ${st}`));
    if (h.note) console.log(`\n      ${C.dim}${h.note}${C.reset}`);
    return true;
  }
  return false;
}

async function startDocker() {
  if (FLAGS.noDocker) { step('Docker'); skip('건너뜀 (--no-docker)'); return; }
  step('Docker');

  // Validate the compose file before invoking docker.
  //
  // Compose rejects a malformed file at *validation* time, which means
  // every subcommand fails — including `down`. Someone who edits the file
  // into that state cannot even clean up, and the error names a line
  // number in a file they may not have touched. Catching it here puts the
  // complaint next to the edit that caused it.
  const composeCheck = spawnSync(process.execPath,
    [path.join(ROOT, 'scripts', 'check-compose.mjs')],
    { cwd: ROOT, encoding: 'utf8' });
  if (composeCheck.status !== 0) {
    console.log((composeCheck.stdout || '').split('\n').filter((l) => /FAIL|실패/.test(l))
      .map((l) => '  ' + l).join('\n'));
    throw new Error('docker-compose.yml 검증 실패 — 위 항목을 고친 뒤 다시 실행하세요');
  }

  const inputs = [path.join(ROOT, 'docker-compose.yml'), path.join(ROOT, '.env')]
    .concat(walk(path.join(ROOT, 'infra'), ['Dockerfile', '.conf', '.sh']))
    // The gateway agent is a Go binary built inside its image, so its
    // sources are image inputs. The fingerprint listed only the
    // Dockerfile; every Go change since 1.7.15 — node reporting, virtual
    // destinations, NAT delivery, and the pre-shared key — rebuilt the
    // host binaries and left the container on the old one. The phone's
    // "invalid response message" survived a fix that was correct because
    // the code that would have applied it never ran.
    .concat(walk(path.join(ROOT, 'server'), ['Dockerfile.gateway-agent', '.go', 'go.mod', 'go.sum']));

  // Whether the containers are actually running matters as much as
  // whether the file changed: `docker compose down` between runs leaves
  // the fingerprint intact but the stack gone.
  // Whether the containers are actually running matters as much as
  // whether the file changed: `docker compose down` between runs leaves
  // the fingerprint intact but the stack gone.
  const down = sh('docker', ['compose', 'ps', '-q'], { quiet: true, allowFail: true })
    .stdout.trim().length === 0;

  await ifChanged('docker', fingerprint(inputs), 'docker compose up', () => {
    try {
      // wg-data-node too.
      //
      // It was left out, so `npm start` produced a stack where
      // registration, policies and approval all worked and no packet
      // ever crossed the tunnel. The phone showed 연결됨 with the key
      // icon — a VPN interface comes up whether or not a peer answers,
      // and WireGuard is silent about an absent one — while every probe
      // timed out.
      //
      // The container has been in docker-compose.yml the whole time.
      // This line simply never named it.
      sh('docker', ['compose', 'up', '-d', '--build',
        'mariadb', 'wg-data-node'], { capture: true });
    } catch (e) {
      // Diagnose before rethrowing, so the remedy appears next to the
      // error rather than after a generic "try again".
      explainDocker(e.output);
      throw e;
    }
  }, down);

  await waitForPort(PORTS.mariadb, 'MariaDB', 90000);

  // A listening port is not a ready database.
  //
  // MariaDB accepts TCP while it is still initialising, and a query sent
  // then comes back "unexpected EOF / driver: bad connection" — which is
  // what migrate hit. Until 1.8.0 this was invisible: Keycloak declared
  // `depends_on: mariadb: condition: service_healthy`, so compose held
  // everything until the healthcheck passed. Removing Keycloak removed
  // that wait with it, and nothing here replaced it.
  //
  // Ask the container's own healthcheck — the same one compose used.
  if (!FLAGS.noDocker) {
    const cid = (sh('docker', ['compose', 'ps', '-q', 'mariadb'],
      { quiet: true, allowFail: true }).stdout || '').trim().split(/\r?\n/)[0];
    let healthy = false;
    for (let i = 0; i < 60 && cid && !healthy; i++) {
      const h = sh('docker', ['inspect', '-f', '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}', cid],
        { quiet: true, allowFail: true });
      const st = (h.stdout || '').trim();
      // "none" means the image has no healthcheck: fall back to the
      // port, which is all we had before.
      healthy = st === 'healthy' || st === 'none';
      if (!healthy) sleepSync(1000);
    }
    if (cid && !healthy) {
      warn('MariaDB 가 60초 안에 준비되지 않았습니다 — docker compose logs mariadb');
    }
  }
  ok(`MariaDB :${PORTS.mariadb}`);

  // The port opens before the realm import finishes, and the controller
  // fails its OIDC discovery if it starts in that window — with an error
  // about a refused connection, which reads as "Keycloak isn't up" when
  // Keycloak is very much up. Wait for the realm itself.

  // …then make the realm match the file.
}

/** Parse .env into a plain object. */
function readEnvFile() {
  const out = {};
  try {
    for (const line of fs.readFileSync(path.join(ROOT, '.env'), 'utf8').split(/\r?\n/)) {
      const t = line.trim();
      if (!t || t.startsWith('#') || !t.includes('=')) continue;
      const i = t.indexOf('=');
      out[t.slice(0, i).trim()] = t.slice(i + 1).trim();
    }
  } catch { /* no .env yet */ }
  return out;
}


async function migrate() {
  step('DB 마이그레이션');
  const migrations = walk(path.join(ROOT, 'server', 'internal', 'db', 'migrations'), ['.sql']);
  if (!migrations.length) { skip('마이그레이션 파일 없음'); return; }

  const readVersion = () => (sh('go', ['run', './cmd/migrate', 'version'],
    { cwd: path.join(ROOT, 'server'), quiet: true, allowFail: true }).stdout || '')
    .trim().replace(/\s+/g, ' ');

  // The stamp is files + the version the database ends up at, so a
  // database reset behind our back is detected even though no file
  // changed.
  //
  // Read *after* migrating, not before. Recording the pre-migration
  // version meant every warm start saw a different value than the one
  // stored and re-ran — the migration is idempotent so nothing broke,
  // but the whole point of the stamp was lost.
  const before = readVersion();
  const filesFp = fingerprint(migrations);
  const stale = lastStamp('migrate') !== `${filesFp}-${before}`;

  await ifChanged('migrate', `${filesFp}-${before}`, `migrate up (${migrations.length / 2}개)`, () => {
    // Retry a connection error once.
    //
    // The healthcheck above is the real fix, but a database that has
    // just reported healthy can still refuse the very first connection
    // while it finishes warming up. Failing the whole start for that
    // sends the user back to `npm start` for something a two-second
    // wait settles. Only connection errors retry; a broken migration
    // fails immediately, as it should.
    const run = () => sh('go', ['run', './cmd/migrate', 'up'],
      { cwd: path.join(ROOT, 'server'), allowFail: true, capture: true });
    let r = run();
    if (r.status !== 0 && /bad connection|unexpected EOF|connection refused/i.test(
      `${r.stdout || ''}${r.stderr || ''}`)) {
      skip('DB 연결이 아직 불안정합니다 — 2초 뒤 다시 시도합니다');
      sleepSync(2000);
      r = run();
    }
    if (r.status !== 0) {
      process.stdout.write(`${r.stdout || ''}${r.stderr || ''}`);
      die('migrate up 실패');
    }
    // Re-stamp against the post-migration version so the next run is a
    // no-op instead of repeating this.
    writeStamp('migrate', `${filesFp}-${readVersion()}`);
  }, stale && lastStamp('migrate') === null);
}

/**
 * Check the console's sources against its last build.
 *
 * The orchestrator fingerprinted server sources and never looked at
 * `console/src` at all. In dev that is usually fine — Vite serves from
 * source — but it produced a failure with no signal anywhere:
 *
 *   - the production path (`console/server.js`, :9111) serves `dist`,
 *     so a stale `dist` shows the old UI while the source on disk is new
 *   - Vite's file watcher does not fire on some mounts (a Windows drive
 *     through WSL2, a network share), so even the dev server keeps
 *     serving what it read at startup
 *
 * In both cases the files are correct, the page is wrong, and nothing
 * says so. Reporting it is most of the fix; rebuilding when `dist`
 * already exists is the rest.
 */
async function checkConsole() {
  step('콘솔 화면');
  const consoleDir = path.join(ROOT, 'console');
  const srcDir = path.join(consoleDir, 'src');
  if (!fs.existsSync(srcDir)) { skip('console/src 없음'); return; }

  const sources = walk(srcDir, ['.vue', '.js', '.css', '.html', '.json'])
    .concat(walk(path.join(consoleDir, 'public'), ['.svg', '.png', '.ico']))
    .concat([path.join(ROOT, 'VERSION'), path.join(consoleDir, 'package.json'), path.join(consoleDir, 'package-lock.json'), path.join(consoleDir, 'vite.config.js'), path.join(consoleDir, 'index.html')]);
  const fp = fingerprint(sources);

  const dist = path.join(consoleDir, 'dist');
  const distMissing = !fs.existsSync(path.join(dist, 'index.html'));

  // Build whenever the sources changed OR dist is absent.
  //
  // 1.0.5 built only when dist already existed, reasoning that its
  // presence meant someone was serving the production bundle. That was
  // wrong in the one case that matters: `dist` is excluded from the
  // release archive, so a fresh unzip has no dist — and the condition
  // then said "nothing to do", forever. The build never ran on any
  // machine that had not already run it.
  //
  // Building unconditionally on first start costs a few seconds once.
  // Not building leaves :9111 with nothing to serve and no message
  // saying why.
  await ifChanged('console-dist', fp, 'console 빌드', () => {
    sh('npx', ['vite', 'build'], { cwd: consoleDir, quiet: true });
  }, distMissing);

  // Whatever the build state, tell the reader how to force a refresh.
  // The most common cause of "I changed it and nothing happened" is the
  // browser, not the build.
  console.log(`      ${C.dim}화면이 그대로면 브라우저에서 Ctrl+Shift+R (강력 새로고침)${C.reset}`);
  if (!has('inotifywait') && process.platform !== 'win32') {
    // Not fatal, and not worth a warning — just the one hint that
    // matters when the watcher is the problem.
    console.log(`      ${C.dim}파일 감시가 안 되는 환경이면 AIDOT_POLL=1 npm start${C.reset}`);
  }
}

async function buildServer() {
  step('서버 빌드');
  const sources = walk(path.join(ROOT, 'server'), ['.go', 'go.mod', 'go.sum'])
    .filter((f) => !f.endsWith('_test.go'));
  const out = path.join(CACHE, 'bin');
  fs.mkdirSync(out, { recursive: true });

  const binaries = ['controller', 'gateway-agent', 'relay'];
  // Windows will not execute a file without an extension, and `go build
  // -o name` writes exactly the name it was given — so the suffix has to
  // be part of the path we ask for, not something added later.
  const exe = (b) => path.join(out, IS_WIN ? `${b}.exe` : b);
  // A missing binary forces the build regardless of the fingerprint.
  const missing = !binaries.every((b) =>
    !fs.existsSync(path.join(ROOT, 'server', 'cmd', b)) || fs.existsSync(exe(b)));

  await ifChanged('build-server', fingerprint(sources), `go build (${binaries.length}개 바이너리)`, () => {
    for (const b of binaries) {
      const cmdDir = path.join(ROOT, 'server', 'cmd', b);
      if (!fs.existsSync(cmdDir)) continue;
      sh('go', ['build', '-o', exe(b), `./cmd/${b}`], { cwd: path.join(ROOT, 'server') });
    }
  }, missing);
}

/** Print the last few lines of a service log, for a failed start. */
function showTail(logFile, n = 10) {
  try {
    const lines = fs.readFileSync(logFile, 'utf8').trim().split(/\r?\n/).slice(-n);
    lines.forEach((l) => console.log(`      ${C.dim}${l}${C.reset}`));
  } catch {
    console.log(`      ${C.dim}(로그가 아직 없습니다)${C.reset}`);
  }
}

function bg(name, cmd, cmdArgs, opts = {}) {
  const logFile = path.join(CACHE, `${name}.log`);
  const fd = fs.openSync(logFile, 'a');
  const viaShell = useShell(cmd);
  const child = spawn(
    viaShell ? winCommandLine(cmd, cmdArgs) : cmd,
    viaShell ? [] : cmdArgs, {
    cwd: opts.cwd || ROOT,
    // detached: true on BOTH platforms.
    //
    // 0.26.2 set this to `!IS_WIN`, reasoning that detaching on Windows
    // opens a console window. It does — and `windowsHide` is what
    // suppresses it. Turning detach off instead removed the very thing
    // that keeps the child alive: Node's documentation says plainly that
    // "on Windows, setting options.detached to true makes it possible
    // for the child process to continue running after the parent exits".
    //
    // The symptom was quiet. `npm start` reported both services up and
    // exited; the services died with it; `npm stop` then found nothing
    // to kill and said "이미 종료됨". Nothing failed loudly — the console
    // simply did not answer afterwards.
    //
    // stdio matters here too, and is already right: the child's output
    // goes to log files, not to the parent's terminal. A child that
    // inherits the parent's stdio stays attached to the controlling
    // terminal and dies with it regardless of `detached`.
    detached: true,
    windowsHide: true,
    // Extra environment for the child, on top of ours. The console dev
    // server reads the controller port from here so its proxy follows
    // .env; without this a moved controller left the console proxying
    // to a port nobody was listening on.
    env: { ...process.env, ...(opts.env || {}) },
    // npx is a .cmd shim on Windows; the built controller binary is not.
    // See useShell — enabling the shell for the binary would let cmd.exe
    // re-split a cache path containing a space.
    shell: viaShell,
    stdio: ['ignore', fd, fd],
    env: { ...process.env, ...(opts.env || {}) },
  });
  child.unref();
  const pids = readPids();
  pids[name] = child.pid;
  fs.writeFileSync(PIDS, JSON.stringify(pids, null, 2));
  return { pid: child.pid, logFile };
}

/**
 * Free a port we own, so the service can be restarted with current code.
 *
 * `npm start` means "make this running with what is on disk now". The
 * 0.28.2 guard read it as "leave whatever is already there", which is a
 * different thing and the wrong one: after replacing the source, a
 * second `npm start` kept the previous process alive, printed 준비 완료,
 * and served the old code. `npm stop && npm start` worked, which is how
 * this surfaced.
 *
 * The guard was protecting against reporting success while a stale
 * process holds the port. That risk is real — it is just not a reason to
 * leave the stale process running when it is ours.
 *
 * Ours means: recorded in pids.json and still alive. Anything else on
 * that port belongs to someone else and is still refused, because
 * killing a process this script did not start would be a much worse
 * failure than not starting.
 */
async function reclaimPort(name, port) {
  if (!(await portOpen(port))) return true;

  const pid = readPids()[name];
  if (!pid || !isAlive(pid)) {
    warn(`:${port} 이 이미 사용 중입니다 — ${name} 를 시작하지 않습니다`);
    console.log(`      ${C.dim}이 프로젝트가 띄운 것이 아닙니다. 무엇이 쓰는지 확인하세요.${C.reset}`);
    return false;
  }

  skip(`${name} 재시작 (pid ${pid} 종료)`);
  killTree(pid);
  const freed = await waitForPortClosed(port, 6000);
  if (!freed) {
    fail(`:${port} 이 해제되지 않았습니다 — ${name} 를 시작하지 않습니다`);
    return false;
  }
  const pids = readPids();
  delete pids[name];
  fs.writeFileSync(PIDS, JSON.stringify(pids, null, 2));
  return true;
}

/** Terminate a service and its children. Shared with stopAll. */
function killTree(pid) {
  if (IS_WIN) {
    spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'pipe' });
    return;
  }
  const sig = (s) => {
    try { process.kill(-pid, s); return true; } catch (e) {
      if (e.code !== 'ESRCH') return false;
      try { process.kill(pid, s); return true; } catch { return false; }
    }
  };
  sig('SIGTERM');
}

/** Wait for a port to stop accepting connections. */
async function waitForPortClosed(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!(await portOpen(port))) return true;
    await sleep(150);
  }
  return !(await portOpen(port));
}

async function run() {
  step('서비스 시작');

  const controller = path.join(CACHE, 'bin', IS_WIN ? 'controller.exe' : 'controller');
  if (fs.existsSync(controller)) {
    // Refuse to start on top of something already holding the port.
    //
    // Otherwise the new process exits on a bind error, waitForPort sees
    // the OLD process still listening, and we report success — running
    // a stale binary while claiming to have started a fresh one. That is
    // the worst shape a start script can fail in, because everything
    // downstream looks fine.
    if (!(await reclaimPort('controller', PORTS.controllerHttp))) {
      // reclaimPort explained why.
    } else {
    const c = bg('controller', controller, []);
    ok(`controller 시작 (pid ${c.pid})`);
    const up = await waitForPort(PORTS.controllerHttp, 'controller', 45000);
    if (up && isAlive(c.pid)) {
      // A listening port is not a serving controller: during migrations
      // or a slow start it accepts the connection and answers nothing.
      // Ask /healthz, the way the phone and console will.
      const url = `http://127.0.0.1:${PORTS.controllerHttp}/healthz`;
      let healthy = false;
      for (let i = 0; i < 20 && !healthy; i++) {
        try {
          const r = await fetch(url, { signal: AbortSignal.timeout(2000) });
          healthy = r.ok;
        } catch { /* not yet */ }
        if (!healthy) await new Promise((res) => setTimeout(res, 500));
      }
      if (healthy) ok(`controller :${PORTS.controllerHttp} — /healthz 응답`);
      else warn(`controller :${PORTS.controllerHttp} 포트는 열렸지만 /healthz 가 답하지 않습니다`);
    }
    else if (up) fail('포트는 열렸지만 controller 프로세스가 살아있지 않습니다 (다른 프로세스가 물고 있습니다)');
    else {
      fail('controller 가 뜨지 않았습니다. 로그:');
      try {
        const log = fs.readFileSync(c.logFile, 'utf8').trim().split(/\r?\n/).slice(-8);
        log.forEach((l) => console.log(`      ${C.dim}${l}${C.reset}`));
      } catch { /* nothing logged yet */ }
    }
    }
  } else {
    warn('controller 바이너리가 없습니다 — 빌드 단계를 확인하세요');
  }

  const consoleDir = path.join(ROOT, 'console');
  if (fs.existsSync(path.join(consoleDir, 'package.json'))) {
    if (!(await reclaimPort('console', PORTS.console))) {
      // reclaimPort explained why.
    } else {
      // Run Vite's own entry point with node, not through npx.
      //
      // npx is a `.cmd` shim on Windows, so launching it needed a shell —
      // and a shell plus `detached: true` gives cmd.exe no console. A
      // batch file running without a console is unreliable, and Vite
      // queries the terminal on startup; the observed symptom was the
      // dev server serving index.html and then dying, so the browser got
      // a white page and ERR_CONNECTION_REFUSED for every asset after it.
      //
      // Calling node directly removes the shim, the shell and cmd.exe
      // from the path entirely. `node` is a real executable on both
      // platforms, so there is no Windows-specific behaviour left here.
      const viteBin = path.join(consoleDir, 'node_modules', 'vite', 'bin', 'vite.js');
      if (!fs.existsSync(viteBin)) {
        warn('vite 를 찾을 수 없습니다 — console 의존성 설치를 확인하세요');
        return;
      }
      const c = bg(
        'console',
        process.execPath,
        [path.join(consoleDir, 'server.js')],
        // cwd and env in one options object. A previous edit put them
        // in two, so cwd became a fifth argument bg() never reads and
        // vite started in the repo root, serving a 404 for everything.
        { cwd: consoleDir, env: { PORT: String(PORTS.console), CONTROLLER_URL: `http://127.0.0.1:${PORTS.controllerHttp}` } },
      );
      ok(`console 시작 (pid ${c.pid})`);
      const up = await waitForPort(PORTS.console, 'console', 45000);
      // A dev server that binds and then exits is the failure this catches.
      // The port test passes at the moment it is taken, so without a
      // second look a dead server reports as started — and the symptom
      // reaches the user as a white page rather than as anything here.
      await sleep(1500);
      if (up && isAlive(c.pid)) {
        ok(`console :${PORTS.console}`);
      } else if (up) {
        fail('console 이 포트를 열고 곧바로 종료했습니다');
        showTail(c.logFile);
      } else {
        warn(`console (:${PORTS.console}) 이 시작되지 않았습니다`);
        showTail(c.logFile);
      }
    }
  }
}

// Say plainly that there is no gateway.
//
// A handset connects, shows 연결됨 and the key icon, and every probe
// times out — because the tunnel interface comes up on the phone whether
// or not anything answers on the other end. WireGuard is silent about
// an absent peer.
//
// Registration, policies and approval all work without one, so the
// absence is invisible until someone tests reachability and reads the
// silence as a bug in the app.
/**
 * Add or replace one line in .env, keeping the rest untouched.
 *
 * The node token is generated once and has to survive the next run —
 * minting a fresh one each time would leave a trail of tokens that all
 * still work.
 */
function writeEnvVar(key, value) {
  const envPath = path.join(ROOT, '.env');
  const lines = fs.existsSync(envPath)
    ? fs.readFileSync(envPath, 'utf8').split(/\r?\n/)
    : [];
  const i = lines.findIndex((l) => l.startsWith(`${key}=`));
  if (i >= 0) lines[i] = `${key}=${value}`;
  else lines.push(`${key}=${value}`);
  fs.writeFileSync(envPath, lines.join('\n'));
}

/**
 * Issue a node token and bring the gateway agent up.
 *
 * The agent is what carries policy from the controller onto the
 * interface — `wg set wg0 peer …`. Without it wg0 stands with an empty
 * peer list, so a phone that registered and got a policy still cannot
 * handshake, and `docker compose logs wg-data-node` shows an interface
 * with no peers.
 *
 * That reads as "no phone has connected yet". It actually means nothing
 * is there to add them.
 *
 * It was in docker-compose.yml behind `profiles: ["gateway"]` and built
 * by this script but never started — so every part of the system worked
 * except the one that joins them.
 */
/**
 * The address a phone on the same network would use to reach this
 * machine.
 *
 * First non-internal IPv4 that is not a Docker or WSL bridge. On the
 * user's box `ipconfig` shows 100.64.0.1 (a VPN adapter), 172.17.32.1
 * (WSL), and 172.30.1.16 (Wi-Fi) — only the last is what a phone can
 * reach, and it is the one with a default gateway. Node cannot see the
 * gateway, so the bridges are excluded by name and range instead.
 */
function lanAddress() {
  const nets = os.networkInterfaces();
  const candidates = [];
  for (const [name, list] of Object.entries(nets)) {
    for (const n of list || []) {
      if (n.family !== 'IPv4' || n.internal) continue;
      const lower = name.toLowerCase();
      if (/wsl|hyper-v|vethernet|docker|vmware|virtualbox|tailscale|zerotier/.test(lower)) continue;
      if (n.address.startsWith('172.17.') || n.address.startsWith('100.64.')) continue;
      candidates.push({ name, address: n.address });
    }
  }
  // Prefer wifi/ethernet by name when there is a choice.
  candidates.sort((a, b) => {
    const score = (c) => (/wi-?fi|wlan|ethernet|eth|en0|이더넷|무선/i.test(c.name) ? 0 : 1);
    return score(a) - score(b);
  });
  return candidates[0]?.address || null;
}

/**
 * On Windows, say whether the two inbound ports are open.
 *
 * The node can advertise the right address, the port can be bound to
 * every interface, and Windows Defender still drops the packet at the
 * door. Nothing in the stack can see that happen: the phone logs
 * unanswered handshakes, the gateway logs nothing, and the reason is
 * in a control panel nobody thinks to open.
 *
 * Read-only. Adding rules needs elevation, and a startup script that
 * silently changes firewall policy is not something to ship. It says
 * what to run instead.
 */
function checkFirewall(wgPort) {
  if (process.platform !== 'win32') return;

  const rule = (name) => sh('powershell', ['-NoProfile', '-Command',
    `(Get-NetFirewallRule -DisplayName '${name}' -ErrorAction SilentlyContinue | ` +
    `Where-Object Enabled -eq True | Measure-Object).Count`],
    { quiet: true, allowFail: true });

  const wg = rule('AidotVpn WireGuard');
  const ctl = rule('AidotVpn Controller');
  if (wg.status !== 0 || ctl.status !== 0) return; // PowerShell unavailable; say nothing rather than guess

  const wgOpen = (wg.stdout || '').trim() !== '0';
  const ctlOpen = (ctl.stdout || '').trim() !== '0';
  if (wgOpen && ctlOpen) {
    ok('Windows 방화벽: 52840/udp, 10030/tcp 열림');
    return;
  }
  globalThis.FIREWALL_MISSING = true;
  warn('Windows 방화벽에 AidotVpn 규칙이 없습니다 — 밖의 폰이 붙지 못합니다');
  console.log(`      ${C.dim}관리자 PowerShell 에서:${C.reset}`);
  if (!wgOpen) {
    console.log(`      ${C.dim}New-NetFirewallRule -DisplayName "AidotVpn WireGuard" -Direction Inbound -Protocol UDP -LocalPort ${wgPort} -Action Allow${C.reset}`);
  }
  if (!ctlOpen) {
    console.log(`      ${C.dim}New-NetFirewallRule -DisplayName "AidotVpn Controller" -Direction Inbound -Protocol TCP -LocalPort ${PORTS.controllerHttp} -Action Allow${C.reset}`);
  }
  console.log(`      ${C.dim}자세한 내용: docs/getting-started.md${C.reset}`);
}

/**
 * Point the seeded node at this machine.
 *
 * Migration 0004 seeds 10.0.2.2 — the emulator's host alias — and a
 * real phone sending handshakes there gets nothing back, while its own
 * interface comes up fine and the app reads 연결됨. The phone logged
 * twelve handshake attempts with no reply before this existed.
 */
function pointNodeAtThisMachine() {
  const host = process.env.AIDOTVPN_PUBLIC_ENDPOINT_HOST || lanAddress();
  const port = process.env.AIDOTVPN_PUBLIC_ENDPOINT_PORT || String(PORTS.wireguard);
  if (!host) {
    warn('이 컴퓨터의 LAN 주소를 찾지 못했습니다 — .env 에 AIDOTVPN_PUBLIC_ENDPOINT_HOST 를 적으세요');
    console.log(`      ${C.dim}폰은 문지기가 어디 있는지 모르게 됩니다.${C.reset}`);
    return;
  }
  const r = sh('go', ['run', './cmd/migrate', 'node-endpoint', 'dev-node-1.aidotvpn.local', host, port],
    { cwd: path.join(ROOT, 'server'), quiet: true, allowFail: true });
  if (r.status !== 0) {
    warn(`노드 접속 주소를 갱신하지 못했습니다: ${(r.stderr || '').trim().split('\n')[0]}`);
    return;
  }
  checkFirewall(port);
  ok(`문지기 접속 주소 → ${host}:${port}`);
  console.log(`      ${C.dim}폰이 여기로 핸드셰이크를 보냅니다. 다른 주소를 쓰려면 .env 의 AIDOTVPN_PUBLIC_ENDPOINT_HOST${C.reset}`);

  // The port must actually be reachable at that address.
  //
  // docker-compose binds the WireGuard UDP port to LAN_BIND_ADDR, and
  // .env.example ships 127.0.0.1 — this machine only. So the node
  // advertised 172.30.1.16:52840 to the phone while the host accepted
  // that port on localhost alone, and every handshake fell on the
  // floor. Telling the phone where to knock is pointless if the door
  // is only open from the inside.
  const bind = (process.env.WG_BIND_ADDR || '0.0.0.0').trim();
  if (bind === '127.0.0.1' || bind === 'localhost') {
    warn('WireGuard 포트가 이 컴퓨터 안에서만 열려 있습니다 (WG_BIND_ADDR=127.0.0.1)');
    console.log(`      ${C.dim}폰이 ${host}:${port} 로 보내도 이 컴퓨터가 받지 않습니다.${C.reset}`);
    console.log(`      ${C.dim}.env 에서 WG_BIND_ADDR 줄을 지우거나 0.0.0.0 으로 바꾸고 npm start 를 다시 실행하세요.${C.reset}`);
  }
}

async function startGatewayAgent() {
  const token = (process.env.GATEWAY_NODE_TOKEN || '').trim();
  let effective = token;

  if (!effective) {
    // Mint one. The hostname must match the seeded node row, since the
    // token is what identifies which node is reporting.
    const out = sh('go', ['run', './cmd/migrate', 'node-token', 'dev-node-1.aidotvpn.local'],
      { cwd: path.join(ROOT, 'server'), quiet: true, allowFail: true });
    // The `token:` line specifically.
    //
    // A bare "20+ characters" pattern matched the hostname on the line
    // above it — dev-node-1.aidotvpn.local — and would have handed the
    // agent a hostname as its credential.
    const m = (out.stdout || '').match(/^\s*token:\s*(\S+)\s*$/m);
    if (!m) {
      warn('노드 토큰을 발급하지 못했습니다 — 게이트웨이 에이전트를 띄우지 않습니다');
      console.log(`      ${C.dim}정책이 문지기에 반영되지 않습니다. 폰은 등록돼도 연결이 거부됩니다.${C.reset}`);
      console.log(`      ${C.dim}${(out.stderr || '').trim().split('\n')[0] || ''}${C.reset}`);
      return;
    }
    effective = m[1];
    writeEnvVar('GATEWAY_NODE_TOKEN', effective);
  }

  const up = sh('docker',
    // --build, and the container recreated when the image changed.
    // Plain `up -d` on a running container is a no-op even when the
    // image behind it has been rebuilt; that is how the agent kept
    // running a binary from before the PSK ever reached it.
    ['compose', '--profile', 'gateway', 'up', '-d', '--build', 'gateway-agent'],
    { env: { AIDOTVPN_VERSION: fs.readFileSync(path.join(ROOT, 'VERSION'), 'utf8').trim() } },
    { quiet: true, allowFail: true, env: { GATEWAY_NODE_TOKEN: effective } });

  if (up.status !== 0) {
    warn('게이트웨이 에이전트를 띄우지 못했습니다');
    console.log(`      ${C.dim}${(up.stderr || '').trim().split('\n')[0] || ''}${C.reset}`);
    console.log(`      ${C.dim}정책이 문지기에 반영되지 않습니다 — docker compose logs gateway-agent${C.reset}`);
    return;
  }
  ok('게이트웨이 에이전트 시작 (정책을 문지기에 반영)');
}

function warnAboutGateway() {
// Check the container, not the host.
//
// The gateway runs in wg-data-node, so `wg` on the host says nothing
// — on Windows there is no `wg` at all and the first version of this
// warned every single run.
const ps = sh('docker', ['compose', 'ps', '-q', 'wg-data-node'],
  { quiet: true, allowFail: true });
if (ps.status === 0 && (ps.stdout || '').trim()) {
  const up = sh('docker', ['compose', 'exec', '-T', 'wg-data-node', 'wg', 'show'],
    { quiet: true, allowFail: true });
  if (up.status === 0 && (up.stdout || '').trim()) {
    // Say which implementation carried it, and show the evidence.
    //
    // A checkmark is not evidence. The build log says plainly that
    // wireguard-go was not installed, so "게이트웨이가 떠 있습니다" on
    // the next run reads as a contradiction — unless it also says the
    // kernel module is what carried it.
    const mod = sh('docker',
      ['compose', 'exec', '-T', 'wg-data-node', 'test', '-e', '/sys/module/wireguard'],
      { quiet: true, allowFail: true });
    const backend = mod.status === 0 ? '커널 모듈' : 'wireguard-go (유저스페이스)';

    const out = (up.stdout || '').split('\n');
    const iface = out.find((l) => l.trim().startsWith('interface:')) || '';
    const port = out.find((l) => l.includes('listening port')) || '';

    ok(`WireGuard 게이트웨이가 떠 있습니다 — ${backend}`);
    if (iface) console.log(`      ${C.dim}${iface.trim()}${C.reset}`);
    if (port) console.log(`      ${C.dim}${port.trim()}${C.reset}`);

    // Is anything listening on the tunnel address?
    //
    // The tutorial points probes at 10.78.0.1:8080, served by a
    // responder the container starts after wg0. A user with the tunnel
    // up and every probe timing out asked whether anything was listening
    // there at all, and nothing in startup could say. This asks the
    // container itself, so the answer does not depend on any phone.
    // Judge by HTTP status line, not exit code.
    //
    // 1.7.31 read wget's exit code and took 8 as "HTTP error, so the
    // proxy answered" — GNU wget semantics. Alpine's busybox wget
    // exits 1 for that, so a proxy returning a perfectly good 404 was
    // reported 무응답, and the advice that followed ("옛 이미지입니다")
    // was wrong. python3 is in the image; urllib distinguishes "got a
    // status" from "nothing there" unambiguously.
    // probe.py is baked into the image; see its header for why not -c.
    let lines = [];
    let r = { status: 1, stdout: '', stderr: '' };
    for (let attempt = 0; attempt < 6; attempt++) {
      r = sh('docker', ['compose', 'exec', '-T', 'wg-data-node', 'python3', '/usr/local/bin/probe.py',
        'http://10.78.0.1:8080/', 'http://10.78.0.1:10030/devices/x/state'],
        { quiet: true, allowFail: true });
      lines = (r.stdout || '').split('\n');
      const answered = lines.filter((l) => /\s\d+$/.test(l.trim())).length;
      if (answered === 2) break;
      if (r.status !== 0 && !lines.some((l) => l.includes('10.78.0.1'))) break; // exec itself failed
      sleepSync(2000);
    }
    const statusOf = (frag) => (lines.find((l) => l.includes(frag)) || '').trim().split(' ').pop();
    const s8080 = statusOf(':8080/');
    const s10030 = statusOf(':10030/');
    const up8080 = /^\d+$/.test(s8080);
    const up10030 = /^\d+$/.test(s10030);
    if (up8080 && up10030) {
      ok(`문지기 응답 서버: 10.78.0.1:8080 (시험 대상, ${s8080}) · :10030 (컨트롤러 중계, ${s10030}) 둘 다 응답`);
    } else {
      warn(`문지기 응답 서버 — 8080 ${up8080 ? `응답(${s8080})` : '무응답'}, 10030 ${up10030 ? `응답(${s10030})` : '무응답'}`);
      if (r.status !== 0 && !lines.some((l) => l.includes('10.78.0.1'))) {
        console.log(`      ${C.dim}컨테이너에 물어보지 못했습니다: ${(r.stderr || '').trim().split('\n')[0]}${C.reset}`);
      } else if (!up8080 && !up10030) {
        console.log(`      ${C.dim}응답 서버가 안 떠 있습니다. docker compose logs wg-data-node | findstr responder${C.reset}`);
      } else {
        console.log(`      ${C.dim}한쪽만 답합니다. docker compose logs wg-data-node 로 Traceback 을 확인하세요.${C.reset}`);
      }
    }
    if (mod.status !== 0) {
      console.log(`      ${C.dim}커널 모듈이 없어 유저스페이스로 돌고 있습니다 — 느립니다${C.reset}`);
    }
    return;
  }
  warn('wg-data-node 는 떠 있으나 WireGuard 인터페이스가 없습니다 — docker compose logs wg-data-node');
  return;
}
warn('WireGuard 게이트웨이가 없습니다 — 터널은 연결되지만 트래픽은 아무 데도 닿지 않습니다');
console.log(`      ${C.dim}등록·정책·승인은 정상 동작합니다. 도달성 시험만 전부 "응답 없음" 이 됩니다.${C.reset}`);
console.log(`      ${C.dim}--no-docker 로 띄우면 게이트웨이가 없습니다. 자세한 내용: docs/getting-started.md${C.reset}`);
}

function summary() {
  warnAboutGateway();
  console.log(`\n${C.bold}${C.green}준비 완료${C.reset}\n`);
  const consoleURL = process.env.CONSOLE_PUBLIC_URL || ENV0.CONSOLE_PUBLIC_URL || savedConsole.publicURL || `${['true','1'].includes((process.env.CONSOLE_HTTPS_ENABLED || ENV0.CONSOLE_HTTPS_ENABLED || String(savedConsole.https?.enabled || false))) ? 'https' : 'http'}://localhost:${PORTS.console}`;
  console.log(`  관리자 화면   ${C.cyan}${consoleURL}${C.reset}`);
  console.log(`  컨트롤러 API  ${C.cyan}http://localhost:${PORTS.controllerHttp}${C.reset}`);
  console.log('');
  console.log(`  ${C.dim}로그 보기   npm run logs${C.reset}`);
  console.log(`  ${C.dim}상태 보기   npm run status${C.reset}`);
  console.log(`  ${C.dim}중지        npm stop${C.reset}`);

  // Repeat the firewall warning here, at the end, where it is the last
  // thing read. It printed once, between migration lines, and was
  // scrolled past: the user rebuilt the gateway image twice looking for
  // a reason phones could not connect while the reason sat forty lines
  // up.
  if (globalThis.FIREWALL_MISSING) {
    console.log('');
    console.log(`  ${C.yellow}${C.bold}!! 폰이 붙을 수 없습니다 — Windows 방화벽이 닫혀 있습니다${C.reset}`);
    console.log(`  ${C.yellow}   관리자 PowerShell 에서 위 New-NetFirewallRule 두 줄을 실행한 뒤 폰에서 재연결하세요.${C.reset}`);
  }
  console.log('');
}

/**
 * Follow the container logs.
 *
 * Separate from `npm run logs`, which follows the controller and console
 * — those are host processes writing to files in .aidot-cache, and the
 * containers are somewhere else entirely. Someone debugging a database
 * or Keycloak problem was looking in the wrong place.
 */
function dockerLogs() {
  step('Docker 로그');
  if (!has('docker')) {
    warn('docker 를 찾을 수 없습니다');
    return;
  }
  console.log(`    ${C.dim}Ctrl+C 로 종료${C.reset}\n`);
  sh('docker', ['compose', 'logs', '-f', '--tail', '80'], { allowFail: true });
}

function tailLogs() {
  step('로그');
  const files = fs.readdirSync(CACHE).filter((f) => f.endsWith('.log'));
  if (!files.length) { skip('로그 없음 — 먼저 npm start 를 실행하세요'); return; }
  const paths = files.map((f) => path.join(CACHE, f));
  console.log(`    ${C.dim}${paths.join('\n    ')}${C.reset}\n`);

  // Implemented here rather than shelling out to `tail -f`, which
  // Windows does not have. Polls file sizes and prints what was appended.
  const offsets = new Map();
  for (const fp of paths) {
    let size = 0;
    try { size = fs.statSync(fp).size; } catch { /* gone */ }
    const back = Math.max(0, size - 4096);
    offsets.set(fp, back);
  }

  const pump = () => {
    for (const fp of paths) {
      let size;
      try { size = fs.statSync(fp).size; } catch { continue; }
      const from = offsets.get(fp) ?? 0;
      // A log that shrank was rotated or truncated; restart from zero
      // rather than reading a negative range.
      if (size < from) { offsets.set(fp, 0); continue; }
      if (size === from) continue;
      const fd = fs.openSync(fp, 'r');
      const buf = Buffer.alloc(size - from);
      fs.readSync(fd, buf, 0, buf.length, from);
      fs.closeSync(fd);
      offsets.set(fp, size);
      const tag = path.basename(fp, '.log');
      buf.toString('utf8').split(/\r?\n/).filter(Boolean)
        .forEach((l) => console.log(`${C.dim}[${tag}]${C.reset} ${l}`));
    }
  };
  pump();
  console.log(`${C.dim}    (Ctrl+C 로 종료)${C.reset}`);
  setInterval(pump, 700);
}

// -------------------------------------------------------------------- main

(async () => {
  console.log(`${C.bold}AidotVpn${C.reset} ${C.dim}— npm start${C.reset}`);

  if (FLAGS.stop) return await stopAll();
  if (FLAGS.ports) { printPorts(); return; }
  if (FLAGS.status) return await status();
  if (FLAGS.logs) return tailLogs();
  if (FLAGS.dockerLogs) return dockerLogs();

  if (FLAGS.clean) {
    warn('--clean: 모든 캐시를 지우고 처음부터 진행합니다');
    for (const f of fs.readdirSync(CACHE)) {
      if (f.endsWith('.stamp')) fs.rmSync(path.join(CACHE, f));
    }
  }

  try {
    checkTools();
    checkEnv();
    await installDeps();
    await startDocker();
    await migrate();
    pointNodeAtThisMachine();
    await buildServer();
    await checkConsole();
    await run();
    // The agent last, after the controller it talks to is listening —
    // and before summary, so the gateway line reflects a real peer
    // sync rather than an interface nobody has populated yet.
    await startGatewayAgent();
    summary();
  } catch (e) {
    console.log('');
    die(e.message, '위 오류를 확인하고 다시 `npm start` 를 실행하세요. 캐시가 꼬였다면 `npm run start:clean`.');
  }
})();

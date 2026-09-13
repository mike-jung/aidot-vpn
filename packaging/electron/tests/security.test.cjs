'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createHash } = require('node:crypto');
const { consoleURL, sameOrigin, normalizeConfig, childEnvironment, assertSettingsSender, windowPreferences, SETTINGS_URL } = require('../security.cjs');
const { DesktopRuntime, readSettings, atomicJSON, availablePort, probe, verifyBackend, BACKENDS } = require('../runtime.cjs');
test('remote addresses require HTTPS; unsafe origins and lookalike hosts are rejected', () => {
  assert.equal(consoleURL('https://vpn.example.com/'), 'https://vpn.example.com');
  assert.equal(consoleURL('http://127.0.0.1:19111'), 'http://127.0.0.1:19111');
  for (const url of ['http://vpn.example.com', 'http://localhost.example.com', 'file:///etc/passwd', 'javascript:alert(1)', 'https://user:secret@vpn.example.com', 'https://vpn.example.com/path', 'https://vpn.example.com/?token=x']) assert.throws(() => consoleURL(url));
  assert.equal(sameOrigin('https://vpn.example.com.evil.test', 'https://vpn.example.com'), false);
  assert.equal(sameOrigin('https://vpn.example.com/ha', 'https://vpn.example.com'), true);
});
test('settings validate types, paths and mutually conflicting ports', () => {
  assert.throws(() => normalizeConfig({ mode: 'bundled', startController: true }));
  assert.throws(() => normalizeConfig({ autoStart: 'false' }));
  assert.throws(() => normalizeConfig({ localPort: 0 }));
  assert.throws(() => normalizeConfig({ controllerEnv: '../controller.env' }));
  assert.throws(() => normalizeConfig({ mode: 'bundled', startController: true, controllerEnv: path.join(os.tmpdir(), 'controller.env'), localPort: 10030 }));
  assert.throws(() => normalizeConfig({ executable: 'malicious.exe' }));
});
test('only the top frame of the dedicated settings window can call desktop IPC', () => {
  const frame = { url: SETTINGS_URL }, contents = { mainFrame: null }; contents.mainFrame = frame;
  const win = { isDestroyed: () => false, webContents: contents }, good = { sender: contents, senderFrame: frame };
  assert.doesNotThrow(() => assertSettingsSender(good, win));
  assert.throws(() => assertSettingsSender({ ...good, sender: {} }, win));
  assert.throws(() => assertSettingsSender({ ...good, senderFrame: { url: SETTINGS_URL } }, win));
  frame.url = 'https://vpn.example.com'; assert.throws(() => assertSettingsSender(good, win));
});
test('untrusted renderer preferences cannot disable isolation or sandboxing', () => {
  const prefs = windowPreferences({ nodeIntegration: true, sandbox: false, contextIsolation: false, webSecurity: false });
  assert.equal(prefs.nodeIntegration, false); assert.equal(prefs.sandbox, true); assert.equal(prefs.contextIsolation, true); assert.equal(prefs.webSecurity, true); assert.equal(prefs.webviewTag, false);
});
test('inherited credentials and runtime injection options do not enter child environments', () => {
  assert.deepEqual(childEnvironment({ PATH: 'test-path', SYSTEMROOT: 'windows', NODE_OPTIONS: '--require injected.cjs', ELECTRON_RUN_AS_NODE: '1', NODE_EXTRA_CA_CERTS: 'unexpected.pem', AIDOTVPN_DB_PASSWORD: 'secret', CONTROLLER_URL: 'https://wrong.example', CONSOLE_PORT: '9111', SETTINGS_ENCRYPTION_KEY: 'secret' }), { PATH: 'test-path', SYSTEMROOT: 'windows' });
});
test('settings survive reopening; a damaged file is preserved instead of reset', t => {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'aidot-settings-')); t.after(() => fs.rmSync(profile, { recursive: true, force: true }));
  assert.equal(readSettings(profile), null);
  const c = normalizeConfig({ locale: 'en' }); atomicJSON(path.join(profile, 'desktop.json'), c); assert.deepEqual(readSettings(profile), c);
  fs.writeFileSync(path.join(profile, 'desktop.json'), '{broken'); assert.throws(() => readSettings(profile)); assert.equal(fs.readFileSync(path.join(profile, 'desktop.json'), 'utf8'), '{broken');
});
test('connecting and quitting never stop an existing server or require bundled executables', async t => {
  const server = http.createServer((_req, res) => res.end('ready'));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); t.after(() => new Promise(resolve => server.close(resolve)));
  const url = 'http://127.0.0.1:' + server.address().port;
  const runtime = new DesktopRuntime({ profile: os.tmpdir(), backend: 'missing-backend', version: 'test' });
  assert.equal(await runtime.start({ mode: 'connect', consoleURL: url }), url); assert.equal(runtime.children.length, 0);
  await runtime.stop(); await probe(url); assert.equal(server.listening, true);
});
test('occupied ports and redirect responses cannot be mistaken for a ready owned server', async t => {
  const server = http.createServer((_req, res) => { res.writeHead(302, { Location: 'https://other.example' }); res.end(); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); t.after(() => new Promise(resolve => server.close(resolve)));
  await assert.rejects(availablePort(server.address().port), /already in use/);
  await assert.rejects(probe('http://127.0.0.1:' + server.address().port), /HTTP 302/);
});
test('wrong-version, missing and modified server binaries are rejected', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'aidot-backend-')); t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const hashes = {};
  for (const name of BACKENDS) { fs.writeFileSync(path.join(directory, name), name); hashes[name] = createHash('sha256').update(name).digest('hex'); }
  atomicJSON(path.join(directory, 'build-manifest.json'), { version: '1.20.0', platform: 'win32', arch: 'x64', hashes });
  assert.doesNotThrow(() => verifyBackend(directory, '1.20.0')); assert.throws(() => verifyBackend(directory, '1.19.0'));
  fs.appendFileSync(path.join(directory, BACKENDS[0]), 'tampered'); assert.throws(() => verifyBackend(directory, '1.20.0'), /integrity/);
  fs.rmSync(path.join(directory, BACKENDS[0])); assert.throws(() => verifyBackend(directory, '1.20.0'));
});

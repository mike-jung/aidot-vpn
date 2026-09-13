'use strict';
const path = require('node:path');
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);
const SETTINGS_URL = 'aidot-desktop://app/settings.html';
function consoleURL(value) {
  if (typeof value !== 'string' || value.length > 2048) throw Error('Enter a console URL.');
  let u; try { u = new URL(value.trim()); } catch { throw Error('Enter a valid console URL.'); }
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password || u.search || u.hash || u.pathname !== '/') throw Error('Use an HTTP(S) origin without credentials, a path, or query parameters.');
  if (u.protocol === 'http:' && !LOOPBACK.has(u.hostname)) throw Error('Remote connections require HTTPS.');
  return u.origin;
}
function isLoopback(value) { try { return LOOPBACK.has(new URL(value).hostname); } catch { return false; } }
function sameOrigin(value, allowed) {
  try { const u = new URL(value); return !u.username && !u.password && ['https:', 'http:'].includes(u.protocol) && u.origin === new URL(allowed).origin; } catch { return false; }
}
function normalizeConfig(value = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Invalid desktop settings.');
  const fields = ['mode', 'consoleURL', 'controllerURL', 'controllerEnv', 'startController', 'localPort', 'autoStart', 'locale'];
  if (Object.keys(value).some(k => !fields.includes(k))) throw Error('Unknown desktop setting.');
  const c = { mode: 'connect', consoleURL: 'http://127.0.0.1:9111', controllerURL: 'http://127.0.0.1:10030', controllerEnv: '', startController: false, localPort: 19111, autoStart: false, locale: 'ko', ...value };
  if (!['connect', 'bundled'].includes(c.mode) || !['ko', 'en'].includes(c.locale)) throw Error('Invalid desktop mode or language.');
  for (const k of ['autoStart', 'startController']) if (typeof c[k] !== 'boolean') throw Error('Invalid desktop option.');
  c.consoleURL = consoleURL(c.consoleURL); c.controllerURL = consoleURL(c.controllerURL);
  if (!Number.isInteger(c.localPort) || c.localPort < 1024 || c.localPort > 65535) throw Error('The local console port must be between 1024 and 65535.');
  if (typeof c.controllerEnv !== 'string' || c.controllerEnv.includes('\0') || c.controllerEnv.length > 4096 || (c.controllerEnv && !path.isAbsolute(c.controllerEnv))) throw Error('Choose an absolute controller.env path.');
  if (c.mode === 'bundled' && c.startController && (!c.controllerEnv || !isLoopback(c.controllerURL))) throw Error('A bundled controller needs its configuration file and a loopback controller URL.');
  if (c.mode === 'bundled' && c.startController && Number(new URL(c.controllerURL).port || 80) === c.localPort) throw Error('Console and controller ports must be different.');
  return c;
}
function childEnvironment(source = process.env) {
  const env = {};
  for (const [key, value] of Object.entries(source)) {
    if (/^(NODE_|ELECTRON_|AIDOTVPN_|CONTROLLER_|CONSOLE_|SETTINGS_ENCRYPTION_KEY$)/i.test(key)) continue;
    env[key] = value;
  }
  return env;
}
function assertSettingsSender(event, window) {
  if (!window || window.isDestroyed() || event.sender !== window.webContents || event.senderFrame !== window.webContents.mainFrame || event.senderFrame.url !== SETTINGS_URL) throw Error('Untrusted desktop request.');
}
function windowPreferences(extra = {}) {
  return { ...extra, nodeIntegration: false, nodeIntegrationInWorker: false, nodeIntegrationInSubFrames: false, contextIsolation: true, sandbox: true, webSecurity: true, allowRunningInsecureContent: false, webviewTag: false, devTools: false };
}
module.exports = { consoleURL, isLoopback, sameOrigin, normalizeConfig, childEnvironment, assertSettingsSender, windowPreferences, SETTINGS_URL };

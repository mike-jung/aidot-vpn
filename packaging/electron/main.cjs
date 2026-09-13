'use strict';
const { app, BrowserWindow, Tray, Menu, dialog, ipcMain, protocol, session, shell } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const { createHash, randomUUID } = require('node:crypto');
const { DesktopRuntime, atomicJSON, readSettings, verifyBackend } = require('./runtime.cjs');
const { normalizeConfig, sameOrigin, assertSettingsSender, windowPreferences, SETTINGS_URL } = require('./security.cjs');
app.setName('AidotVPN Desktop');
app.setAppUserModelId('com.aidotvpn.desktop');
app.enableSandbox();
protocol.registerSchemesAsPrivileged([{ scheme: 'aidot-desktop', privileges: { standard: true, secure: true, supportFetchAPI: true } }]);
const customProfile = process.env.AIDOTVPN_DESKTOP_PROFILE;
if (customProfile) { if (!path.isAbsolute(customProfile)) throw Error('Desktop profile must be an absolute path.'); app.setPath('userData', customProfile); }
const profile = app.getPath('userData');
const version = app.getVersion();
const backend = app.isPackaged ? path.join(process.resourcesPath, 'backend') : path.resolve(__dirname, '../out/win32-x64');
const icon = app.isPackaged ? path.join(process.resourcesPath, 'aidotvpn.ico') : path.resolve(__dirname, '../windows/aidotvpn.ico');
let settingsWindow, consoleWindow, tray, config, quitting = false, busy = false;
let queue = Promise.resolve();
const serial = action => { const result = queue.then(action); queue = result.catch(() => {}); return result; };
const ko = () => (config?.locale || 'ko') === 'ko';
const tr = (k, e) => ko() ? k : e;
const runtime = new DesktopRuntime({ profile, backend, version, onExit: () => {
  serial(async () => { await runtime.stop(); if (consoleWindow && !consoleWindow.isDestroyed()) consoleWindow.hide(); showSettings(); dialog.showErrorBox('AidotVPN Desktop', tr('서버가 종료되었습니다. 설정 창의 로그 폴더에서 원인을 확인하세요.', 'A packaged server stopped. Open the logs folder from Desktop settings.')); });
} });
function secureWindow(win, allow) {
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (event, url) => { if (!allow(url)) event.preventDefault(); });
  win.webContents.on('will-redirect', (event, url) => { if (!allow(url)) event.preventDefault(); });
  win.webContents.on('will-attach-webview', event => event.preventDefault());
  win.on('close', event => { if (!quitting) { event.preventDefault(); win.hide(); } });
}
function showSettings() {
  if (settingsWindow && !settingsWindow.isDestroyed()) { settingsWindow.show(); settingsWindow.focus(); return; }
  settingsWindow = new BrowserWindow({ width: 780, height: 790, minWidth: 640, minHeight: 620, title: 'AidotVPN Desktop', icon, autoHideMenuBar: true, webPreferences: windowPreferences({ preload: path.join(__dirname, 'preload.cjs') }) });
  settingsWindow.setMenu(null);
  secureWindow(settingsWindow, url => url === SETTINGS_URL);
  settingsWindow.loadURL(SETTINGS_URL).catch(() => dialog.showErrorBox('AidotVPN Desktop', 'Desktop settings could not be loaded.'));
}
async function showConsole(settings = false) {
  if (!runtime.url) { showSettings(); return; }
  const url = runtime.url;
  if (!consoleWindow || consoleWindow.isDestroyed() || !sameOrigin(consoleWindow.webContents.getURL(), url)) {
    if (consoleWindow && !consoleWindow.isDestroyed()) consoleWindow.destroy();
    const partition = 'persist:aidot-console-' + createHash('sha256').update(url).digest('hex').slice(0, 16);
    const ses = session.fromPartition(partition);
    ses.setPermissionRequestHandler((contents, permission, callback) => callback(permission === 'clipboard-sanitized-write' && sameOrigin(contents?.getURL(), url)));
    ses.setPermissionCheckHandler((_contents, permission, origin) => permission === 'clipboard-sanitized-write' && sameOrigin(origin, url));
    consoleWindow = new BrowserWindow({ width: 1380, height: 900, minWidth: 960, minHeight: 680, title: 'AidotVPN', icon, autoHideMenuBar: true, webPreferences: windowPreferences({ partition }) });
    consoleWindow.setMenu(null);
    // The console has no preload bridge and never receives desktop filesystem/IPC privileges.
    secureWindow(consoleWindow, target => sameOrigin(target, url));
    consoleWindow.webContents.on('did-fail-load', (_event, code, _description, _url, isMainFrame) => {
      if (isMainFrame && code !== -3) { showSettings(); runtime.log('Console navigation failed (' + code + ')'); }
    });
    await consoleWindow.loadURL(url + (settings ? '/?settings=1' : '/'));
  } else if (settings) await consoleWindow.loadURL(url + '/?settings=1');
  consoleWindow.show(); consoleWindow.focus();
}
function menu() {
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: tr('콘솔 열기', 'Open console'), click: () => showConsole().catch(() => showSettings()) },
    { label: tr('콘솔 설정', 'Console settings'), click: () => showConsole(true).catch(() => showSettings()) },
    { label: tr('데스크톱 연결 설정', 'Desktop connection settings'), click: showSettings },
    { type: 'separator' },
    { label: tr('종료', 'Quit'), click: () => app.quit() }
  ]));
}
function installIPC() {
  const handle = (name, fn) => ipcMain.handle('desktop:' + name, async (event, input) => {
    assertSettingsSender(event, settingsWindow);
    try { return { ok: true, value: await fn(input) }; } catch (e) { return { ok: false, error: e.message }; }
  });
  handle('state', () => ({ version, config: config || normalizeConfig(), connected: Boolean(runtime.url), busy, profile }));
  handle('choose-env', async () => { const result = await dialog.showOpenDialog(settingsWindow, { properties: ['openFile'], title: tr('제어 서버 설정 파일 선택', 'Choose controller configuration'), filters: [{ name: 'Environment files', extensions: ['env'] }, { name: 'All files', extensions: ['*'] }] }); return result.canceled ? null : result.filePaths[0]; });
  handle('logs', async () => { const directory = path.join(profile, 'logs'); fs.mkdirSync(directory, { recursive: true }); const error = await shell.openPath(directory); if (error) throw Error(error); });
  handle('template', async () => {
    fs.mkdirSync(profile, { recursive: true });
    const source = app.isPackaged ? path.join(backend, 'controller.env.example') : path.resolve(__dirname, '../controller.env.example');
    const destination = path.join(profile, 'controller.env.example');
    if (!fs.existsSync(destination)) fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
    const error = await shell.openPath(profile); if (error) throw Error(error);
    return destination;
  });
  handle('apply', input => {
    const next = normalizeConfig(input);
    if (busy) throw Error('A desktop connection is already being changed.');
    busy = true;
    return serial(async () => {
      const previous = config;
      try {
        await runtime.stop();
        await runtime.start(next);
        await showConsole();
        if (app.isPackaged && !customProfile) app.setLoginItemSettings({ openAtLogin: next.autoStart, path: process.execPath, args: ['--hidden'] });
        atomicJSON(path.join(profile, 'desktop.json'), next);
        config = next; menu();
        settingsWindow?.hide();
        return { connected: true };
      } catch (e) {
        if (consoleWindow && !consoleWindow.isDestroyed()) consoleWindow.destroy();
        await runtime.stop();
        if (previous) { config = previous; try { await runtime.start(previous); await showConsole(); } catch {} }
        throw e;
      } finally { busy = false; }
    });
  });
}
app.on('window-all-closed', () => {});
app.on('second-instance', () => showConsole().catch(() => showSettings()));
app.on('activate', () => showConsole().catch(() => showSettings()));
app.on('before-quit', event => {
  if (quitting) return;
  event.preventDefault();
  serial(async () => { await runtime.stop(); quitting = true; tray?.destroy(); app.quit(); });
});
if (!app.requestSingleInstanceLock()) { quitting = true; app.quit(); }
else app.whenReady().then(async () => {
  const diagnostic = process.argv.indexOf('--diagnostics');
  if (diagnostic !== -1) {
    const output = process.argv[diagnostic + 1];
    if (!customProfile || !output || !path.isAbsolute(output)) throw Error('Diagnostics requires a separate AIDOTVPN_DESKTOP_PROFILE and an absolute output file.');
    const manifest = verifyBackend(backend, version);
    const runtimeConfigIndex = process.argv.indexOf('--runtime-config');
    const shutdownFile = runtimeConfigIndex === -1 ? null : path.join(profile, 'diagnostics-' + randomUUID() + '.shutdown');
    if (runtimeConfigIndex !== -1) {
      const file = process.argv[runtimeConfigIndex + 1];
      if (!file || !path.isAbsolute(file)) throw Error('Runtime verification requires an absolute configuration file.');
      await runtime.start(normalizeConfig(JSON.parse(fs.readFileSync(file, 'utf8'))));
    }
    atomicJSON(output, { success: true, version, electron: process.versions.electron, node: process.versions.node, chromium: process.versions.chrome, platform: process.platform, packaged: app.isPackaged, backendVersion: manifest.version, profile, renderer: windowPreferences(), url: runtime.url, childPids: runtime.children.map(child => child.pid), shutdownFile, scope: 'Packaged Electron main process and backend integrity; no visual UI test' });
    if (runtimeConfigIndex !== -1) {
      // Windows GUI executables may see stdin EOF even with an inherited pipe.
      // Use a per-run signal inside the explicitly isolated diagnostic profile.
      const timer = setInterval(() => {
        if (!fs.existsSync(shutdownFile)) return;
        clearInterval(timer); fs.rmSync(shutdownFile, { force: true }); app.quit();
      }, 200);
      app.once('will-quit', () => clearInterval(timer));
      return;
    }
    quitting = true; app.quit(); return;
  }
  session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  const assets = { '/settings.html': 'text/html; charset=utf-8', '/settings.js': 'text/javascript; charset=utf-8', '/settings.css': 'text/css; charset=utf-8', '/icon.svg': 'image/svg+xml' };
  protocol.handle('aidot-desktop', request => {
    const u = new URL(request.url);
    if (request.method !== 'GET' || u.hostname !== 'app' || u.username || u.password || !Object.hasOwn(assets, u.pathname)) return new Response('', { status: 404 });
    return new Response(fs.readFileSync(path.join(__dirname, 'ui', u.pathname.slice(1))), { headers: { 'Content-Type': assets[u.pathname], 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" } });
  });
  try { config = readSettings(profile); } catch { config = null; dialog.showErrorBox('AidotVPN Desktop', 'Desktop settings could not be read. The existing file was preserved.'); }
  tray = new Tray(icon); tray.setToolTip('AidotVPN Desktop'); tray.on('click', () => showConsole().catch(() => showSettings())); menu(); installIPC();
  if (!config) showSettings();
  else await serial(async () => {
    try { await runtime.start(config); if (!process.argv.includes('--hidden')) await showConsole(); }
    catch (error) { runtime.log('Startup failed'); showSettings(); dialog.showErrorBox('AidotVPN Desktop', error.message); }
  });
}).catch(async error => {
  runtime.log('Desktop initialization failed');
  await runtime.stop();
  const diagnostic = process.argv.indexOf('--diagnostics');
  const output = process.argv[diagnostic + 1];
  if (diagnostic !== -1 && customProfile) {
    if (output && path.isAbsolute(output)) atomicJSON(output, { success: false, version, error: error.message });
  } else dialog.showErrorBox('AidotVPN Desktop', error.message);
  quitting = true; app.exit(1);
});

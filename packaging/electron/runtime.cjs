'use strict';
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const { spawn } = require('node:child_process');
const { randomUUID, createHash } = require('node:crypto');
const { parseEnv } = require('node:util');
const { normalizeConfig, childEnvironment, consoleURL } = require('./security.cjs');
const BACKENDS = ['aidotvpn-console.exe', 'aidotvpn-controller.exe', 'aidotvpn-migrate.exe', 'aidotvpn-relay.exe'];
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
function atomicJSON(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temp = file + '.' + randomUUID() + '.tmp';
  try { fs.writeFileSync(temp, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 }); fs.renameSync(temp, file); }
  finally { fs.rmSync(temp, { force: true }); }
}
function readSettings(profile) {
  try { return normalizeConfig(JSON.parse(fs.readFileSync(path.join(profile, 'desktop.json'), 'utf8'))); }
  catch (e) { if (e.code === 'ENOENT') return null; throw e; }
}
function verifyBackend(directory, version, expectedEdition) {
  const manifest = JSON.parse(fs.readFileSync(path.join(directory, 'build-manifest.json'), 'utf8'));
  if (manifest.version !== version || manifest.platform !== 'win32' || manifest.arch !== 'x64') throw Error('Rebuild Windows server binaries for this desktop version.');
  if (expectedEdition && manifest.edition !== expectedEdition) throw Error('Server edition does not match the desktop source edition.');
  for (const name of BACKENDS) {
    const file = path.join(directory, name);
    if (fs.lstatSync(file).isSymbolicLink() || createHash('sha256').update(fs.readFileSync(file)).digest('hex') !== manifest.hashes[name]) throw Error('Server binary integrity check failed: ' + name);
  }
  return manifest;
}
async function availablePort(port, host = '127.0.0.1') {
  // Windows may allow a wildcard bind alongside an occupied specific address.
  // Check the address the child uses as well as the wildcard listener.
  for (const address of new Set([host, host.includes(':') ? '::' : '0.0.0.0'])) await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', () => reject(Error(`Port ${port} is already in use. Choose a different port or connect to the existing console.`)));
    server.listen({ port, host: address, exclusive: true }, () => server.close(resolve));
  });
}
function probe(url, pathname = '/healthz') {
  return new Promise((resolve, reject) => {
    const target = new URL(pathname, consoleURL(url));
    const options = { timeout: 2500, rejectUnauthorized: true };
    if (target.protocol === 'https:') options.ca = [...tls.getCACertificates('bundled'), ...tls.getCACertificates('system')];
    const req = (target.protocol === 'https:' ? https : http).get(target, options, res => { res.resume(); res.on('end', () => res.statusCode === 200 ? resolve() : reject(Error('Server is not ready (HTTP ' + res.statusCode + ').'))); });
    req.on('error', reject); req.on('timeout', () => req.destroy(Error('Server readiness timed out.')));
  });
}
class DesktopRuntime {
  constructor({ profile, backend, version, onExit = () => {} }) { Object.assign(this, { profile, backend, version, onExit }); this.children = []; this.stopping = false; this.url = null; }
  log(message) {
    const dir = path.join(this.profile, 'logs'); fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, 'desktop.log');
    if (fs.existsSync(file) && fs.statSync(file).size > 2 * 1024 * 1024) fs.renameSync(file, file + '.previous');
    fs.appendFileSync(file, new Date().toISOString() + ' ' + message + '\n');
  }
  startChild(name, args, env, cwd) {
    const logdir = path.join(this.profile, 'logs'); fs.mkdirSync(logdir, { recursive: true });
    const logfile = path.join(logdir, name + '.log');
    if (fs.existsSync(logfile) && fs.statSync(logfile).size > 10 * 1024 * 1024) fs.renameSync(logfile, logfile + '.previous');
    const fd = fs.openSync(logfile, 'a');
    let child;
    try { child = spawn(path.join(this.backend, name + '.exe'), args, { cwd, env, windowsHide: true, stdio: ['pipe', fd, fd], shell: false }); }
    finally { fs.closeSync(fd); }
    child.stdin.on('error', () => {});
    child.done = new Promise(resolve => { child.once('error', error => { child.startError = error; resolve(); }); child.once('exit', resolve); });
    child.once('exit', code => { this.log(`${name} exited (${code})`); if (!this.stopping && this.url) this.onExit(name); });
    this.children.push(child); return child;
  }
  async waitReady(child, url, pathname, descriptor) {
    const until = Date.now() + 45000;
    while (Date.now() < until) {
      if (child.startError || child.exitCode !== null || child.signalCode !== null) throw Error('The packaged server stopped before it was ready. Open the logs folder for details.');
      try { if (descriptor && !fs.existsSync(descriptor)) throw Error('Starting'); await probe(url, pathname); return; } catch {}
      await sleep(150);
    }
    throw Error('The packaged server did not become ready. Check its configuration and logs.');
  }
  async start(input) {
    if (this.children.length || this.url) throw Error('Stop the current desktop connection before changing its settings.');
    const cfg = normalizeConfig(input); this.stopping = false;
    if (cfg.mode === 'connect') { await probe(cfg.consoleURL); this.url = cfg.consoleURL; return this.url; }
    verifyBackend(this.backend, this.version);
    const base = path.join(this.profile, 'server'); fs.mkdirSync(base, { recursive: true });
    await availablePort(cfg.localPort);
    try {
      if (cfg.startController) {
        if (fs.statSync(cfg.controllerEnv).size > 1024 * 1024) throw Error('The controller configuration file is too large.');
        const envFile = fs.readFileSync(cfg.controllerEnv, 'utf8');
        const values = parseEnv(envFile.replace(/^\uFEFF/, ''));
        const listen = values.CONTROLLER_HTTP_LISTEN || '127.0.0.1:10030';
        const controller = new URL(cfg.controllerURL);
        const port = Number(listen.slice(listen.lastIndexOf(':') + 1));
        if (!Number.isInteger(port) || port < 1024 || port > 65535 || port !== Number(controller.port || (controller.protocol === 'https:' ? 443 : 80)) || controller.protocol !== 'http:') throw Error('Match the local controller URL to CONTROLLER_HTTP_LISTEN (HTTP loopback).');
        await availablePort(port, controller.hostname.replace(/^\[|\]$/g, ''));
        const env = { ...childEnvironment(), AIDOTVPN_ENV_FILE: cfg.controllerEnv, AIDOTVPN_SERVICE_STDIN: '1' };
        const child = this.startChild('aidotvpn-controller', [], env, base);
        await this.waitReady(child, cfg.controllerURL, '/readyz');
      }
      const data = path.join(base, 'console'), config = path.join(data, 'config');
      fs.mkdirSync(config, { recursive: true });
      const url = `http://127.0.0.1:${cfg.localPort}`;
      atomicJSON(path.join(config, 'console.json'), { bindHost: '127.0.0.1', port: cfg.localPort, controllerURL: cfg.controllerURL, publicURL: url, https: { enabled: false, certFile: '', keyFile: '' } });
      const descriptor = path.join(base, 'endpoint-' + randomUUID() + '.json');
      this.descriptor = descriptor;
      const env = { ...childEnvironment(), NODE_USE_SYSTEM_CA: '1', AIDOTVPN_SCOPE: 'user', AIDOTVPN_DATA_DIR: data, AIDOTVPN_CONFIG_DIR: config, AIDOTVPN_CONSOLE_ENV_FILE: path.join(config, 'desktop-managed.env'), AIDOTVPN_ENDPOINT_FILE: descriptor, AIDOTVPN_SERVICE_STDIN: '1', CONSOLE_BIND_HOST: '127.0.0.1', CONSOLE_PORT: String(cfg.localPort), CONSOLE_PUBLIC_URL: url, CONSOLE_HTTPS_ENABLED: 'false' };
      // This internal loopback listener is owned by Desktop. Existing service settings are separate.
      fs.writeFileSync(env.AIDOTVPN_CONSOLE_ENV_FILE, '# Managed by AidotVPN Desktop.\n', { mode: 0o600 });
      const child = this.startChild('aidotvpn-console', [], env, base);
      await this.waitReady(child, url, '/healthz', descriptor);
      this.url = url; this.log('Packaged server is ready'); return url;
    } catch (error) { await this.stop(); throw error; }
  }
  async stop() {
    this.stopping = true; this.url = null;
    for (const child of [...this.children].reverse()) {
      if (child.exitCode !== null || child.signalCode !== null || child.startError) continue;
      child.stdin.end('shutdown\n');
      let timeout;
      await Promise.race([child.done, new Promise(resolve => { timeout = setTimeout(resolve, 17000); })]); clearTimeout(timeout);
      if (child.exitCode === null && child.signalCode === null && !child.startError) { child.kill(); await child.done; }
    }
    this.children = [];
    if (this.descriptor) fs.rmSync(this.descriptor, { force: true });
  }
}
module.exports = { DesktopRuntime, BACKENDS, atomicJSON, readSettings, verifyBackend, availablePort, probe };

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
const directory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const root = path.resolve(directory, '../..');
const require = createRequire(path.join(directory, 'package.json'));
const { getCurrentFuseWire, FuseV1Options, FuseState } = require('@electron/fuses');
const { verifyBackend } = require('./runtime.cjs');
const pkg = require('./package.json');
if (process.platform !== 'win32') throw Error('Run the packaged Electron smoke check on Windows.');
const built = path.join(root, 'dist', pkg.version, 'electron', 'win-unpacked');
const exe = path.join(built, 'AidotVPN-Desktop.exe');
verifyBackend(path.join(built, 'resources/backend'), pkg.version);
const fuses = await getCurrentFuseWire(exe);
for (const option of [FuseV1Options.RunAsNode, FuseV1Options.EnableNodeOptionsEnvironmentVariable, FuseV1Options.EnableNodeCliInspectArguments, FuseV1Options.GrantFileProtocolExtraPrivileges]) assert.equal(fuses[option], FuseState.DISABLE, 'An unsafe Electron fuse is enabled');
for (const option of [FuseV1Options.EnableCookieEncryption, FuseV1Options.EnableEmbeddedAsarIntegrityValidation, FuseV1Options.OnlyLoadAppFromAsar]) assert.equal(fuses[option], FuseState.ENABLE, 'A required Electron protection is missing');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'aidot-desktop-한글-'));
const output = path.join(work, 'diagnostics.json');
const profile = path.join(work, 'isolated profile');
fs.mkdirSync(profile);
const env = { ...process.env, AIDOTVPN_DESKTOP_PROFILE: profile, ELECTRON_RUN_AS_NODE: '1', NODE_OPTIONS: '--require=' + path.join(work, 'must-not-load.cjs') };
let child;
try {
  child = spawn(exe, ['--diagnostics', output], { env, cwd: work, windowsHide: true, stdio: 'ignore' });
  const exit = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(Error('Electron diagnostics timed out.')); }, 45000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); resolve(code); });
  });
  assert.equal(exit, 0);
  const result = JSON.parse(fs.readFileSync(output, 'utf8'));
  assert.equal(result.success, true); assert.equal(result.packaged, true);
  assert.equal(result.version, pkg.version); assert.equal(result.backendVersion, pkg.version);
  assert.equal(result.electron, pkg.devDependencies.electron);
  assert.equal(result.profile, profile); assert.equal(result.renderer.sandbox, true); assert.equal(result.renderer.nodeIntegration, false);
  const evidence = { success: true, version: pkg.version, electron: result.electron, checks: ['Windows backend hash and version match', 'Electron fuses verified in the Windows executable', 'Packaged Electron main process starts', 'Inherited NODE_OPTIONS and ELECTRON_RUN_AS_NODE are ineffective', 'Separate Unicode profile path', 'Diagnostic process exits cleanly'], scope: 'Windows packaged main process and integrity; no visual UI or installer lifecycle test' };
  fs.writeFileSync(path.join(root, 'dist', pkg.version, 'electron', 'windows-smoke-results.json'), JSON.stringify(evidence, null, 2) + '\n');
  console.log(JSON.stringify(evidence, null, 2));
} finally {
  if (child && child.exitCode === null && child.signalCode === null) child.kill();
  fs.rmSync(work, { recursive: true, force: true });
}

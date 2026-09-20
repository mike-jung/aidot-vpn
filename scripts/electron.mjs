import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { assertBuildHost } from './toolchain.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const electron = path.join(root, 'packaging/electron');
const args = process.argv.slice(2);
if (args.some(a => !['--dir', '--dev', '--reuse-backend'].includes(a))) throw Error('Supported options: --dir, --dev, --reuse-backend');
if (process.platform !== 'win32' || process.arch !== 'x64') throw Error('Build the Windows Electron installer on Windows x64.');
// The bundled SEA server uses the downloaded pinned runtime; Electron ships its own runtime.
assertBuildHost();
const npm = path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js');
if (!fs.existsSync(npm)) throw Error('The matching npm CLI was not found next to Node.');
function run(command, argv, cwd = root) {
  const result = spawnSync(command, argv, { cwd, stdio: 'inherit', env: process.env, shell: false });
  if (result.error) throw result.error;
  if (result.status !== 0) throw Error(`${path.basename(command)} failed (${result.status}).`);
}
function npmRun(argv, cwd) { run(process.execPath, [npm, ...argv], cwd); }
if (!args.includes('--reuse-backend')) {
  npmRun(['ci'], path.join(root, 'console'));
  npmRun(['ci', '--ignore-scripts'], path.join(root, 'packaging'));
  run(process.execPath, ['packaging/build.mjs']);
}
// Verify reused binaries too; an old or edited backend never enters an installer.
const { verifyBackend } = await import('../packaging/electron/runtime.cjs');
const version = fs.readFileSync(path.join(root, 'VERSION'), 'utf8').trim();
const edition = JSON.parse(fs.readFileSync(path.join(root, 'package.json'))).aidotEdition;
verifyBackend(path.join(root, 'packaging/out/win32-x64'), version, edition);
npmRun(['ci', '--ignore-scripts'], electron);
run(process.execPath, ['node_modules/electron/install.js'], electron);
run(process.execPath, ['--test', 'packaging/electron/tests/security.test.cjs']);
if (args.includes('--dev')) {
  run(path.join(electron, 'node_modules/electron/dist/electron.exe'), [electron]);
} else {
  run(process.execPath, ['node_modules/electron-builder/out/cli/cli.js', '--win', '--x64', ...(args.includes('--dir') ? ['--dir'] : []), '--publish', 'never', '--config', 'builder.cjs'], electron);
  const output = path.join(root, 'dist', version, 'electron');
  if (!args.includes('--dir')) {
    const file = `AidotVPN-Desktop-${version}-windows-x64-setup.exe`;
    const bytes = fs.readFileSync(path.join(output, file));
    const metadata = { version, edition, file, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), electron: JSON.parse(fs.readFileSync(path.join(electron, 'package.json'))).devDependencies.electron, signing: 'Verify Authenticode before public distribution', kind: 'Electron + NSIS with bundled SEA and Go server' };
    fs.writeFileSync(path.join(output, 'desktop-build-manifest.json'), JSON.stringify(metadata, null, 2) + '\n');
    console.log(`Installer: ${path.join(output, file)}`);
  }
}

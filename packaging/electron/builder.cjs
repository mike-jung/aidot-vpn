'use strict';
const path = require('node:path');
const fs = require('node:fs');
const { BACKENDS, verifyBackend } = require('./runtime.cjs');
const directory = __dirname;
const root = path.resolve(directory, '../..');
const pkg = require('./package.json');
const edition = JSON.parse(fs.readFileSync(path.join(root, 'package.json'))).aidotEdition;
const APP_FILES = Object.freeze(['package.json', 'main.cjs', 'preload.cjs', 'runtime.cjs', 'security.cjs', 'ui/settings.html', 'ui/settings.js', 'ui/settings.css', 'ui/icon.svg']);
module.exports = {
  appId: 'com.aidotvpn.desktop', productName: 'AidotVPN Desktop', executableName: 'AidotVPN-Desktop',
  copyright: 'Copyright © 2026 AidotVPN',
  directories: { app: directory, output: path.join(root, 'dist', pkg.version, 'electron'), buildResources: path.resolve(directory, '../windows') },
  files: [...APP_FILES], asar: true, npmRebuild: false,
  extraResources: [
    { from: path.resolve(directory, '../out/win32-x64'), to: 'backend', filter: [...BACKENDS, 'build-manifest.json', 'THIRD-PARTY-NOTICES.txt'] },
    { from: path.resolve(directory, '../controller.env.example'), to: 'backend/controller.env.example' },
    { from: path.resolve(directory, '../windows/aidotvpn.ico'), to: 'aidotvpn.ico' }
  ],
  win: { target: [{ target: 'nsis', arch: ['x64'] }], icon: path.resolve(directory, '../windows/aidotvpn.ico'), artifactName: 'AidotVPN-Desktop-${version}-windows-${arch}-setup.${ext}', requestedExecutionLevel: 'asInvoker' },
  nsis: { guid: 'f1d0fa3a-1c4e-4a9f-99e3-9a02f035c81c', oneClick: false, perMachine: false, allowElevation: false, allowToChangeInstallationDirectory: true, createDesktopShortcut: true, createStartMenuShortcut: true, shortcutName: 'AidotVPN Desktop', deleteAppDataOnUninstall: false, runAfterFinish: true, differentialPackage: false, installerLanguages: ['en_US', 'ko_KR'], displayLanguageSelector: true },
  beforePack: async () => {
    const version = fs.readFileSync(path.join(root, 'VERSION'), 'utf8').trim();
    if (version !== pkg.version) throw Error('Desktop and project versions must match.');
    verifyBackend(path.resolve(directory, '../out/win32-x64'), version, edition);
    for (const file of APP_FILES) if (fs.lstatSync(path.join(directory, file)).isSymbolicLink()) throw Error('Symbolic links cannot be packaged.');
  },
  afterPack: async context => {
    const binary = path.join(context.appOutDir, 'AidotVPN-Desktop.exe');
    const { flipFuses, FuseVersion, FuseV1Options } = require('@electron/fuses');
    await flipFuses(binary, { version: FuseVersion.V1,
      [FuseV1Options.RunAsNode]: false,
      [FuseV1Options.EnableCookieEncryption]: true,
      [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
      [FuseV1Options.EnableNodeCliInspectArguments]: false,
      [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
      [FuseV1Options.OnlyLoadAppFromAsar]: true,
      [FuseV1Options.GrantFileProtocolExtraPrivileges]: false
    });
    const { listPackage } = require('@electron/asar');
    const packed = listPackage(path.join(context.appOutDir, 'resources/app.asar')).map(p => p.replace(/^[\\/]+/, '').replaceAll('\\', '/')).filter(p => p && !['ui'].includes(p));
    if (packed.length !== APP_FILES.length || packed.some(p => !APP_FILES.includes(p))) throw Error('Unexpected file in the desktop ASAR: ' + packed.filter(p => !APP_FILES.includes(p)).join(', '));
    verifyBackend(path.join(context.appOutDir, 'resources/backend'), pkg.version, edition);
  }
};

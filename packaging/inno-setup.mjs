// SPDX-License-Identifier: Apache-2.0
// Obtains the Inno Setup compiler that assembles the Windows installer.
//
// Inno Setup publishes no machine-readable checksum feed, so the release, its download URL and its
// SHA-256 are pinned in packaging/build-tools.json; the digest there is the one Microsoft's
// winget-pkgs manifest records for the same file. The installer is then run in PORTABLE mode:
// jrsoftware/issrc at tag is-6_5_3 sets `Uninstallable=not PortableCheck` in setup.iss and skips the
// Start Menu group, the desktop icon and the .iss file association, so nothing is written outside the
// directory below — no uninstall entry, no file associations, no machine-wide state.
//
// Environment overrides:
//   AIDOT_BUILD_ISCC          path to an ISCC.exe to use as-is; no download happens
//   AIDOT_BUILD_ISCC_ARCHIVE  path to an already-downloaded official installer; still checksum-verified
import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { acquireTool, packagingRoot, pinnedTool } from './tool-cache.mjs'

export const defaultCacheDir = path.join(packagingRoot, '.build-tools')

// /VERYSILENT runs with no window, /SP- drops the "this will install" prompt, /SUPPRESSMSGBOXES
// answers the remaining dialogs, /NORESTART keeps it from rebooting and /PORTABLE=1 makes the
// installation self-contained. /DIR decides where that self-contained copy goes.
export function installerArguments(destination) {
  return ['/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', '/PORTABLE=1', `/DIR=${destination}`]
}

export function compilerPath(home, pin) { return path.join(home, pin.directory, pin.compiler) }

// Returns {version, compiler, sha256, source}. Windows only: ISCC.exe is a Windows executable and
// scripts/dist.mjs already requires the Windows installer to be built on Windows.
export async function ensureInnoSetup({cacheDir = defaultCacheDir, env = process.env, log = console.log,
                                       platform = process.platform, pin = pinnedTool('innoSetup')} = {}) {
  if (env.AIDOT_BUILD_ISCC) {
    if (!fs.existsSync(env.AIDOT_BUILD_ISCC)) throw Error(`AIDOT_BUILD_ISCC points at ${env.AIDOT_BUILD_ISCC}, which does not exist`)
    log(`Inno Setup: using AIDOT_BUILD_ISCC (${env.AIDOT_BUILD_ISCC})`)
    return {version: null, compiler: env.AIDOT_BUILD_ISCC, sha256: null, source: 'AIDOT_BUILD_ISCC'}
  }
  if (platform !== 'win32') throw Error('The Inno Setup compiler runs on Windows; build the Windows installer on Windows x64.')

  const id = `inno-setup-${pin.version}`
  const ready = home => fs.existsSync(compilerPath(home, pin))
  const result = await acquireTool({
    id, cacheDir, fileName: pin.file, url: pin.url, digest: pin.sha256,
    digestSource: `packaging/build-tools.json (${pin.digestSource})`,
    localArchive: env.AIDOT_BUILD_ISCC_ARCHIVE, localArchiveLabel: 'AIDOT_BUILD_ISCC_ARCHIVE',
    ready, log, label: `Inno Setup ${pin.version}`,
    install: ({archivePath, home}) => {
      const destination = path.join(home, pin.directory)
      log(`Inno Setup ${pin.version}: installing portable copy into ${destination}`)
      execFileSync(archivePath, installerArguments(destination), {stdio: 'inherit'})
    }
  })
  return {version: pin.version, compiler: compilerPath(result.home, pin), sha256: result.sha256, source: result.source}
}

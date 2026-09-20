// SPDX-License-Identifier: Apache-2.0
// Obtains the exact Node runtime this release ships, instead of requiring it on the build machine.
//
// The installer embeds a Node binary and bytecode that only that binary can load, so the two must
// come from the same Node version. Reading them off the developer's PATH made every build machine
// carry an exact Node install. This module downloads the pinned distribution from nodejs.org,
// verifies its SHA-256 against the official SHASUMS256.txt, caches it under packaging/.build-tools,
// and hands back the binary plus its matching LICENSE. The build machine's own Node only has to be
// new enough to run the build scripts.
//
// Environment overrides, for build machines without direct access to nodejs.org:
//   AIDOT_BUILD_NODE_MIRROR   base URL holding the v<version>/ directories (default https://nodejs.org/dist)
//   AIDOT_BUILD_NODE_ARCHIVE  path to an already-downloaded official archive; still checksum-verified
//   AIDOT_BUILD_NODE_SHA256   expected digest, used instead of fetching SHASUMS256.txt
// None of these relax verification. A digest that does not match aborts the build.
import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { acquireTool, extractArchive, fetchText, normalizeDigest, packagingRoot } from './tool-cache.mjs'

export const defaultMirror = 'https://nodejs.org/dist'
export const defaultCacheDir = path.join(packagingRoot, '.build-tools')
export { packagingRoot }

// Describes one official distribution artifact. The names match nodejs.org/dist exactly, because the
// SHASUMS256.txt entries are keyed by these names.
export function artifactFor(platform, arch, version) {
  if (arch !== 'x64') throw Error(`This release packages x64 only; asked for ${arch}`)
  if (platform === 'win32') {
    const base = `node-v${version}-win-x64`
    return {id: `node-${version}-win32-x64`, archive: `${base}.zip`, format: 'zip', directory: base, executable: 'node.exe', license: 'LICENSE'}
  }
  if (platform === 'linux') {
    const base = `node-v${version}-linux-x64`
    return {id: `node-${version}-linux-x64`, archive: `${base}.tar.xz`, format: 'tar.xz', directory: base, executable: 'bin/node', license: 'LICENSE'}
  }
  throw Error(`This release packages Linux and Windows only; asked for ${platform}`)
}

// SHASUMS256.txt is "<64 hex>  <name>" per line; names may contain a directory prefix.
export function parseShasums(text) {
  const sums = new Map()
  for (const line of text.split('\n')) {
    const match = /^([a-f0-9]{64}) [ *](.+?)\r?$/.exec(line)
    if (match) sums.set(match[2], match[1])
  }
  if (!sums.size) throw Error('SHASUMS256.txt held no usable checksum lines')
  return sums
}

export async function expectedDigest(artifact, {version, mirror, env = process.env, fetchText: read = fetchText}) {
  if (env.AIDOT_BUILD_NODE_SHA256) return {digest: normalizeDigest(env.AIDOT_BUILD_NODE_SHA256, 'AIDOT_BUILD_NODE_SHA256'), source: 'AIDOT_BUILD_NODE_SHA256'}
  const url = `${mirror}/v${version}/SHASUMS256.txt`
  const digest = parseShasums(await read(url)).get(artifact.archive)
  if (!digest) throw Error(`${url} has no entry for ${artifact.archive}. Check that Node ${version} publishes this artifact.`)
  return {digest, source: url}
}

// Builds are native-OS only, so the downloaded runtime must run here and report the pinned version.
export function verifyReports(execPath, version, platform) {
  if (platform !== process.platform) return
  const reported = execFileSync(execPath, ['--version'], {encoding: 'utf8'}).trim()
  if (reported !== `v${version}`) throw Error(`The downloaded runtime reports ${reported} instead of v${version}`)
}

// Returns {version, execPath, licensePath, sha256, source}. Throws rather than falling back to any
// other runtime: a mismatch here would ship a Node nobody verified.
export async function ensureNodeRuntime({version, platform = process.platform, arch = process.arch,
                                         cacheDir = defaultCacheDir, env = process.env, log = console.log,
                                         verify = verifyReports} = {}) {
  if (!/^\d+\.\d+\.\d+$/.test(version || '')) throw Error(`ensureNodeRuntime needs an exact version, got ${JSON.stringify(version)}`)
  const artifact = artifactFor(platform, arch, version)
  const mirror = (env.AIDOT_BUILD_NODE_MIRROR || defaultMirror).replace(/\/+$/, '')
  const paths = home => ({
    execPath: path.join(home, artifact.directory, artifact.executable),
    licensePath: path.join(home, artifact.directory, artifact.license)
  })
  const ready = home => {
    const {execPath, licensePath} = paths(home)
    return fs.existsSync(execPath) && fs.existsSync(licensePath)
  }

  let digest, digestSource
  const cachedMarker = path.join(cacheDir, artifact.id, 'tool.json')
  if (fs.existsSync(cachedMarker) && ready(path.join(cacheDir, artifact.id))) {
    ({sha256: digest, verifiedAgainst: digestSource} = JSON.parse(fs.readFileSync(cachedMarker, 'utf8')))
  } else {
    ({digest, source: digestSource} = await expectedDigest(artifact, {version, mirror, env}))
  }

  const result = await acquireTool({
    id: artifact.id, cacheDir, fileName: artifact.archive,
    url: `${mirror}/v${version}/${artifact.archive}`,
    digest, digestSource, localArchive: env.AIDOT_BUILD_NODE_ARCHIVE, localArchiveLabel: 'AIDOT_BUILD_NODE_ARCHIVE', ready, log,
    label: `Node ${version} runtime`,
    install: ({archivePath, home}) => extractArchive(archivePath, artifact.format, home)
  })
  const {execPath, licensePath} = paths(result.home)
  if (platform !== 'win32') fs.chmodSync(execPath, 0o755)
  verify(execPath, version, platform)
  return {version, execPath, licensePath, sha256: result.sha256, source: result.source}
}

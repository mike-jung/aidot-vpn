// SPDX-License-Identifier: Apache-2.0
// Obtains the exact Go toolchain the service binaries are built with.
//
// The version comes from the `toolchain` directive in server/go.mod, the same line the GitHub Actions
// workflow is checked against, so the compiler that produces controller/migrate/relay/gateway-agent
// is the one the project declares rather than whatever is on the build machine's PATH. The archive is
// downloaded from go.dev and checked against the SHA-256 that go.dev publishes for it.
//
// Environment overrides:
//   AIDOT_BUILD_GO          path to a go executable to use as-is; its version is still checked
//   AIDOT_BUILD_GO_MIRROR   base URL holding the release archives (default https://go.dev/dl)
//   AIDOT_BUILD_GO_ARCHIVE  path to an already-downloaded official archive; still checksum-verified
//   AIDOT_BUILD_GO_SHA256   expected digest, used instead of fetching the release index
import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { acquireTool, extractArchive, fetchText, normalizeDigest, packagingRoot, requiredGoVersion } from './tool-cache.mjs'

export const defaultMirror = 'https://go.dev/dl'
export const defaultCacheDir = path.join(packagingRoot, '.build-tools')
export { requiredGoVersion }

export function artifactFor(platform, arch, version) {
  if (arch !== 'x64') throw Error(`This release builds x64 only; asked for ${arch}`)
  if (platform === 'win32') return {id: `go-${version}-win32-x64`, archive: `go${version}.windows-amd64.zip`, format: 'zip', executable: 'go/bin/go.exe'}
  if (platform === 'linux') return {id: `go-${version}-linux-x64`, archive: `go${version}.linux-amd64.tar.gz`, format: 'tar.gz', executable: 'go/bin/go'}
  throw Error(`This release builds on Linux and Windows only; asked for ${platform}`)
}

// go.dev/dl?mode=json lists every release with a sha256 per downloadable file.
export function digestFromIndex(text, version, archive) {
  let releases
  try { releases = JSON.parse(text) } catch { throw Error('The Go release index was not valid JSON') }
  if (!Array.isArray(releases)) throw Error('The Go release index was not a list of releases')
  const release = releases.find(entry => entry.version === `go${version}`)
  if (!release) throw Error(`The Go release index has no entry for go${version}`)
  const file = (release.files || []).find(entry => entry.filename === archive)
  if (!file?.sha256) throw Error(`The Go release index has no sha256 for ${archive}`)
  return normalizeDigest(file.sha256, `sha256 for ${archive}`)
}

export async function expectedDigest(artifact, {version, mirror, env = process.env, fetchText: read = fetchText}) {
  if (env.AIDOT_BUILD_GO_SHA256) return {digest: normalizeDigest(env.AIDOT_BUILD_GO_SHA256, 'AIDOT_BUILD_GO_SHA256'), source: 'AIDOT_BUILD_GO_SHA256'}
  const url = `${mirror}/?mode=json&include=all`
  return {digest: digestFromIndex(await read(url), version, artifact.archive), source: url}
}

export function reportedVersion(execPath) {
  return execFileSync(execPath, ['version'], {encoding: 'utf8'}).trim()
}

export function verifyReports(execPath, version) {
  const reported = reportedVersion(execPath)
  if (!reported.startsWith(`go version go${version} `)) throw Error(`${execPath} reports "${reported}" instead of go${version}`)
}

// Returns {version, execPath, sha256, source}. An explicit AIDOT_BUILD_GO wins, and a matching Go
// already on PATH is used as-is; otherwise the pinned toolchain is downloaded. Every path ends with
// the same version assertion, so the build never silently compiles with a different compiler.
export async function ensureGoToolchain({version, platform = process.platform, arch = process.arch,
                                         cacheDir = defaultCacheDir, env = process.env, log = console.log,
                                         verify = verifyReports} = {}) {
  version ||= requiredGoVersion()
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw Error(`ensureGoToolchain needs an exact version, got ${JSON.stringify(version)}`)

  if (env.AIDOT_BUILD_GO) {
    verify(env.AIDOT_BUILD_GO, version)
    log(`Go ${version}: using AIDOT_BUILD_GO (${env.AIDOT_BUILD_GO})`)
    return {version, execPath: env.AIDOT_BUILD_GO, sha256: null, source: 'AIDOT_BUILD_GO'}
  }
  if (platform === process.platform) {
    try {
      verify('go', version)
      log(`Go ${version}: already on PATH (${reportedVersion('go')})`)
      return {version, execPath: 'go', sha256: null, source: 'PATH'}
    } catch { /* not present, or the wrong version: download the pinned toolchain below */ }
  }

  const artifact = artifactFor(platform, arch, version)
  const mirror = (env.AIDOT_BUILD_GO_MIRROR || defaultMirror).replace(/\/+$/, '')
  const execPathIn = home => path.join(home, ...artifact.executable.split('/'))
  const ready = home => fs.existsSync(execPathIn(home))

  let digest, digestSource
  const marker = path.join(cacheDir, artifact.id, 'tool.json')
  if (fs.existsSync(marker) && ready(path.join(cacheDir, artifact.id))) {
    ({sha256: digest, verifiedAgainst: digestSource} = JSON.parse(fs.readFileSync(marker, 'utf8')))
  } else {
    ({digest, source: digestSource} = await expectedDigest(artifact, {version, mirror, env}))
  }

  const result = await acquireTool({
    id: artifact.id, cacheDir, fileName: artifact.archive, url: `${mirror}/${artifact.archive}`,
    digest, digestSource, localArchive: env.AIDOT_BUILD_GO_ARCHIVE, localArchiveLabel: 'AIDOT_BUILD_GO_ARCHIVE',
    ready, log, label: `Go ${version} toolchain`,
    install: ({archivePath, home}) => extractArchive(archivePath, artifact.format, home)
  })
  const execPath = execPathIn(result.home)
  if (platform !== 'win32') fs.chmodSync(execPath, 0o755)
  if (platform === process.platform) verify(execPath, version)
  return {version, execPath, sha256: result.sha256, source: result.source}
}

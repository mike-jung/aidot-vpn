// SPDX-License-Identifier: Apache-2.0
// Shared plumbing for the pinned third-party build tools: download, verify, unpack, cache.
//
// The build needs three things it must not take from whatever happens to be on the build machine:
// the Node runtime that ends up inside the installer, the Go compiler that produces the service
// binaries, and the Inno Setup compiler that assembles the Windows installer. Each is pinned to one
// version, fetched from its official location, checked against a published SHA-256, and kept under
// packaging/. Nothing here falls back to another version: a digest that does not match stops the build.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'

export const packagingRoot = path.dirname(fileURLToPath(import.meta.url))
export const projectRoot = path.dirname(packagingRoot)

export const sha256 = buffer => createHash('sha256').update(buffer).digest('hex')

export async function fetchBuffer(url) {
  const response = await fetch(url, {redirect: 'follow'})
  if (!response.ok) throw Error(`${url} returned HTTP ${response.status}`)
  return Buffer.from(await response.arrayBuffer())
}
export const fetchText = async url => (await fetchBuffer(url)).toString('utf8')

export function normalizeDigest(value, label) {
  const digest = String(value || '').trim().toLowerCase()
  if (!/^[a-f0-9]{64}$/.test(digest)) throw Error(`${label} must be a 64 character hex SHA-256`)
  return digest
}

// The caller owns `destination` and has already emptied it; the archive itself may live there, so
// this must not wipe the directory on the way in.
export function extractArchive(archivePath, format, destination) {
  fs.mkdirSync(destination, {recursive: true})
  if (format === 'tar.xz' || format === 'tar.gz') {
    execFileSync('tar', [format === 'tar.xz' ? '-xJf' : '-xzf', archivePath, '-C', destination], {stdio: 'inherit'})
    return
  }
  if (format === 'zip') {
    // Expand-Archive ships with Windows PowerShell 5.1 and PowerShell 7, so a Windows build machine
    // needs no extra archiver.
    const command = `$ProgressPreference='SilentlyContinue'; Expand-Archive -LiteralPath ${JSON.stringify(archivePath)} -DestinationPath ${JSON.stringify(destination)} -Force`
    execFileSync(process.platform === 'win32' ? 'powershell.exe' : 'pwsh', ['-NoProfile', '-NonInteractive', '-Command', command], {stdio: 'inherit'})
    return
  }
  throw Error(`Unsupported archive format: ${format}`)
}

// Fetches `fileName` (or reads it from `localArchive`), checks it against `digest`, then hands the
// bytes to `install`, which lays the tool out inside a fresh cache directory. Returns that directory.
// A cache entry recorded by an earlier run is reused without touching the network.
export async function acquireTool({
  id, cacheDir, fileName, url, digest, digestSource, localArchive, localArchiveLabel = 'The supplied archive',
  install, ready, keepArchive = false, log = console.log, label = id
}) {
  const home = path.join(cacheDir, id)
  const marker = path.join(home, 'tool.json')
  const recorded = fs.existsSync(marker) ? JSON.parse(fs.readFileSync(marker, 'utf8')) : null
  if (recorded?.id === id && recorded.sha256 === digest && ready(home)) {
    log(`${label}: cached (${digest.slice(0, 12)}…)`)
    return {home, sha256: digest, source: 'cache'}
  }

  let bytes, origin
  if (localArchive) {
    origin = path.resolve(localArchive)
    if (path.basename(origin) !== fileName) throw Error(`${localArchiveLabel} must be ${fileName}, not ${path.basename(origin)}`)
    bytes = fs.readFileSync(origin)
  } else {
    origin = url
    log(`${label}: downloading ${origin}`)
    bytes = await fetchBuffer(origin)
  }
  const actual = sha256(bytes)
  if (actual !== digest) throw Error(`${fileName} failed verification.\n  expected ${digest} (from ${digestSource})\n  actual   ${actual}\nThe build stops here; nothing was installed.`)

  fs.rmSync(home, {recursive: true, force: true}); fs.mkdirSync(home, {recursive: true})
  const archivePath = path.join(home, fileName)
  fs.writeFileSync(archivePath, bytes)
  try {
    await install({archivePath, home})
  } finally {
    if (!keepArchive) fs.rmSync(archivePath, {force: true})
  }
  if (!ready(home)) throw Error(`${fileName} did not produce the expected layout under ${home}`)
  fs.writeFileSync(marker, JSON.stringify({id, file: fileName, sha256: actual, verifiedAgainst: digestSource}, null, 2) + '\n')
  log(`${label}: verified ${actual}`)
  return {home, sha256: actual, source: origin}
}

// Reads the Go toolchain this project builds with. server/go.mod is the single source, the same one
// the GitHub Actions workflow is checked against.
export function requiredGoVersion(root = projectRoot) {
  const text = fs.readFileSync(path.join(root, 'server/go.mod'), 'utf8')
  const version = /^toolchain go(\d+\.\d+\.\d+)$/m.exec(text)?.[1]
  if (!version) throw Error('server/go.mod has no "toolchain goX.Y.Z" directive to pin the Go build against')
  return version
}

// Pinned versions and digests for tools that publish no machine-readable checksum feed.
export function pinnedTool(name, root = projectRoot) {
  const pins = JSON.parse(fs.readFileSync(path.join(root, 'packaging/build-tools.json'), 'utf8'))
  const pin = pins[name]
  if (!pin) throw Error(`packaging/build-tools.json has no entry for ${name}`)
  return pin
}

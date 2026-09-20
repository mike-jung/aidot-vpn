// SPDX-License-Identifier: Apache-2.0
// The Windows installer is assembled by a pinned Inno Setup compiler and the service binaries by a
// pinned Go toolchain. These tests hold the line on where those come from: an official download whose
// SHA-256 matched, never whatever version a build machine happens to have, and never an archive that
// failed verification.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { requiredGoVersion, pinnedTool } from '../tool-cache.mjs'
import { artifactFor, digestFromIndex, expectedDigest, ensureGoToolchain, defaultMirror } from '../go-toolchain.mjs'
import { installerArguments, ensureInnoSetup } from '../inno-setup.mjs'

const FAKE = '99.0.0'
const scratch = () => fs.mkdtempSync(path.join(os.tmpdir(), 'aidot-build-tools-'))
// The stand-in below is not a real Go distribution, so these tests assert on the extracted file
// rather than letting the production check execute it.
const verify = execPath => { if (!fs.existsSync(execPath)) throw Error('missing toolchain binary') }

function stubGoArchive(directory) {
  const artifact = artifactFor('linux', 'x64', FAKE)
  const stage = path.join(directory, 'stage')
  const exe = path.join(stage, 'go', 'bin', 'go')
  fs.mkdirSync(path.dirname(exe), {recursive: true})
  fs.writeFileSync(exe, `#!/bin/sh\necho "go version go${FAKE} linux/amd64"\n`)
  fs.chmodSync(exe, 0o755)
  const archive = path.join(directory, artifact.archive)
  execFileSync('tar', ['-czf', archive, '-C', stage, 'go'])
  return {artifact, archive, sha256: createHash('sha256').update(fs.readFileSync(archive)).digest('hex')}
}

test('the Go version is taken from the toolchain directive in server/go.mod', () => {
  const version = requiredGoVersion()
  assert.match(version, /^\d+\.\d+\.\d+$/)
  assert.ok(fs.readFileSync(new URL('../../server/go.mod', import.meta.url), 'utf8').includes(`toolchain go${version}`))
})

test('Go archive names follow the official go.dev layout', () => {
  assert.equal(defaultMirror, 'https://go.dev/dl')
  assert.equal(artifactFor('win32', 'x64', '1.27.1').archive, 'go1.27.1.windows-amd64.zip')
  assert.equal(artifactFor('win32', 'x64', '1.27.1').executable, 'go/bin/go.exe')
  assert.equal(artifactFor('linux', 'x64', '1.27.1').archive, 'go1.27.1.linux-amd64.tar.gz')
  assert.equal(artifactFor('linux', 'x64', '1.27.1').executable, 'go/bin/go')
  assert.throws(() => artifactFor('linux', 'arm64', '1.27.1'), /x64 only/)
  assert.throws(() => artifactFor('darwin', 'x64', '1.27.1'), /Linux and Windows only/)
})

test('the Go release index supplies the digest, and says so when it cannot', () => {
  const digest = 'a'.repeat(64)
  const index = JSON.stringify([
    {version: 'go1.26.0', files: [{filename: 'go1.26.0.linux-amd64.tar.gz', sha256: 'b'.repeat(64)}]},
    {version: 'go1.27.1', files: [{filename: 'go1.27.1.windows-amd64.zip', sha256: 'c'.repeat(64)},
                                  {filename: 'go1.27.1.linux-amd64.tar.gz', sha256: digest}]}
  ])
  assert.equal(digestFromIndex(index, '1.27.1', 'go1.27.1.linux-amd64.tar.gz'), digest)
  assert.throws(() => digestFromIndex(index, '1.99.0', 'go1.99.0.linux-amd64.tar.gz'), /no entry for go1\.99\.0/)
  assert.throws(() => digestFromIndex(index, '1.27.1', 'go1.27.1.darwin-arm64.tar.gz'), /no sha256 for/)
  assert.throws(() => digestFromIndex('<html>', '1.27.1', 'x'), /not valid JSON/)
})

test('the digest is read from the published index, or from an explicit override', async () => {
  const artifact = artifactFor('linux', 'x64', '1.27.1')
  const digest = 'd'.repeat(64)
  const fetched = await expectedDigest(artifact, {
    version: '1.27.1', mirror: 'https://example.invalid/dl', env: {},
    fetchText: async url => {
      assert.equal(url, 'https://example.invalid/dl/?mode=json&include=all')
      return JSON.stringify([{version: 'go1.27.1', files: [{filename: artifact.archive, sha256: digest}]}])
    }
  })
  assert.equal(fetched.digest, digest)
  const pinned = await expectedDigest(artifact, {version: '1.27.1', mirror: defaultMirror, env: {AIDOT_BUILD_GO_SHA256: 'E'.repeat(64)}})
  assert.equal(pinned.digest, 'e'.repeat(64))
})

test('an explicit AIDOT_BUILD_GO is used as-is, but still version-checked', async () => {
  const seen = []
  const result = await ensureGoToolchain({
    version: FAKE, env: {AIDOT_BUILD_GO: '/opt/go/bin/go'}, log: () => {},
    verify: (execPath, version) => seen.push([execPath, version])
  })
  assert.equal(result.execPath, '/opt/go/bin/go')
  assert.deepEqual(seen, [['/opt/go/bin/go', FAKE]])
  await assert.rejects(ensureGoToolchain({
    version: FAKE, env: {AIDOT_BUILD_GO: '/opt/go/bin/go'}, log: () => {},
    verify: () => { throw Error('reports go1.0.0 instead') }
  }), /reports go1\.0\.0 instead/)
})

test('a verified Go archive is unpacked and reused from cache', {skip: process.platform === 'win32' ? 'stand-in archive is POSIX' : false}, async () => {
  const directory = scratch()
  try {
    const stub = stubGoArchive(directory)
    const cacheDir = path.join(directory, 'cache')
    const env = {AIDOT_BUILD_GO_ARCHIVE: stub.archive, AIDOT_BUILD_GO_SHA256: stub.sha256}
    const first = await ensureGoToolchain({version: FAKE, platform: 'linux', cacheDir, env, log: () => {}, verify})
    assert.equal(first.sha256, stub.sha256)
    assert.ok(fs.existsSync(first.execPath))
    assert.match(execFileSync(first.execPath, ['version'], {encoding: 'utf8'}), new RegExp(`go version go${FAKE}`))
    const second = await ensureGoToolchain({version: FAKE, platform: 'linux', cacheDir, env: {}, log: () => {}, verify})
    assert.equal(second.source, 'cache')
  } finally { fs.rmSync(directory, {recursive: true, force: true}) }
})

test('a Go archive whose digest does not match aborts and installs nothing', {skip: process.platform === 'win32' ? 'stand-in archive is POSIX' : false}, async () => {
  const directory = scratch()
  try {
    const stub = stubGoArchive(directory)
    const cacheDir = path.join(directory, 'cache')
    await assert.rejects(ensureGoToolchain({
      version: FAKE, platform: 'linux', cacheDir, log: () => {}, verify,
      env: {AIDOT_BUILD_GO_ARCHIVE: stub.archive, AIDOT_BUILD_GO_SHA256: 'f'.repeat(64)}
    }), /failed verification/)
    assert.ok(!fs.existsSync(path.join(cacheDir, `go-${FAKE}-linux-x64`, 'tool.json')))
  } finally { fs.rmSync(directory, {recursive: true, force: true}) }
})

test('Inno Setup is installed in portable mode, writing nothing machine-wide', () => {
  const args = installerArguments('D:\\build\\Inno Setup 6')
  assert.ok(args.includes('/PORTABLE=1'), 'portable mode leaves no uninstall entry or file association')
  assert.ok(args.includes('/VERYSILENT') && args.includes('/SUPPRESSMSGBOXES') && args.includes('/NORESTART') && args.includes('/SP-'))
  assert.ok(args.includes('/DIR=D:\\build\\Inno Setup 6'))
})

test('the pinned Inno Setup release carries a source for its digest', () => {
  const pin = pinnedTool('innoSetup')
  assert.match(pin.version, /^\d+\.\d+\.\d+$/)
  assert.match(pin.sha256, /^[a-f0-9]{64}$/)
  assert.ok(pin.url.startsWith('https://') && pin.url.endsWith(pin.file))
  assert.ok(pin.digestSource.includes('winget'), 'the digest must name where it was taken from')
})

test('an explicit AIDOT_BUILD_ISCC wins, and a missing one is reported', async () => {
  const directory = scratch()
  try {
    const iscc = path.join(directory, 'ISCC.exe')
    fs.writeFileSync(iscc, 'stand-in')
    const resolved = await ensureInnoSetup({env: {AIDOT_BUILD_ISCC: iscc}, log: () => {}, platform: 'linux'})
    assert.equal(resolved.compiler, iscc)
    await assert.rejects(ensureInnoSetup({env: {AIDOT_BUILD_ISCC: path.join(directory, 'nope.exe')}, log: () => {}}), /does not exist/)
    await assert.rejects(ensureInnoSetup({env: {}, log: () => {}, platform: 'linux'}), /runs on Windows/)
  } finally { fs.rmSync(directory, {recursive: true, force: true}) }
})

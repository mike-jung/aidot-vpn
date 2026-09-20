// SPDX-License-Identifier: Apache-2.0
// The installer embeds a Node binary. These tests hold the line on where it comes from: an official
// archive whose SHA-256 matched, extracted and executed before it is accepted — never the build
// machine's own Node, and never an archive that failed verification.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { artifactFor, parseShasums, expectedDigest, ensureNodeRuntime, defaultMirror } from '../node-runtime.mjs'

// The stand-in below is not a real node binary, so these tests assert on the extracted file directly
// instead of letting the production check execute it. The production default is exercised by a real
// build; see docs/verification-1.20.7-ko.md.
const verify = (execPath) => { if (!fs.existsSync(execPath)) throw Error('missing runtime binary') }

const FAKE = '99.0.0'
const scratch = () => fs.mkdtempSync(path.join(os.tmpdir(), 'aidot-node-runtime-'))

// Builds an archive shaped like the official distribution, holding a stand-in "node" that reports a
// version. Real distributions are too large to ship with the tests, and the code under test only
// cares about the layout, the digest and what the binary reports.
function stubArchive(directory) {
  const artifact = artifactFor(process.platform, 'x64', FAKE)
  const stage = path.join(directory, 'stage', artifact.directory)
  const exe = path.join(stage, artifact.executable)
  fs.mkdirSync(path.dirname(exe), {recursive: true})
  if (process.platform === 'win32') fs.writeFileSync(exe, `@echo off\r\necho v${FAKE}\r\n`)
  else { fs.writeFileSync(exe, `#!/bin/sh\necho v${FAKE}\n`); fs.chmodSync(exe, 0o755) }
  fs.writeFileSync(path.join(stage, artifact.license), 'Stand-in Node distribution licence\n')
  const archive = path.join(directory, artifact.archive)
  if (artifact.format === 'tar.xz') execFileSync('tar', ['-cJf', archive, '-C', path.join(directory, 'stage'), artifact.directory])
  else execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
    `$ProgressPreference='SilentlyContinue'; Compress-Archive -Path ${JSON.stringify(path.join(directory, 'stage', artifact.directory))} -DestinationPath ${JSON.stringify(archive)} -Force`])
  return {artifact, archive, sha256: createHash('sha256').update(fs.readFileSync(archive)).digest('hex')}
}

test('artifact names follow the official nodejs.org layout', () => {
  assert.equal(defaultMirror, 'https://nodejs.org/dist')
  const win = artifactFor('win32', 'x64', '24.19.0')
  assert.equal(win.archive, 'node-v24.19.0-win-x64.zip')
  assert.equal(path.posix.join(win.directory, win.executable), 'node-v24.19.0-win-x64/node.exe')
  const linux = artifactFor('linux', 'x64', '24.19.0')
  assert.equal(linux.archive, 'node-v24.19.0-linux-x64.tar.xz')
  assert.equal(path.posix.join(linux.directory, linux.executable), 'node-v24.19.0-linux-x64/bin/node')
  assert.throws(() => artifactFor('linux', 'arm64', '24.19.0'), /x64 only/)
  assert.throws(() => artifactFor('darwin', 'x64', '24.19.0'), /Linux and Windows only/)
})

test('SHASUMS256.txt parsing handles binary markers, CRLF and nested names', () => {
  const digest = 'a'.repeat(64), other = 'b'.repeat(64)
  const sums = parseShasums(`${digest}  node-v24.19.0-linux-x64.tar.xz\r\n${other} *win-x64/node.exe\n# comment\n\n`)
  assert.equal(sums.get('node-v24.19.0-linux-x64.tar.xz'), digest)
  assert.equal(sums.get('win-x64/node.exe'), other)
  assert.throws(() => parseShasums('not a checksum file'), /no usable checksum lines/)
})

test('the expected digest comes from SHASUMS256.txt, or from an explicit override', async () => {
  const artifact = artifactFor('linux', 'x64', '24.19.0')
  const digest = 'c'.repeat(64)
  const fetched = await expectedDigest(artifact, {
    version: '24.19.0', mirror: 'https://example.invalid/dist', env: {},
    fetchText: async url => {
      assert.equal(url, 'https://example.invalid/dist/v24.19.0/SHASUMS256.txt')
      return `${digest}  ${artifact.archive}\n`
    }
  })
  assert.equal(fetched.digest, digest)

  const pinned = await expectedDigest(artifact, {version: '24.19.0', mirror: defaultMirror, env: {AIDOT_BUILD_NODE_SHA256: 'D'.repeat(64)}})
  assert.equal(pinned.digest, 'd'.repeat(64), 'an explicit digest is normalised, not re-fetched')
  await assert.rejects(expectedDigest(artifact, {version: '24.19.0', mirror: defaultMirror, env: {AIDOT_BUILD_NODE_SHA256: 'nope'}}), /64 character hex/)

  await assert.rejects(expectedDigest(artifact, {
    version: '24.19.0', mirror: 'https://example.invalid/dist', env: {}, fetchText: async () => `${digest}  some-other-file.tar.xz\n`
  }), /no entry for/)
})

test('a verified archive is extracted, executed and reused from cache', async () => {
  const directory = scratch()
  try {
    const stub = stubArchive(directory)
    const cacheDir = path.join(directory, 'cache')
    const env = {AIDOT_BUILD_NODE_ARCHIVE: stub.archive, AIDOT_BUILD_NODE_SHA256: stub.sha256}
    const first = await ensureNodeRuntime({version: FAKE, cacheDir, env, log: () => {}, verify})
    assert.equal(first.sha256, stub.sha256)
    assert.ok(fs.existsSync(first.execPath), 'the runtime binary is extracted')
    assert.ok(fs.readFileSync(first.licensePath, 'utf8').includes('licence'), 'the matching LICENSE travels with it')
    if (process.platform !== 'win32') assert.equal(execFileSync(first.execPath, ['--version'], {encoding: 'utf8'}).trim(), `v${FAKE}`)

    // A second call must not need the archive at all.
    const second = await ensureNodeRuntime({version: FAKE, cacheDir, env: {}, log: () => {}, verify})
    assert.equal(second.source, 'cache')
    assert.equal(second.sha256, stub.sha256)
  } finally { fs.rmSync(directory, {recursive: true, force: true}) }
})

test('a digest that does not match aborts the build and installs nothing', async () => {
  const directory = scratch()
  try {
    const stub = stubArchive(directory)
    const cacheDir = path.join(directory, 'cache')
    await assert.rejects(
      ensureNodeRuntime({version: FAKE, cacheDir, log: () => {}, verify, env: {AIDOT_BUILD_NODE_ARCHIVE: stub.archive, AIDOT_BUILD_NODE_SHA256: 'f'.repeat(64)}}),
      /failed verification/)
    const home = path.join(cacheDir, `node-${FAKE}-${process.platform}-x64`)
    assert.ok(!fs.existsSync(path.join(home, 'tool.json')), 'a rejected download leaves no usable runtime behind')
  } finally { fs.rmSync(directory, {recursive: true, force: true}) }
})

test('an exact version is required, and the archive name must match the platform', async () => {
  await assert.rejects(ensureNodeRuntime({version: '24', log: () => {}, verify}), /exact version/)
  const directory = scratch()
  try {
    const decoy = path.join(directory, 'node-something-else.tar.xz')
    fs.writeFileSync(decoy, 'not an archive')
    await assert.rejects(ensureNodeRuntime({
      version: FAKE, cacheDir: path.join(directory, 'cache'), log: () => {}, verify,
      env: {AIDOT_BUILD_NODE_ARCHIVE: decoy, AIDOT_BUILD_NODE_SHA256: 'e'.repeat(64)}
    }), /AIDOT_BUILD_NODE_ARCHIVE must be/)
  } finally { fs.rmSync(directory, {recursive: true, force: true}) }
})

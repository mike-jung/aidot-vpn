// SPDX-License-Identifier: Apache-2.0
// Two different Node versions matter in this project, and they are deliberately not the same thing.
//
//  1. The SHIPPED runtime — `.node-version`. The installer embeds a Node binary plus bytecode that
//     only that exact binary can load, so this one is pinned to a single patch release. The build
//     downloads it from nodejs.org and verifies its checksum (packaging/node-runtime.mjs); it is NOT
//     taken from the build machine. CI reads the same file through node-version-file.
//
//  2. The BUILD HOST runtime — whatever Node runs these scripts. It only has to be new enough to run
//     them, so it is a floor (`engines.node` in the root package.json), not a pin. Nothing from the
//     build machine's Node ends up in the installer.
//
// Keeping the pin in one file is what stopped the two from drifting: before this, the same version
// number was typed out in six places, and correcting one of them left the rest disagreeing.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const projectRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
export const versionFileName = '.node-version'

export function versionFile(root = projectRoot) { return path.join(root, versionFileName) }

// The Node version the installer ships. Exact, by design.
export function requiredNodeVersion(root = projectRoot) {
  const file = versionFile(root)
  let text
  try { text = fs.readFileSync(file, 'utf8') }
  catch { throw Error(`${versionFileName} is missing at ${file}. It pins the Node runtime the installer embeds.`) }
  const version = text.replace(/^﻿/, '').trim().replace(/^v/, '')
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw Error(`${versionFileName} must hold one exact version such as 24.19.0, not ${JSON.stringify(version)}`)
  return version
}

// The minimum Node the build scripts themselves need, from the root package.json engines field.
export function minimumHostVersion(root = projectRoot) {
  const engines = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).engines?.node || ''
  const match = /^>=\s*(\d+\.\d+\.\d+)$/.exec(engines.trim())
  if (!match) throw Error(`package.json engines.node must read ">=X.Y.Z", not ${JSON.stringify(engines)}`)
  return match[1]
}

export function compareVersions(a, b) {
  const left = a.split('.').map(Number), right = b.split('.').map(Number)
  for (let i = 0; i < 3; i++) if (left[i] !== right[i]) return left[i] < right[i] ? -1 : 1
  return 0
}

// Checks the machine running the build scripts. The shipped runtime is downloaded separately, so a
// newer or older patch release here changes nothing about the installer.
export function assertBuildHost({ root = projectRoot, found = process.versions.node } = {}) {
  const minimum = minimumHostVersion(root)
  if (compareVersions(found, minimum) < 0) throw Error([
    `These build scripts need Node ${minimum} or newer. This machine runs ${found}.`,
    '',
    `The Node ${requiredNodeVersion(root)} that the installer embeds is downloaded and checksum-verified`,
    'by the build itself, so you do not need that exact version installed — only a recent enough Node',
    'to run the scripts. Update from https://nodejs.org and try again.',
    '',
    `[ko] 빌드 스크립트 실행에는 Node ${minimum} 이상이 필요합니다. 지금은 ${found} 입니다.`,
    '     설치본에 들어가는 Node 는 빌드가 직접 내려받아 검증하므로 PC 에 특정 버전을 깔 필요는 없습니다.'
  ].join('\n'))
  return found
}

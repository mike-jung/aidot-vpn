// SPDX-License-Identifier: Apache-2.0
// Prints the path to one pinned build tool, downloading and verifying it first if needed.
// packaging/windows/build.ps1 uses this to locate the Inno Setup compiler instead of hard-coding a
// Program Files path, so the Windows installer is always assembled by the pinned compiler.
//
//   node packaging/resolve-tool.mjs iscc
//   node packaging/resolve-tool.mjs go --out path.txt
//
// Progress goes to stderr and the resolved path to stdout, so a caller can capture one without the
// other. With --out the path is also written to that file, which is how the PowerShell build reads it
// without having to separate native stdout from native stderr.
import fs from 'node:fs'
import path from 'node:path'

const args = process.argv.slice(2)
const name = args[0]
const outIndex = args.indexOf('--out')
const outFile = outIndex === -1 ? null : args[outIndex + 1]
const log = message => console.error(message)

try {
  let resolved
  if (name === 'iscc') {
    const {ensureInnoSetup} = await import('./inno-setup.mjs')
    resolved = (await ensureInnoSetup({log})).compiler
  } else if (name === 'go') {
    const {ensureGoToolchain} = await import('./go-toolchain.mjs')
    resolved = (await ensureGoToolchain({log})).execPath
  } else {
    throw Error('Usage: node packaging/resolve-tool.mjs iscc|go [--out FILE]')
  }
  if (outFile) {
    fs.mkdirSync(path.dirname(path.resolve(outFile)), {recursive: true})
    fs.writeFileSync(outFile, resolved)
  }
  process.stdout.write(resolved + '\n')
} catch (error) {
  console.error(error.message)
  process.exit(1)
}

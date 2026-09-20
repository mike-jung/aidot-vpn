// SPDX-License-Identifier: Apache-2.0
// Compiles the bundled server to V8 bytecode using the runtime that will ship with the installer.
// build.mjs runs this with the downloaded Node binary, not with the build machine's Node, because
// bytecode is only loadable by the exact V8 that produced it.
const path = require('node:path')
const bytenode = require('bytenode')
const [input, output] = process.argv.slice(2)
if (!input || !output) throw Error('Usage: compile-bytecode.cjs <bundled.cjs> <output.jsc>')
bytenode.compileFile({filename: path.resolve(input), output: path.resolve(output), createLoader: false})
  .then(() => process.stdout.write(`bytecode compiled by ${process.version}\n`),
        error => { console.error(error); process.exit(1) })

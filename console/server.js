import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { startConsole } from './listener.js'
import { readSourceConfig } from './source-config.js'
const here = path.dirname(fileURLToPath(import.meta.url))
const { base, env, stateFile, certificateBaseDir } = readSourceConfig()
const running = await startConsole({
  base, env, stateFile, certificateBaseDir, distDir: path.join(here, 'dist'),
})
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => { await running.close(); process.exit(0) })

import { main } from './main.mjs'
main().catch(error => { console.error(`Startup failed: ${error.code || error.message}`); process.exitCode = 1 })

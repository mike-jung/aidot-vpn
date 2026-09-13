import path from 'node:path'
import { readSourceConfig } from '../console/source-config.js'
import { validateConfig } from '../console/listener-config.js'
const help = {
  certificate_paths_missing: 'No certificate/key is configured. Run npm run https:cert, then npm run check:https.',
  certificate_paths_must_be_absolute: 'Use a full Windows path (D:/certs/fullchain.pem) or a path relative to the selected .env file. Drive-relative paths such as D:cert.pem are invalid.',
  certificate_file_not_found: 'A configured certificate/key file does not exist. Check the paths in .env or run npm run https:cert to configure a local certificate.',
  certificate_file_not_readable: 'The certificate/key must be readable files for the account running the console.',
  certificate_hostname_mismatch: 'CONSOLE_PUBLIC_URL must match a certificate SAN. For a local certificate run npm run https:cert -- --url https://HOST:PORT --renew.',
  certificate_expired_or_not_yet_valid: 'Check the system clock and renew the certificate. For a generated local certificate: npm run https:cert -- --renew.',
}
try {
  if (process.argv.slice(2).some(a => a !== '--check')) throw Error('Use npm run start:https or npm run check:https')
  const { cfg, env, envFile, stateFile } = readSourceConfig({ forceHTTPS:true })
  const checked = validateConfig(cfg)
  Object.assign(process.env, env, {
    AIDOTVPN_CONSOLE_ENV_FILE:envFile, AIDOTVPN_DATA_DIR:path.dirname(stateFile),
    CONSOLE_HTTPS_ENABLED:'true', CONSOLE_PORT:String(cfg.port), CONSOLE_PUBLIC_URL:checked.url,
    CONSOLE_TLS_CERT_FILE:cfg.https.certFile, CONSOLE_TLS_KEY_FILE:cfg.https.keyFile,
  })
  console.log(`HTTPS configuration valid: ${checked.url}`)
  if (!process.argv.includes('--check')) await import('./start.mjs')
} catch (e) {
  console.error(`HTTPS startup failed: ${e.message}`)
  console.error(help[e.message] || 'Check CONSOLE_PUBLIC_URL, CONSOLE_TLS_CERT_FILE and CONSOLE_TLS_KEY_FILE in .env.')
  console.error('Guide: docs/https.md')
  process.exitCode = 1
}

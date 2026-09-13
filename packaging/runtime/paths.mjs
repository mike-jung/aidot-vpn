import path from 'node:path'
import os from 'node:os'
export function dataPaths(env = process.env, platform = process.platform, home = os.homedir()) {
  const p = platform === 'win32' ? path.win32 : path.posix
  const scope = env.AIDOTVPN_SCOPE || 'user'
  if (!['user', 'system'].includes(scope)) throw new Error('AIDOTVPN_SCOPE must be user or system')
  const base = env.AIDOTVPN_DATA_DIR || (platform === 'win32'
    ? p.join(scope === 'system' ? required(env.ProgramData, 'ProgramData') : required(env.LOCALAPPDATA, 'LOCALAPPDATA'), 'AidotVPN')
    : scope === 'system' ? '/var/lib/aidotvpn' : p.join(env.XDG_STATE_HOME || p.join(home, '.local/state'), 'aidotvpn'))
  const config = env.AIDOTVPN_CONFIG_DIR || (platform !== 'win32' && scope === 'system' ? '/etc/aidotvpn' : p.join(base, 'config'))
  for (const value of [base, config]) if (!p.isAbsolute(value)) throw new Error('Data/config paths must be absolute')
  return {scope, data: base, config, logs: p.join(base, 'logs'), exports: p.join(base, 'exports'), backups: p.join(base, 'backups')}
}
function required(value, name) { if (!value) throw new Error(`${name} is unavailable; set AIDOTVPN_DATA_DIR explicitly`); return value }

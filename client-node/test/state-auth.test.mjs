import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const cli = fileURLToPath(new URL('../aidot-client.mjs', import.meta.url));
test('CLI sends scoped token and refuses missing credentials without an HTTP request', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'aidot-state-auth-'));
  let requests = 0;
  const server = http.createServer((req, res) => {
    requests++;
    if (req.headers.authorization !== 'Bearer test-state-token') { res.writeHead(401); res.end('{}'); return; }
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ status: 'active', policy_bound: true, allowed_ips: ['10.78.0.1/32'] }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const state = { controller: `http://127.0.0.1:${server.address().port}`, deviceId: 'test', stateToken: 'test-state-token' };
  const run = (command = 'status') => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, command], { env: { ...process.env, AIDOT_STATE_DIR: dir } });
    let output = ''; child.stdout.on('data', b => output += b); child.stderr.on('data', b => output += b);
    child.on('error', reject); child.on('exit', code => resolve({ code, output }));
  });
  try {
    await fs.writeFile(path.join(dir, 'device.json'), JSON.stringify(state), { mode: 0o600 });
    const accepted = await run(); assert.equal(accepted.code, 0); assert.equal(requests, 1);
    assert.ok(!accepted.output.includes(state.stateToken));
    const saved = JSON.parse(await fs.readFile(path.join(dir, 'device.json'), 'utf8'));
    assert.deepEqual(saved.allowedIps, ['10.78.0.1/32']); assert.equal(saved.stateToken, state.stateToken);
    const shown = await run('show'); assert.equal(shown.code, 0);
    assert.ok(!shown.output.includes(state.stateToken)); assert.match(shown.output, /redacted/);
    delete state.stateToken;
    await fs.writeFile(path.join(dir, 'device.json'), JSON.stringify(state));
    const missing = await run(); assert.notEqual(missing.code, 0); assert.equal(requests, 1);
    assert.match(missing.output, /다시 enroll/);
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await fs.rm(dir, { recursive: true, force: true }); }
});

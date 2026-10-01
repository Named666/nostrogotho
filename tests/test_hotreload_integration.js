/**
 * Linux integration test for module replacement without dropping a socket.
 * Port of test_hotreload_integration.py.
 *
 * Starts a hot relay, connects a WebSocket, and publishes two module builds
 * while the same socket stays connected. Each publication must produce a
 * new loaded generation and the socket must still complete REQ/EOSE.
 *
 * Requires the Linux builder (build/nob_configed + build/main + .so module).
 * On other platforms it reports SKIP (exit 0).
 */
import { spawnSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { Conn, sleep, ROOT } from './relay.js';

const BUILD = path.join(ROOT, 'build');
const FILTER = { ids: ['f'.repeat(64)] };

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

function loadedGenerations(pid) {
  const prefix = `nhr_${pid}_`;
  try {
    const hits = fs.readdirSync(BUILD).filter((f) => f.startsWith(prefix) && f.endsWith('.so'));
    if (hits.length > 0) return new Set(hits);
  } catch {
    /* ignore */
  }
  if (process.platform === 'linux') {
    try {
      const maps = fs.readFileSync(`/proc/${pid}/maps`, 'utf8');
      const found = new Set();
      for (const line of maps.split('\n')) {
        const last = line.trim().split(' ').at(-1) ?? '';
        if (last.includes('nhr_') && last.endsWith('.so')) found.add(last);
      }
      if (found.size > 0) return found;
    } catch {
      /* ignore */
    }
  }
  return new Set();
}

async function waitForEose(conn, subId) {
  await conn.waitFor((m) => m[0] === 'EOSE' && m[1] === subId, 20000, `EOSE ${subId}`);
}

async function verifySocket(uri, relayProc, generations) {
  const conn = await Conn.open(uri, 10000);
  try {
    conn.sendJson(['REQ', 'before', FILTER]);
    await waitForEose(conn, 'before');
    for (let i = 0; i < 2; i++) {
      const r = spawnSync(path.join(BUILD, 'nob_configed'), ['-module-only'], {
        cwd: ROOT,
        stdio: 'ignore',
      });
      if (r.status !== 0) throw new Error('module-only rebuild failed');
      const deadline = Date.now() + 20000;
      for (;;) {
        const current = loadedGenerations(relayProc.pid);
        if (current.size > 0 && ![...current].every((g) => generations.has(g))) {
          generations = current;
          break;
        }
        if (Date.now() > deadline) throw new Error('host did not load a new module generation');
        await sleep(100);
      }
      const subId = `after-${i}`;
      conn.sendJson(['REQ', subId, FILTER]);
      await waitForEose(conn, subId);
    }
    console.log('PASS: two module publications preserved the WebSocket and query path');
  } finally {
    await conn.close();
  }
}

async function main() {
  if (os.platform() !== 'linux') {
    console.log('SKIP: this integration test requires the Linux builder');
    return;
  }
  for (const f of ['main', 'nob_configed', 'nostrogotho.so']) {
    if (!fs.existsSync(path.join(BUILD, f))) {
      console.log(`SKIP: build/${f} not found — run the Linux builder first`);
      return;
    }
  }
  const port = await freePort();
  const relay = spawn(
    path.join(BUILD, 'main'),
    ['--hot-reload', '--module', path.join(BUILD, 'nostrogotho.so'), '-port', String(port)],
    { cwd: ROOT, stdio: 'ignore' },
  );
  try {
    const uri = `ws://127.0.0.1:${port}`;
    const deadline = Date.now() + 10000;
    for (;;) {
      try {
        await new Promise((resolve, reject) => {
          const s = net.createConnection({ host: '127.0.0.1', port }, () => {
            s.end();
            resolve();
          });
          s.once('error', reject);
        });
        break;
      } catch {
        if (relay.exitCode !== null) throw new Error(`relay exited early: ${relay.exitCode}`);
        if (Date.now() > deadline) throw new Error('relay did not open its listener');
        await sleep(100);
      }
    }
    await verifySocket(uri, relay, loadedGenerations(relay.pid));
  } finally {
    relay.kill();
  }
}

main().catch((err) => {
  console.error(`FAIL: ${err.message}`);
  process.exit(1);
});

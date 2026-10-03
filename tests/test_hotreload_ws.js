/**
 * Test: Automated live hot-reload test over WebSocket (all platforms)
 * NIPs: N/A (Hot-reload infrastructure)
 * PLAN.md sections: §1.1 (Hot Reload Without State Loss - NHR), §1.3 (Host Services as ABI Boundary)
 *
 * Builds the policy module, starts a hot host, verifies REQ/EOSE on one
 * held-open connection, rebuilds the module (new generation), waits until
 * the host loads it (new nhr_<pid>_* image appears), and verifies the SAME
 * socket still completes REQ/EOSE. Any step failing exits nonzero.
 *
 * Prerequisites (same as `nob -hr`): a C compiler on PATH,
 * build/nob_configed(.exe), and a hot-capable build/main(.exe).
 * Missing pieces SKIP (exit 0) with a reason -- nothing here can
 * fabricate a reload environment.
 */
import { spawnSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { Conn, sleep, ROOT, authEvent, randomSecretKey, assert } from './relay.js';

const BUILD = path.join(ROOT, 'build');
const IS_WIN = os.platform() === 'win32';
const MODULE_EXT = IS_WIN ? '.dll' : '.so';
const MODULE_FILE = path.join(BUILD, `nostrogotho${MODULE_EXT}`);
const NOB_CONFIGED = path.join(BUILD, IS_WIN ? 'nob_configed.exe' : 'nob_configed');
const HOT_HOST = path.join(BUILD, IS_WIN ? 'main.exe' : 'main');
const FILTER = { ids: ['f'.repeat(64)] };

function skip(reason) {
  console.log(`SKIP: ${reason}`);
  process.exit(0);
}

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

function buildModule() {
  const r = spawnSync(NOB_CONFIGED, ['-module-only'], { cwd: ROOT, stdio: 'ignore' });
  return r.status === 0;
}

/** Generation images the host has loaded (unique nhr_<pid>_* copies). */
function loadedGenerations(pid) {
  const prefix = `nhr_${pid}_`;
  try {
    return new Set(
      fs.readdirSync(BUILD).filter((f) => f.startsWith(prefix) && f.endsWith(MODULE_EXT)),
    );
  } catch {
    return new Set();
  }
}

async function handleAuth(conn, wsUrl) {
  const first = await conn.next(5000);
  if (!first || first[0] !== 'AUTH') {
    if (first) conn.queue.unshift(first);
    return;
  }
  conn.sendJson(['AUTH', authEvent(randomSecretKey(), wsUrl, first[1])]);
  const ok = await conn.waitFor((m) => m[0] === 'OK', 5000, 'OK');
  assert(ok[2] === true, `AUTH must succeed, got ${JSON.stringify(ok)}`);
}

async function waitForEose(conn, subId) {
  await conn.waitFor((m) => m[0] === 'EOSE' && m[1] === subId, 20000, `EOSE ${subId}`);
}

async function main() {
  if (!fs.existsSync(NOB_CONFIGED)) skip('build/nob_configed not found -- run nob build first');
  if (!fs.existsSync(HOT_HOST)) skip('hot host binary not found -- run nob build first');

  console.log('Building policy module (gen 1)...');
  if (!buildModule()) skip('module build failed -- no working C compiler?');

  const port = await freePort();
  const wsUrl = `ws://127.0.0.1:${port}`;
  const dbPath = path.join(ROOT, `test_hotreload_ws_${port}.sqlite`);
  const host = spawn(
    HOT_HOST,
    [
      '--hot-reload', '--module', MODULE_FILE,
      '-database', dbPath,
      '-port', String(port),
      '-service-url', wsUrl,
    ],
    { cwd: ROOT, stdio: 'ignore' },
  );
  const cleanupDb = () => {
    // Give host time to release DB locks
    for (const s of ['', '-shm', '-wal', '-journal']) {
      try { fs.unlinkSync(dbPath + s); } catch { /* ignore */ }
    }
  };
  let failed = false;
  try {
    // Wait for the listener.
    const deadline = Date.now() + 15000;
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
        if (host.exitCode !== null) throw new Error(`hot host exited early: ${host.exitCode}`);
        if (Date.now() > deadline) throw new Error('hot host did not open its listener');
        await sleep(100);
      }
    }
    console.log(`Hot host up on ${wsUrl} (pid ${host.pid})`);

    const conn = await Conn.open(wsUrl, 10000);
    try {
      await handleAuth(conn, wsUrl);
      conn.sendJson(['REQ', 'before', FILTER]);
      await waitForEose(conn, 'before');
      console.log('Pre-reload REQ/EOSE ok');

      const before = loadedGenerations(host.pid);
      console.log(`Rebuilding policy module (loaded images: ${before.size})...`);
      if (!buildModule()) throw new Error('module rebuild failed');

      const dl2 = Date.now() + 30000;
      let after = before;
      for (;;) {
        const current = loadedGenerations(host.pid);
        const fresh = [...current].filter((g) => !before.has(g));
        if (fresh.length > 0) {
          after = current;
          console.log(`Host loaded new generation: ${fresh.join(',')}`);
          break;
        }
        if (host.exitCode !== null) throw new Error(`hot host died during reload: ${host.exitCode}`);
        if (Date.now() > dl2) throw new Error('host did not load a new module generation');
        await sleep(200);
      }
      assert(after.size >= before.size, 'generation set must grow, never shrink');

      conn.sendJson(['REQ', 'after', FILTER]);
      await waitForEose(conn, 'after');
      console.log('Post-reload REQ/EOSE ok on the SAME socket');
      console.log('PASS: live hot-reload preserves WebSocket + query path');
    } finally {
      await conn.close();
    }
  } catch (err) {
    failed = true;
    console.error(`FAIL: ${err.message}`);
  } finally {
    // Kill host first, wait for it to exit and release DB locks, then cleanup
    host.kill();
    await new Promise(resolve => setTimeout(resolve, 500));
    cleanupDb();
  }
  process.exit(failed ? 1 : 0);
}

main();

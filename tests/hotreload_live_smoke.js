/**
 * Keep one WebSocket connected across module publication/reload.
 * Port of hotreload_live_smoke.py.
 *
 * Run against a hot relay, then rebuild/publish the module while this
 * script sits in its 20-second wait window:
 *   node hotreload_live_smoke.js [--uri ws://127.0.0.1:7456]
 */
import { Conn } from './relay.js';

const FILTER = { ids: ['f'.repeat(64)] };

const uriArg = process.argv.find((a) => a.startsWith('--uri='));
const uriFlag = process.argv.indexOf('--uri');
const uri =
  (uriArg && uriArg.slice('--uri='.length)) ||
  (uriFlag >= 0 && process.argv[uriFlag + 1]) ||
  'ws://127.0.0.1:7456';

async function waitForEose(conn, subId) {
  await conn.waitFor((m) => m[0] === 'EOSE' && m[1] === subId, 10000, `EOSE ${subId}`);
}

async function main() {
  const conn = await Conn.open(uri, 10000);
  try {
    conn.sendJson(['REQ', 'before-reload', FILTER]);
    await waitForEose(conn, 'before-reload');
    console.log('READY: trigger a module rebuild now');
    await new Promise((r) => setTimeout(r, 20000));
    conn.sendJson(['REQ', 'after-reload', FILTER]);
    await waitForEose(conn, 'after-reload');
    console.log('PASS: same WebSocket completed REQ/EOSE before and after reload');
  } finally {
    await conn.close();
  }
}

main().catch((err) => {
  console.error(`FAIL: ${err.message}`);
  process.exit(1);
});

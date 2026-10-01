/**
 * Multi-step probe with assertions: REQ, id-filtered REQ, COUNT.
 *
 * Self-contained by default (spawns its own relay on :7473); pass a URI
 * (`node test_ws2.js ws://127.0.0.1:7447`) to probe an already-running
 * relay instead. Every step is asserted; any failure exits nonzero.
 */
import { Conn, Relay, authEvent, randomSecretKey, assert } from './relay.js';

const PORT = 7473;
const externalUri = process.argv[2] ?? null;

async function handleAuth(conn, wsUrl) {
  const first = await conn.next(5000);
  assert(first && first[0] === 'AUTH', `expected AUTH challenge, got ${JSON.stringify(first)}`);
  console.log(`  Received AUTH challenge: ${first[1]}`);
  const sk = randomSecretKey();
  conn.sendJson(['AUTH', authEvent(sk, wsUrl, first[1])]);
  const ok = await conn.waitFor((m) => m[0] === 'OK', 5000, 'OK');
  assert(ok[2] === true, `AUTH must succeed, got ${JSON.stringify(ok)}`);
  console.log('  Authentication successful');
}

async function recvAll(conn, timeout = 2000) {
  const msgs = [];
  const deadline = Date.now() + timeout;
  for (;;) {
    const msg = await conn.next(Math.max(50, deadline - Date.now()));
    if (msg === null || Date.now() > deadline) break;
    msgs.push(msg);
  }
  return msgs;
}

async function main() {
  let failed = false;
  let relay = null;
  try {
    const wsUrl = externalUri ?? `ws://127.0.0.1:${PORT}`;
    console.log(`=== Connecting to ${wsUrl} ===`);
    if (!externalUri) {
      relay = new Relay(PORT);
      await relay.start();
    }
    const ws = await Conn.open(wsUrl, 10000);
    try {
      await handleAuth(ws, wsUrl);

      ws.sendJson(['REQ', 'test', { kinds: [1] }]);
      const afterReq = await recvAll(ws);
      console.log(`[after REQ] received: ${JSON.stringify(afterReq)}`);
      assert(
        afterReq.some((m) => m[0] === 'EOSE' && m[1] === 'test'),
        'REQ must complete with EOSE',
      );

      ws.sendJson(['REQ', '_', { ids: ['a'.repeat(64)], limit: 1 }]);
      const afterPing = await recvAll(ws);
      console.log(`[after dummy REQ ping] received: ${JSON.stringify(afterPing)}`);
      assert(
        afterPing.some((m) => m[0] === 'EOSE' && m[1] === '_'),
        'id-filtered REQ must complete with EOSE',
      );

      ws.sendJson(['COUNT', 'cnt', { kinds: [1] }]);
      const afterCount = await recvAll(ws);
      console.log(`[after COUNT] received: ${JSON.stringify(afterCount)}`);
      const count = afterCount.find((m) => m[0] === 'COUNT' && m[1] === 'cnt');
      assert(count && typeof count[2].count === 'number', 'COUNT must return a numeric count');

      console.log('PASS: ws2 multi-step (REQ + id-REQ + COUNT)');
    } finally {
      await ws.close();
    }
  } catch (err) {
    failed = true;
    console.error(`FAIL: ${err.message}`);
  } finally {
    if (relay) await relay.stop();
  }
  process.exit(failed ? 1 : 0);
}

main();

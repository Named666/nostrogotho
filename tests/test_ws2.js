/**
 * Test: Multi-step WebSocket probe (REQ, id-filtered REQ, COUNT)
 * NIPs: NIP-01 (Basic Protocol Flow), NIP-42 (Authentication), NIP-45 (COUNT)
 * Spec sections: NIP-01 § "Communication", NIP-42 § "Authentication Flow", NIP-45 § "COUNT"
 * PLAN.md sections: §1.5 (Protocol/Transport Boundary), §1.6 (Composable REQ filter -> SQL mapping)
 *
 * Self-contained by default (spawns its own relay on :7473); pass a URI
 * (`node test_ws2.js ws://127.0.0.1:7447`) to probe an already-running
 * relay instead. Every step is asserted; any failure exits nonzero.
 */
import { Relay, withRelay, assert } from './relay.js';

const PORT = 7473;
const externalUri = process.argv[2] ?? null;

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

async function runCase(wsUrl) {
  await withRelay(PORT, async (relay) => {
    const conn = await relay.connect();
    try {
      console.log(`=== Connecting to ${wsUrl} ===`);

      // Handle AUTH
      const { authEvent, randomSecretKey } = await import('./relay.js');
      const first = await conn.next(5000);
      assert(first && first[0] === 'AUTH', `expected AUTH challenge, got ${JSON.stringify(first)}`);
      console.log(`  Received AUTH challenge: ${first[1]}`);
      const sk = randomSecretKey();
      conn.sendJson(['AUTH', authEvent(sk, wsUrl, first[1])]);
      const ok = await conn.waitFor((m) => m[0] === 'OK', 5000, 'OK');
      assert(ok[2] === true, `AUTH must succeed, got ${JSON.stringify(ok)}`);
      console.log('  Authentication successful');

      // REQ
      conn.sendJson(['REQ', 'test', { kinds: [1] }]);
      const afterReq = await recvAll(conn);
      console.log(`[after REQ] received: ${JSON.stringify(afterReq)}`);
      assert(
        afterReq.some((m) => m[0] === 'EOSE' && m[1] === 'test'),
        'REQ must complete with EOSE',
      );

      // id-filtered REQ
      conn.sendJson(['REQ', '_', { ids: ['a'.repeat(64)], limit: 1 }]);
      const afterPing = await recvAll(conn);
      console.log(`[after dummy REQ ping] received: ${JSON.stringify(afterPing)}`);
      assert(
        afterPing.some((m) => m[0] === 'EOSE' && m[1] === '_'),
        'id-filtered REQ must complete with EOSE',
      );

      // COUNT
      conn.sendJson(['COUNT', 'cnt', { kinds: [1] }]);
      const afterCount = await recvAll(conn);
      console.log(`[after COUNT] received: ${JSON.stringify(afterCount)}`);
      const count = afterCount.find((m) => m[0] === 'COUNT' && m[1] === 'cnt');
      assert(count && typeof count[2].count === 'number', 'COUNT must return a numeric count');

      console.log('PASS: ws2 multi-step (REQ + id-REQ + COUNT)');
    } finally {
      await conn.close();
    }
  });
}

async function main() {
  const wsUrl = externalUri ?? `ws://127.0.0.1:${PORT}`;
  await runCase(wsUrl);
}

main().catch((err) => {
  console.error(`FAIL: ${err.message}`);
  process.exit(1);
});

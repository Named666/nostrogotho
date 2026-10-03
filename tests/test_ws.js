/**
 * Test: Basic WebSocket connectivity (AUTH + REQ/EOSE round trip)
 * NIPs: NIP-01 (Basic Protocol Flow), NIP-42 (Authentication)
 * Spec sections: NIP-01 § "Communication", NIP-42 § "Authentication Flow"
 * PLAN.md sections: §1.5 (Protocol/Transport Boundary)
 *
 * Self-contained by default (spawns its own relay on :7472); pass a URI
 * (`node test_ws.js ws://127.0.0.1:7447`) to probe an already-running
 * relay instead. Every step is asserted; any failure exits nonzero.
 */
import { Relay, withRelay, assert } from './relay.js';

const PORT = 7472;
const externalUri = process.argv[2] ?? null;

async function runCase(wsUrl) {
  await withRelay(PORT, async (relay) => {
    const conn = await relay.connect();
    try {
      console.log(`Connecting to ${wsUrl} ...`);
      console.log('CONNECTED!');

      // Handle AUTH
      const first = await conn.next(5000);
      assert(first && first[0] === 'AUTH', `expected AUTH challenge, got ${JSON.stringify(first)}`);
      console.log(`  Received AUTH challenge: ${first[1]}`);
      const { authEvent, randomSecretKey } = await import('./relay.js');
      const sk = randomSecretKey();
      conn.sendJson(['AUTH', authEvent(sk, wsUrl, first[1])]);
      const ok = await conn.waitFor(
        (m) => m[0] === 'OK',
        5000,
        'OK',
      );
      assert(ok[2] === true, `AUTH must succeed, got ${JSON.stringify(ok)}`);
      console.log('  Authentication successful');

      // REQ/EOSE
      conn.sendJson(['REQ', 'test', { kinds: [1] }]);
      console.log('Sent REQ');
      const eose = await conn.waitFor(
        (m) => m[0] === 'EOSE' && m[1] === 'test',
        5000,
        'EOSE',
      );
      assert(eose, 'REQ must complete with EOSE');
      console.log(`Received: ${JSON.stringify(eose)}`);
      console.log('PASS: ws connectivity (AUTH + REQ/EOSE)');
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

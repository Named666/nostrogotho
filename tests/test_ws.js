/**
 * Minimal connectivity test: AUTH + REQ/EOSE round trip.
 *
 * Self-contained by default (spawns its own relay on :7472); pass a URI
 * (`node test_ws.js ws://127.0.0.1:7447`) to probe an already-running
 * relay instead. Every step is asserted; any failure exits nonzero.
 */
import { Conn, Relay, authEvent, randomSecretKey, assert } from './relay.js';

const PORT = 7472;
const externalUri = process.argv[2] ?? null;

async function handleAuth(conn, wsUrl) {
  const first = await conn.next(5000);
  assert(first && first[0] === 'AUTH', `expected AUTH challenge, got ${JSON.stringify(first)}`);
  console.log(`  Received AUTH challenge: ${first[1]}`);
  const sk = randomSecretKey();
  conn.sendJson(['AUTH', authEvent(sk, wsUrl, first[1])]);
  const ok = await conn.waitFor(
    (m) => m[0] === 'OK',
    5000,
    'OK',
  );
  assert(ok[2] === true, `AUTH must succeed, got ${JSON.stringify(ok)}`);
  console.log('  Authentication successful');
}

async function runCase(conn, wsUrl) {
  await handleAuth(conn, wsUrl);
  conn.sendJson(['REQ', 'test', { kinds: [1] }]);
  console.log('Sent REQ');
  const eose = await conn.waitFor(
    (m) => m[0] === 'EOSE' && m[1] === 'test',
    5000,
    'EOSE',
  );
  assert(eose, 'REQ must complete with EOSE');
  console.log(`Received: ${JSON.stringify(eose)}`);
}

async function main() {
  let failed = false;
  let relay = null;
  try {
    const wsUrl = externalUri ?? `ws://127.0.0.1:${PORT}`;
    console.log(`Connecting to ${wsUrl} ...`);
    if (!externalUri) {
      relay = new Relay(PORT);
      await relay.start();
    }
    const conn = await Conn.open(wsUrl, 10000);
    try {
      console.log('CONNECTED!');
      await runCase(conn, wsUrl);
      console.log('PASS: ws connectivity (AUTH + REQ/EOSE)');
    } finally {
      await conn.close();
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

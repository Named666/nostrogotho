/**
 * Verbose probe: dumps everything the relay sends at each step.
 * Port of test_ws2.py.
 *
 * Connects to an already-running relay (default ws://127.0.0.1:7447,
 * override with `node test_ws2.js <uri>`), answers NIP-42, then issues a
 * REQ, a dummy REQ ping and a COUNT, printing all frames received.
 */
import { Conn, authEvent, randomSecretKey } from './relay.js';

const uri = process.argv[2] ?? 'ws://127.0.0.1:7447';

async function handleAuth(conn) {
  const first = await conn.next(3000);
  if (!first || first[0] !== 'AUTH') {
    if (first) conn.queue.unshift(first);
    return false;
  }
  console.log(`  Received AUTH challenge: ${first[1]}`);
  const sk = randomSecretKey();
  conn.sendJson(['AUTH', authEvent(sk, uri, first[1])]);
  const ok = await conn.next(5000);
  if (ok && ok[0] === 'OK' && ok[2]) {
    console.log('  Authentication successful');
  } else {
    console.log(`  Authentication failed: ${JSON.stringify(ok)}`);
  }
  return true;
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
  console.log(`=== Connecting to ${uri} ===`);
  const ws = await Conn.open(uri, 10000);
  try {
    await handleAuth(ws);

    ws.sendJson(['REQ', 'test', { kinds: [1] }]);
    console.log(`[after REQ] received: ${JSON.stringify(await recvAll(ws))}`);

    ws.sendJson(['REQ', '_', { ids: [`${'a'.repeat(64)}`], limit: 1 }]);
    console.log(`[after dummy REQ ping] received: ${JSON.stringify(await recvAll(ws))}`);

    ws.sendJson(['COUNT', 'cnt', { kinds: [1] }]);
    console.log(`[after COUNT] received: ${JSON.stringify(await recvAll(ws))}`);
  } finally {
    await ws.close();
  }
}

main().catch((err) => {
  console.log(`FAILED: ${err.constructor.name}: ${err.message}`);
  process.exit(1);
});

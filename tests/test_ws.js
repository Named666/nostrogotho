/**
 * Minimal connectivity smoke test. Port of test_ws.py.
 *
 * Connects to an already-running relay (default ws://127.0.0.1:7447,
 * override with `node test_ws.js <uri>`), answers the NIP-42 challenge,
 * sends a NIP-01 REQ and prints the first response.
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

async function main() {
  console.log(`Connecting to ${uri} ...`);
  try {
    const conn = await Conn.open(uri, 10000);
    try {
      console.log('CONNECTED!');
      await handleAuth(conn);
      conn.sendJson(['REQ', 'test', { kinds: [1] }]);
      console.log('Sent REQ');
      const msg = await conn.next(5000);
      if (msg) console.log(`Received: ${JSON.stringify(msg)}`);
      else console.log('No response within 5s (but connection is alive)');
    } finally {
      await conn.close();
    }
  } catch (err) {
    console.log(`FAILED: ${err.constructor.name}: ${err.message}`);
    process.exit(1);
  }
}

main();

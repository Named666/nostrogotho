/**
 * Mission 1: pass a NIP-42 AUTH challenge.
 *
 * Connects to a fresh relay, answers the AUTH challenge with a correctly
 * signed kind-22242 event (nostr-tools), and asserts the relay replies OK true.
 */
import {
  Relay,
  authEvent,
  testSecretKey,
  assert,
} from './relay.js';

const PORT = 7481;

async function main() {
  const relay = new Relay(PORT);
  await relay.start();
  let failed = false;
  try {
    const conn = await relay.connect();
    try {
      const challenge = await conn.waitFor('AUTH', 5000, 'AUTH challenge');
      console.log(`Challenge: ${challenge[1]}`);

      conn.sendJson(['AUTH', authEvent(testSecretKey(), relay.wsUrl, challenge[1])]);
      const ok = await conn.waitFor('OK', 5000, 'OK');
      console.log(`OK: ${JSON.stringify(ok)}`);
      assert(ok[0] === 'OK' && ok[2] === true, `AUTH must succeed, got ${JSON.stringify(ok)}`);
      console.log('PASS: AUTH challenge');
    } finally {
      await conn.close();
    }
  } catch (err) {
    failed = true;
    console.error(`FAIL: ${err.message}`);
  } finally {
    await relay.stop();
  }
  process.exit(failed ? 1 : 0);
}

main();

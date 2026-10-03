/**
 * Test: NIP-42 AUTH challenge happy path
 * NIPs: NIP-42 (Authentication)
 * Spec sections: NIP-42 § "Authentication Flow", § "Challenge Format", § "AUTH Event"
 * PLAN.md sections: §1.5 (Protocol/Transport Boundary)
 *
 * Connects to a fresh relay, answers the AUTH challenge with a correctly
 * signed kind-22242 event (nostr-tools), and asserts the relay replies OK true.
 */
import {
  Relay,
  authEvent,
  testSecretKey,
  assert,
  withAuthConn,
} from './relay.js';

const PORT = 7481;

async function main() {
  await withAuthConn(PORT, async ({ conn, ok }) => {
    assert(ok && ok[2] === true, `AUTH must succeed, got ${JSON.stringify(ok)}`);
    console.log('PASS: AUTH challenge');
  });
}

main().catch((err) => {
  console.error(`FAIL: ${err.message}`);
  process.exit(1);
});

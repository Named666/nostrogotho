/**
 * NIP-13 PoW acceptance test (difficulty 16). Port of test_nip13.py.
 *
 * Starts the relay with MIN_POW_DIFFICULTY=16, then:
 *   1. Publishes a kind-1 note mined to difficulty >= 16 (with a committed
 *      ["nonce", "<value>", "16"] tag) -> expect OK true.
 *   2. Publishes a kind-1 note with no PoW at all -> expect OK false with a
 *      "pow:" rejection reason.
 */
import {
  Relay,
  signEvent,
  randomSecretKey,
  pubkeyOf,
  assert,
} from './relay.js';
import { getEventHash } from 'nostr-tools/pure';

const PORT = 7449;
const URI = `ws://127.0.0.1:${PORT}`;
const DIFFICULTY = 16;

function leadingZeroBits(hexStr) {
  let count = 0;
  for (const ch of hexStr) {
    const nibble = parseInt(ch, 16);
    if (nibble === 0) {
      count += 4;
    } else {
      count += 4 - nibble.toString(2).length;
      break;
    }
  }
  return count;
}

function powProof(eventId, difficulty) {
  const bits = BigInt(`0x${eventId}`).toString(2).padStart(256, '0');
  const zeros = leadingZeroBits(eventId);
  const verdict = zeros >= difficulty ? '>=' : '<';
  return `id has ${zeros} leading zero bits (${verdict} target ${difficulty}): ${bits.slice(0, zeros)}...${bits.slice(-8)}`;
}

/** Mine a kind-1 note until its id has >= difficulty leading zero bits. */
function mineEvent(sk, content, difficulty, commitTarget) {
  const pubkey = pubkeyOf(sk);
  const createdAt = Math.floor(Date.now() / 1000);
  let nonce = 0;
  for (;;) {
    const tags = commitTarget ? [['nonce', String(nonce), String(difficulty)]] : [];
    const template = { kind: 1, pubkey, created_at: createdAt, tags, content };
    const id = getEventHash(template);
    if (leadingZeroBits(id) >= difficulty) {
      return signEvent(sk, { kind: 1, tags, content, created_at: createdAt });
    }
    nonce++;
  }
}

async function main() {
  const relay = new Relay(PORT);
  relay.wsUrl = URI;
  await relay.start([], { MIN_POW_DIFFICULTY: String(DIFFICULTY) });
  const results = [];
  try {
    const { conn, ok: authOk } = await relay.connectAndAuth(randomSecretKey());
    void authOk;

    const minerSk = randomSecretKey();

    // Test 1: mined note -> accepted.
    const mined = mineEvent(minerSk, 'hello from the NIP-13 test (mined)', DIFFICULTY, true);
    console.log(`[test 1] mined id=${mined.id} (${leadingZeroBits(mined.id)} zero bits, target ${DIFFICULTY})`);
    conn.sendJson(['EVENT', mined]);
    const ok = await conn.waitFor(
      (m) => m[0] === 'OK' && m[1] === mined.id, 5000, 'OK',
    );
    const passed = ok[2] === true && leadingZeroBits(mined.id) >= DIFFICULTY;
    console.log(`[test 1] ${passed ? 'PASS' : 'FAIL'}: relay said ${JSON.stringify(ok)}`);
    console.log(`[test 1] proof: ${powProof(mined.id, DIFFICULTY)}`);
    results.push(['mined note accepted', passed]);

    // Test 2: unmined note -> rejected with pow reason.
    let plain = mineEvent(minerSk, 'no work done here', 0, false);
    if (leadingZeroBits(plain.id) >= DIFFICULTY) {
      plain = mineEvent(minerSk, 'no work done here (retry)', 0, false);
    }
    console.log(`[test 2] plain id=${plain.id} (${leadingZeroBits(plain.id)} zero bits)`);
    conn.sendJson(['EVENT', plain]);
    const ok2 = await conn.waitFor(
      (m) => m[0] === 'OK' && m[1] === plain.id, 5000, 'OK',
    );
    const passed2 =
      ok2[2] === false &&
      /pow/.test(String(ok2[3]).toLowerCase()) &&
      leadingZeroBits(plain.id) < DIFFICULTY;
    console.log(`[test 2] ${passed2 ? 'PASS' : 'FAIL'}: relay said ${JSON.stringify(ok2)}`);
    console.log(`[test 2] proof: ${powProof(plain.id, DIFFICULTY)} (below target, so rejection is correct)`);
    results.push(['unmined note rejected with pow reason', passed2]);

    await conn.close();
  } finally {
    await relay.stop();
  }

  const failed = results.filter(([, p]) => !p).map(([n]) => n);
  console.log();
  if (failed.length > 0) {
    console.log(`FAILED: ${failed.join(', ')}`);
    process.exit(1);
  }
  console.log('ALL TESTS PASSED');
}

main().catch((err) => {
  console.error(`FATAL: ${err.message}`);
  process.exit(1);
});

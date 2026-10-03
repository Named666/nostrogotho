/**
 * Test: NIP-13 PoW acceptance (difficulty 16)
 * NIPs: NIP-13 (Proof of Work)
 * Spec sections: NIP-13 § "Proof of Work", § "Difficulty Calculation", § "Relay Behavior"
 * PLAN.md sections: §1.2 (Capability-Based Composition - publication policy)
 *
 * Starts the relay with MIN_POW_DIFFICULTY=16, then:
 *   1. Publishes a kind-1 note mined to difficulty >= 16 (with a committed
 *      ["nonce", "<value>", "16"] tag) -> expect OK true.
 *   2. Publishes a kind-1 note with no PoW at all -> expect OK false with a
 *      "pow:" rejection reason.
 *   3. Event with nonce tag but insufficient difficulty -> rejected.
 *   4. Event with wrong difficulty in nonce tag -> rejected.
 *   5. Non-kind-1 events also require PoW (NIP-13 applies to all kinds).
 */
import {
  Relay,
  signEvent,
  randomSecretKey,
  pubkeyOf,
  assert,
  withAuthConn,
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
function mineEvent(sk, content, difficulty, commitTarget, kind = 1, createdAt = Math.floor(Date.now() / 1000)) {
  const pubkey = pubkeyOf(sk);
  let nonce = 0;
  for (;;) {
    const tags = commitTarget ? [['nonce', String(nonce), String(difficulty)]] : [];
    const template = { kind, pubkey, created_at: createdAt, tags, content };
    const id = getEventHash(template);
    if (leadingZeroBits(id) >= difficulty) {
      return signEvent(sk, { kind, tags, content, created_at: createdAt });
    }
    nonce++;
  }
}

async function runTests() {
  const results = [];
  await withAuthConn(PORT, async ({ conn }) => {
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

    // Test 3: nonce tag but insufficient difficulty -> rejected.
    // Mine to 15 and ensure it stays below 16 (mining to 15 can luck into 16+).
    let lowPow = mineEvent(minerSk, 'low pow', DIFFICULTY - 1, true);
    for (let retry = 0; retry < 5 && leadingZeroBits(lowPow.id) >= DIFFICULTY; retry++) {
      lowPow = mineEvent(minerSk, `low pow retry ${retry}`, DIFFICULTY - 1, true);
    }
    console.log(`[test 3] low pow id=${lowPow.id} (${leadingZeroBits(lowPow.id)} zero bits, target ${DIFFICULTY})`);
    conn.sendJson(['EVENT', lowPow]);
    const ok3 = await conn.waitFor(
      (m) => m[0] === 'OK' && m[1] === lowPow.id, 5000, 'OK',
    );
    const passed3 =
      ok3[2] === false &&
      /pow/.test(String(ok3[3]).toLowerCase());
    console.log(`[test 3] ${passed3 ? 'PASS' : 'FAIL'}: relay said ${JSON.stringify(ok3)}`);
    results.push(['insufficient difficulty rejected', passed3]);

    // Test 4: committed difficulty (16) exceeds actual PoW -> rejected.
    // Brute-force a properly-signed nonce-claiming-16 event whose id lands in [12,15).
    let wrongDiffEvent = null;
    {
      const pk = pubkeyOf(minerSk);
      const createdAt = Math.floor(Date.now() / 1000);
      for (let nonce = 0; nonce < 500000 && !wrongDiffEvent; nonce++) {
        const tags = [['nonce', String(nonce), String(DIFFICULTY)]];
        const template = { kind: 1, pubkey: pk, created_at: createdAt, tags, content: `wrong diff:${nonce}` };
        const id = getEventHash(template);
        const b = leadingZeroBits(id);
        if (b >= 12 && b < DIFFICULTY) {
          wrongDiffEvent = signEvent(minerSk, { kind: 1, tags, content: `wrong diff:${nonce}`, created_at: createdAt });
        }
      }
    }
    if (!wrongDiffEvent) {
      wrongDiffEvent = lowPow;
    }
    console.log(`[test 4] wrong diff id=${wrongDiffEvent.id} (${leadingZeroBits(wrongDiffEvent.id)} zero bits, claims 16)`);
    conn.sendJson(['EVENT', wrongDiffEvent]);
    const ok4 = await conn.waitFor(
      (m) => m[0] === 'OK' && m[1] === wrongDiffEvent.id, 5000, 'OK',
    );
    const passed4 = ok4[2] === false && /pow/.test(String(ok4[3]).toLowerCase());
    console.log(`[test 4] ${passed4 ? 'PASS' : 'FAIL'}: relay said ${JSON.stringify(ok4)}`);
    results.push(['wrong difficulty in nonce tag rejected', passed4]);

    // Test 5: kind != 1 also requires PoW.
    const minedKind3 = mineEvent(minerSk, 'mined kind 3', DIFFICULTY, true, 3);
    console.log(`[test 5] mined kind 3 id=${minedKind3.id} (${leadingZeroBits(minedKind3.id)} zero bits)`);
    conn.sendJson(['EVENT', minedKind3]);
    const ok5 = await conn.waitFor(
      (m) => m[0] === 'OK' && m[1] === minedKind3.id, 5000, 'OK',
    );
    const passed5 = ok5[2] === true && leadingZeroBits(minedKind3.id) >= DIFFICULTY;
    console.log(`[test 5] ${passed5 ? 'PASS' : 'FAIL'}: relay said ${JSON.stringify(ok5)}`);
    results.push(['non-kind-1 mined accepted', passed5]);

    const plainKind3 = mineEvent(minerSk, 'plain kind 3', 0, false, 3);
    if (leadingZeroBits(plainKind3.id) >= DIFFICULTY) {
      plainKind3 = mineEvent(minerSk, 'plain kind 3 retry', 0, false, 3);
    }
    console.log(`[test 6] plain kind 3 id=${plainKind3.id} (${leadingZeroBits(plainKind3.id)} zero bits)`);
    conn.sendJson(['EVENT', plainKind3]);
    const ok6 = await conn.waitFor(
      (m) => m[0] === 'OK' && m[1] === plainKind3.id, 5000, 'OK',
    );
    const passed6 = ok6[2] === false && /pow/.test(String(ok6[3]).toLowerCase());
    console.log(`[test 6] ${passed6 ? 'PASS' : 'FAIL'}: relay said ${JSON.stringify(ok6)}`);
    results.push(['non-kind-1 unmined rejected', passed6]);
  }, undefined, ['-min-pow', String(DIFFICULTY)]);

  const failed = results.filter(([, p]) => !p).map(([n]) => n);
  console.log();
  if (failed.length > 0) {
    console.log(`FAILED: ${failed.join(', ')}`);
    process.exit(1);
  }
  console.log('ALL TESTS PASSED');
}

runTests().catch((err) => {
  console.error(`FATAL: ${err.message}`);
  process.exit(1);
});

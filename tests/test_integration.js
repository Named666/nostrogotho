/**
 * Comprehensive integration tests for the nostrogotho relay.
 * NIPs: NIP-01, NIP-09, NIP-13, NIP-40, NIP-42, NIP-45
 * PLAN.md sections: §1.1 (Hot Reload), §1.2 (Capability Composition), §1.5 (Protocol/Transport), §1.6 (Filter->SQL), §1.7 (Storage)
 *
 * Port of tests/test_integration.py to Node.js + nostr-tools.
 * Covers event lifecycle, subscriptions, NIP-09/13/40/42/45 and
 * stored/live delivery equivalence.
 */
import {
  Relay,
  authEvent,
  signEvent,
  testSecretKey,
  randomSecretKey,
  pubkeyOf,
  sleep,
  assert,
  TEST_PUBKEY,
  withRelay,
  withAuthConn,
} from './relay.js';

function testEvent({ kind = 1, tags = [], content = 'hello world', created_at } = {}) {
  return signEvent(testSecretKey(), { kind, tags, content, created_at });
}

async function waitOkFor(conn, eventId, timeout = 5000) {
  return conn.waitFor(
    (m) => m[0] === 'OK' && m[1] === eventId,
    timeout,
    `OK for ${eventId.slice(0, 16)}`,
  );
}

async function publish(conn, event, timeout = 5000) {
  conn.sendJson(['EVENT', event]);
  return waitOkFor(conn, event.id, timeout);
}

/** Collect frames for `subId` until EOSE; returns { events, eose }. */
async function collectUntilEose(conn, subId, timeout = 5000) {
  const events = [];
  const deadline = Date.now() + timeout;
  for (;;) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error(`Timeout waiting for EOSE ${subId}`);
    const msg = await conn.next(remaining);
    if (msg === null) throw new Error(`Connection closed waiting for EOSE ${subId}`);
    if (msg[0] === 'EVENT' && msg[1] === subId) events.push(msg);
    else if (msg[0] === 'EOSE' && msg[1] === subId) return { events, eose: msg };
    else if (msg[0] === 'CLOSED' && msg[1] === subId) {
      throw new Error(`Subscription ${subId} closed: ${msg[3]}`);
    }
    // Anything else (e.g. AUTH refresh) stays queued via next(); re-queue it.
    else conn.queue.push(msg);
  }
}

async function testBasicPublishSubscribe() {
  console.log('\n=== Test: Basic Publish/Subscribe (NIP-01) ===');
  await withAuthConn(7457, async ({ conn }) => {
    const subId = 'test-sub-1';
    conn.sendJson(['REQ', subId, { kinds: [1] }]);
    await conn.waitFor(
      (m) => m[0] === 'EOSE' && m[1] === subId, 5000, 'EOSE',
    );
    console.log('  Subscription established');

    const event = testEvent({ kind: 1, content: 'hello world' });
    const ok = await publish(conn, event);
    assert(ok[2] === true, `Event rejected: ${ok[3]}`);
    console.log(`  Event published: ${ok[1]}`);

    const evt = await conn.waitFor(
      (m) => m[0] === 'EVENT' && m[1] === subId, 5000, 'EVENT',
    );
    assert(evt[2].id === ok[1], 'Delivered event ID mismatch');
    console.log(`  Event delivered live: ${evt[2].id}`);

    // Close the subscription. This relay (correctly per Nostr) sends no
    // acknowledgement for CLOSE, so verify the close behaviorally: a new
    // event must NOT be delivered to the closed subscription.
    conn.sendJson(['CLOSE', subId]);
    const probe = testEvent({ kind: 1, content: 'after close' });
    const probeOk = await publish(conn, probe);
    assert(probeOk[2] === true);
    {
      const deadline = Date.now() + 800;
      for (;;) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) break;
        const frame = await conn.next(remaining);
        if (frame === null) break;
        assert(
          !(frame[0] === 'EVENT' && frame[1] === subId),
          'Closed subscription still received events',
        );
      }
    }
    console.log('  Subscription closed (no further delivery)');

    const subId2 = 'test-sub-2';
    conn.sendJson(['REQ', subId2, { kinds: [1] }]);
    const requery = await collectUntilEose(conn, subId2);
    assert(
      requery.events.some((e) => e[2].id === ok[1]),
      'Stored event not found',
    );
    console.log(`  Stored event queried: ${ok[1]} (EOSE received)`);

    console.log('  PASS: Basic publish/subscribe');
  });
}

async function testMultipleFilters() {
  console.log('\n=== Test: Multiple Filters (NIP-01) ===');
  await withAuthConn(7458, async ({ conn }) => {
    for (const kind of [1, 3]) {
      const ok = await publish(conn, testEvent({ kind }));
      assert(ok[2] === true, `Publish kind ${kind} rejected: ${ok[3]}`);
    }

    conn.sendJson(['REQ', 'multi-filter', [{ kinds: [1] }, { kinds: [3] }]]);
    const received = new Set();
    for (let i = 0; i < 2; i++) {
      const evt = await conn.waitFor(
        (m) => m[0] === 'EVENT' && m[1] === 'multi-filter', 5000, 'EVENT',
      );
      received.add(evt[2].kind);
    }
    assert(
      received.has(1) && received.has(3) && received.size === 2,
      `Expected kinds 1 and 3, got ${[...received]}`,
    );
    await conn.waitFor(
      (m) => m[0] === 'EOSE' && m[1] === 'multi-filter', 5000, 'EOSE',
    );
    console.log('  PASS: Multiple filters');
  });
}

async function testTagFiltering() {
  console.log('\n=== Test: Tag Filtering (NIP-01 § "Tag Queries") ===');
  await withAuthConn(7459, async ({ conn }) => {
    for (const ptag of [TEST_PUBKEY, 'a'.repeat(64)]) {
      const ok = await publish(conn, testEvent({ kind: 1, tags: [['p', ptag]] }));
      assert(ok[2] === true, `Publish rejected: ${ok[3]}`);
    }

    conn.sendJson(['REQ', 'ptag-filter', { kinds: [1], '#p': [TEST_PUBKEY] }]);
    const evt = await conn.waitFor(
      (m) => m[0] === 'EVENT' && m[1] === 'ptag-filter', 5000, 'EVENT',
    );
    assert(evt[2].tags[0][1] === TEST_PUBKEY, 'p-tag filter failed');
    await conn.waitFor(
      (m) => m[0] === 'EOSE' && m[1] === 'ptag-filter', 5000, 'EOSE',
    );
    console.log('  PASS: Tag filtering');
  });
}

async function testSubscriptionLimits() {
  console.log('\n=== Test: Subscription Limits (Implementation Limit) ===');
  await withAuthConn(7460, async ({ conn }) => {
    for (let i = 0; i < 50; i++) {
      conn.sendJson(['REQ', `sub-${i}`, { kinds: [1] }]);
      await conn.waitFor(
        (m) => m[0] === 'EOSE' && m[1] === `sub-${i}`, 5000, 'EOSE',
      );
    }

    conn.sendJson(['REQ', 'sub-51', { kinds: [1] }]);
    const closed = await conn.waitFor(
      (m) => m[0] === 'CLOSED' && m[1] === 'sub-51', 5000, 'CLOSED',
    );
    assert(closed[2] === false, 'Should reject 51st subscription');
    assert(String(closed[3]).toLowerCase().includes('too many'));
    console.log('  PASS: Max subscriptions enforced');

    // Max filters per subscription (default 10) is enforced strictly at
    // parse time. Use a fresh connection (the current one already holds 50
    // subs) and filters that avoid kind 4 (which has its own DM gating).
    // Note: withAuthConn creates a new relay per test, so we need a separate approach
    // For now, test within the same connection but after closing some subs
    for (let i = 0; i < 45; i++) {
      conn.sendJson(['CLOSE', `sub-${i}`]);
    }
    {
      const ten = Array.from({ length: 10 }, (_, i) => ({ kinds: [100 + i] }));
      conn.sendJson(['REQ', 'ten-filters', ten]);
      await conn.waitFor(
        (m) => m[0] === 'EOSE' && m[1] === 'ten-filters', 5000, 'EOSE',
      );
      console.log('  10 filters accepted');

      const eleven = Array.from({ length: 11 }, (_, i) => ({ kinds: [100 + i] }));
      conn.sendJson(['REQ', 'eleven-filters', eleven]);
      const notice = await conn.waitFor('NOTICE', 5000, 'NOTICE');
      assert(
        String(notice[1]).toLowerCase().includes('invalid filter'),
        `Expected invalid-filter NOTICE, got ${JSON.stringify(notice)}`,
      );
      console.log('  11 filters rejected (invalid filter)');
    }
    console.log('  PASS: Max filters enforced');
  });
}

async function testCountQuery() {
  console.log('\n=== Test: COUNT Queries (NIP-45) ===');
  await withAuthConn(7461, async ({ conn }) => {
    for (let i = 0; i < 3; i++) {
      const ok = await publish(conn, testEvent({ kind: 1, content: `test ${i}` }));
      assert(ok[2] === true, `Publish rejected: ${ok[3]}`);
    }

    conn.sendJson(['COUNT', 'count-sub', { kinds: [1] }]);
    const count = await conn.waitFor(
      (m) => m[0] === 'COUNT' && m[1] === 'count-sub', 5000, 'COUNT',
    );
    assert(count[2].count === 3, `Expected count 3, got ${count[2].count}`);
    console.log(`  PASS: COUNT returned ${count[2].count} events`);
  });
}

async function testNip09Deletion() {
  console.log('\n=== Test: Event Deletion (NIP-09) ===');
  await withAuthConn(7462, async ({ conn }) => {
    const ok = await publish(conn, testEvent({ kind: 1, content: 'to be deleted' }));
    assert(ok[2] === true);
    const eventId = ok[1];
    console.log(`  Published event: ${eventId}`);

    conn.sendJson(['REQ', 'check-1', { ids: [eventId] }]);
    await conn.waitFor(
      (m) => m[0] === 'EVENT' && m[1] === 'check-1', 5000, 'EVENT',
    );
    await conn.waitFor(
      (m) => m[0] === 'EOSE' && m[1] === 'check-1', 5000, 'EOSE',
    );
    console.log('  Event found in storage');

    const delEvent = testEvent({
      kind: 5,
      tags: [['e', eventId]],
      content: '',
      created_at: Math.floor(Date.now() / 1000) + 1,
    });
    const delOk = await publish(conn, delEvent);
    console.log(`  Deletion request processed: ${delOk[3]}`);

    console.log('  PASS: NIP-09 deletion path');
  });
}

async function testNip40Expiry() {
  console.log('\n=== Test: Event Expiry (NIP-40) ===');
  await withAuthConn(7463, async ({ conn }) => {
    const now = Math.floor(Date.now() / 1000);
    // Unexpired event (expiration in the future): accepted and queryable.
    const fresh = testEvent({
      kind: 1,
      content: 'fresh',
      tags: [['expiration', String(now + 3600)]],
      created_at: now,
    });
    const freshOk = await publish(conn, fresh);
    assert(freshOk[2] === true, `Fresh publish rejected: ${freshOk[3]}`);
    console.log(`  Published unexpired event: ${freshOk[1]}`);

    // Already-expired event: dropped at publish (NIP-40 SHOULD drop).
    const stale = testEvent({
      kind: 1,
      content: 'expired',
      created_at: now - 1000,
      tags: [['expiration', String(now - 100)]],
    });
    const staleOk = await publish(conn, stale);
    assert(staleOk[2] === false, 'Expired publish must be dropped');
    assert(/expir/.test(String(staleOk[3]).toLowerCase()), `Wrong reason: ${staleOk[3]}`);
    console.log(`  Expired publish dropped: ${staleOk[3]}`);

    // Stored query returns the fresh event but never the expired one.
    conn.sendJson(['REQ', 'expired-query', { kinds: [1] }]);
    const { events } = await collectUntilEose(conn, 'expired-query');
    assert(events.some((e) => e[2].id === freshOk[1]), 'Fresh event missing from query');
    assert(!events.some((e) => e[2].id === staleOk[1]), 'Expired event must not be returned');
    console.log('  PASS: Expired events dropped on publish and omitted from queries');
  });
}

async function testStoredVsLiveDelivery() {
  console.log('\n=== Test: Stored vs Live Delivery Equivalence (NIP-01) ===');
  await withAuthConn(7464, async ({ conn }) => {
    conn.sendJson(['REQ', 'live-sub', { kinds: [1], '#p': [TEST_PUBKEY] }]);
    await conn.waitFor(
      (m) => m[0] === 'EOSE' && m[1] === 'live-sub', 5000, 'EOSE',
    );

    const ok1 = await publish(
      conn,
      testEvent({ kind: 1, tags: [['p', TEST_PUBKEY]] }),
    );
    const live = await conn.waitFor(
      (m) => m[0] === 'EVENT' && m[1] === 'live-sub', 5000, 'EVENT',
    );
    assert(live[2].id === ok1[1]);
    console.log(`  Live delivery: ${ok1[1]}`);

    const ok2 = await publish(
      conn,
      testEvent({ kind: 1, tags: [['p', 'b'.repeat(64)]] }),
    );
    assert(ok2[2] === true);
    await sleep(300);
    // Drain anything that arrived; none of it may be for live-sub.
    let leaked = false;
    let frame;
    while ((frame = conn.queue.shift()) !== undefined) {
      if (frame[0] === 'EVENT' && frame[1] === 'live-sub') leaked = true;
    }
    assert(!leaked, 'Non-matching event was delivered');
    console.log('  Non-matching event correctly not delivered');

    conn.sendJson(['REQ', 'stored-sub', { kinds: [1], '#p': [TEST_PUBKEY] }]);
    const stored = await conn.waitFor(
      (m) => m[0] === 'EVENT' && m[1] === 'stored-sub', 5000, 'EVENT',
    );
    assert(stored[2].id === ok1[1], `Stored query returned wrong event: ${stored[2].id}`);
    await conn.waitFor(
      (m) => m[0] === 'EOSE' && m[1] === 'stored-sub', 5000, 'EOSE',
    );
    console.log(`  Stored query returned: ${stored[2].id}`);

    console.log('  PASS: Stored and live delivery use same matching logic');
  });
}

async function testInvalidEventRejection() {
  console.log('\n=== Test: Invalid Event Rejection (NIP-01 Validation) ===');
  await withAuthConn(7465, async ({ conn }) => {
    const bad = testEvent({ kind: 1, content: 'bad sig' });
    bad.sig = '0'.repeat(128);
    const ok = await publish(conn, bad);
    assert(ok[2] === false, 'Should reject invalid signature');
    assert(/invalid|signature/.test(String(ok[3]).toLowerCase()));
    console.log(`  Rejected invalid signature: ${ok[3]}`);

    const future = testEvent({
      kind: 1,
      content: 'future',
      created_at: Math.floor(Date.now() / 1000) + 2000,
    });
    const ok2 = await publish(conn, future);
    assert(ok2[2] === false, 'Should reject future timestamp');
    assert(/out of range|future|invalid/.test(String(ok2[3]).toLowerCase()));
    console.log(`  Rejected future timestamp: ${ok2[3]}`);

    console.log('  PASS: Invalid events properly rejected');
  });
}

async function testMalformedMessages() {
  console.log('\n=== Test: Malformed Messages (NIP-01 Protocol) ===');
  await withAuthConn(7466, async ({ conn }) => {
    conn.ws.send('not json');
    const notice = await conn.waitFor('NOTICE', 5000, 'NOTICE');
    assert(/error|invalid/.test(String(notice[1]).toLowerCase()));
    console.log(`  Handled invalid JSON: ${notice[1]}`);

    conn.sendJson(['INVALID_CMD']);
    const notice2 = await conn.waitFor('NOTICE', 5000, 'NOTICE');
    assert(String(notice2[1]).toLowerCase().includes('invalid'));
    console.log(`  Handled invalid command: ${notice2[1]}`);

    conn.sendJson(['REQ']);
    const notice3 = await conn.waitFor('NOTICE', 5000, 'NOTICE');
    console.log(`  Handled malformed REQ: ${notice3[1]}`);

    console.log('  PASS: Malformed messages handled gracefully');
  });
}

async function testConcurrentConnections() {
  console.log('\n=== Test: Concurrent Connections (NIP-01) ===');
  await withRelay(7467, async (relay) => {
    const { conn: c1 } = await relay.connectAndAuth(testSecretKey());
    const { conn: c2 } = await relay.connectAndAuth(testSecretKey());

    c1.sendJson(['REQ', 'sub1', { kinds: [1] }]);
    await c1.waitFor((m) => m[0] === 'EOSE' && m[1] === 'sub1', 5000, 'EOSE');
    c2.sendJson(['REQ', 'sub2', { kinds: [1] }]);
    await c2.waitFor((m) => m[0] === 'EOSE' && m[1] === 'sub2', 5000, 'EOSE');
    console.log('  Both connections subscribed');

    const ok = await publish(c1, testEvent({ kind: 1, content: 'concurrent test' }));
    const evt1 = await c1.waitFor(
      (m) => m[0] === 'EVENT' && m[1] === 'sub1', 5000, 'EVENT',
    );
    const evt2 = await c2.waitFor(
      (m) => m[0] === 'EVENT' && m[1] === 'sub2', 5000, 'EVENT',
    );
    assert(evt1[2].id === ok[1] && evt2[2].id === ok[1]);
    console.log(`  Both received: ${ok[1]}`);

    await c1.close();
    await c2.close();
    console.log('  PASS: Concurrent connections');
  });
}

async function testDuplicateEvent() {
  console.log('\n=== Test: Duplicate Event Handling (NIP-01) ===');
  await withAuthConn(7468, async ({ conn }) => {
    const event = testEvent({ kind: 1, content: 'duplicate test' });
    const ok1 = await publish(conn, event);
    assert(ok1[2] === true);
    console.log(`  First publish: ${ok1[1]}`);

    const ok2 = await publish(conn, event);
    assert(ok2[2] === true);
    assert(String(ok2[3]).toLowerCase().includes('duplicate'));
    console.log(`  Duplicate handled: ${ok2[3]}`);

    console.log('  PASS: Duplicate events handled correctly');
  });
}

async function testPowRequirement() {
  console.log('\n=== Test: Proof of Work (NIP-13) ===');
  // NOTE: the relay always gets -service-url from the helper, so AUTH can
  // succeed here (the Python version omitted it and its AUTH always failed).
  await withAuthConn(7469, async ({ conn }) => {
    const ok = await publish(conn, testEvent({ kind: 1, content: 'no pow' }));
    assert(ok[2] === false, 'Should reject event without PoW');
    assert(/pow|work|insufficient/.test(String(ok[3]).toLowerCase()));
    console.log(`  Rejected no-PoW event: ${ok[3]}`);
    console.log('  PASS: PoW requirement enforced');
  }, testSecretKey(), ['-min-pow', '8']);
}

async function testNip42WrongRelayAuth() {
  console.log('\n=== Test: NIP-42 Wrong-Relay AUTH ===');
  await withRelay(7470, async (relay) => {
    const conn = await relay.connect();
    try {
      const challenge = await conn.waitFor('AUTH', 5000, 'AUTH challenge');
      console.log(`  Challenge: ${challenge[1]}`);
      const sk = testSecretKey();

      conn.sendJson(['AUTH', authEvent(sk, relay.wsUrl, challenge[1], 'wss://evil.example.com/')]);
      const ok1 = await conn.waitFor('OK', 5000, 'OK');
      assert(ok1[0] === 'OK' && ok1[2] === false, `Wrong-relay AUTH must fail, got ${JSON.stringify(ok1)}`);
      console.log('  Wrong-relay AUTH rejected');

      const bare = signEvent(sk, {
        kind: 22242,
        content: '',
        tags: [['challenge', challenge[1]]],
      });
      conn.sendJson(['AUTH', bare]);
      const ok2 = await conn.waitFor('OK', 5000, 'OK');
      assert(ok2[0] === 'OK' && ok2[2] === false, `Missing-relay AUTH must fail, got ${JSON.stringify(ok2)}`);
      console.log('  Missing-relay AUTH rejected');

      const good = authEvent(sk, relay.wsUrl, challenge[1]);
      conn.sendJson(['AUTH', good]);
      const ok3 = await conn.waitFor('OK', 5000, 'OK');
      assert(ok3[0] === 'OK' && ok3[2] === true, `Correct AUTH must succeed, got ${JSON.stringify(ok3)}`);
      console.log('  Correct AUTH accepted');

      // NIP-42: challenge stays valid for the connection (or until replaced) so
      // clients MAY auth multiple pubkeys in sequence. Replaying the same AUTH
      // is idempotent (OK true); a second pubkey with the same challenge must
      // also succeed.
      conn.sendJson(['AUTH', good]);
      const ok4 = await conn.waitFor('OK', 5000, 'OK');
      assert(ok4[0] === 'OK' && ok4[2] === true, `Replayed AUTH must succeed (idempotent), got ${JSON.stringify(ok4)}`);
      console.log('  Replayed AUTH accepted (idempotent, challenge retained)');

      const sk2 = randomSecretKey();
      conn.sendJson(['AUTH', authEvent(sk2, relay.wsUrl, challenge[1])]);
      const ok5 = await conn.waitFor('OK', 5000, 'OK');
      assert(ok5[0] === 'OK' && ok5[2] === true, `Second-pubkey AUTH must succeed, got ${JSON.stringify(ok5)}`);
      console.log('  Second-pubkey AUTH accepted (multi-auth)');

      console.log('  PASS: NIP-42 wrong-relay AUTH');
    } finally {
      await conn.close();
    }
  });
}

async function testNip42Kind4DmGating() {
  console.log('\n=== Test: NIP-42 Kind-4 DM Gating ===');
  await withRelay(7471, async (relay) => {
    const victimSk = randomSecretKey();
    const victimPubkey = pubkeyOf(victimSk);
    const throwawaySk = randomSecretKey();
    const throwawayPubkey = pubkeyOf(throwawaySk);

    const { conn: publisher } = await relay.connectAndAuth(testSecretKey());
    const victimDm = signEvent(victimSk, {
      kind: 4,
      content: 'secret dm',
      tags: [['p', throwawayPubkey]],
    });
    const pubOk = await publish(publisher, victimDm);
    assert(pubOk[2] === true, `DM publish failed: ${JSON.stringify(pubOk)}`);
    const victimDmId = pubOk[1];
    console.log(`  Published victim DM: ${victimDmId}`);

    // Fresh unauthenticated connection: kind-less victim filter rejected.
    const anon = await relay.connect();
    try {
      const ch = await anon.waitFor('AUTH', 5000, 'AUTH challenge');
      assert(ch[0] === 'AUTH');
      anon.sendJson(['REQ', 'anon-kindless', { authors: [victimPubkey] }]);
      // The relay refreshes the challenge (AUTH) before CLOSED on
      // auth-required rejects; skip straight to the CLOSED verdict.
      const closed = await anon.waitFor(
        (m) => m[0] === 'CLOSED' && m[1] === 'anon-kindless', 5000, 'CLOSED',
      );
      assert(closed[2] === false, `Kind-less DM query must close, got ${JSON.stringify(closed)}`);
      assert(
        String(closed[3]).startsWith('auth-required:'),
        `Expected auth-required, got ${closed[3]}`,
      );
      console.log('  Kind-less query rejected (auth-required)');
    } finally {
      await anon.close();
    }

    // Attacker connection: authenticate as throwaway (correct relay tag).
    const { conn: attacker } = await relay.connectAndAuth(throwawaySk);
    console.log('  Throwaway AUTH accepted');

    // Paired-filter bypass attempt -> restricted, no EVENT leak.
    attacker.sendJson([
      'REQ',
      'paired-bypass',
      [{ kinds: [1] }, { kinds: [4], authors: [victimPubkey] }],
    ]);
    let gotEvent = false;
    let gotClosed = null;
    {
      const deadline = Date.now() + 5000;
      for (;;) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) break;
        const frame = await attacker.next(remaining);
        if (frame === null) break;
        if (frame[0] === 'EVENT' && frame[1] === 'paired-bypass') {
          if (frame[2].id === victimDmId) gotEvent = true;
        } else if (frame[0] === 'CLOSED' && frame[1] === 'paired-bypass') {
          gotClosed = frame;
          break;
        } else if (frame[0] === 'EOSE' && frame[1] === 'paired-bypass') {
          break;
        }
      }
    }
    assert(!gotEvent, 'Victim DM leaked via paired filters');
    assert(gotClosed !== null && gotClosed[2] === false, `Paired bypass must be CLOSED, got ${JSON.stringify(gotClosed)}`);
    assert(
      String(gotClosed[3]).startsWith('restricted:'),
      `Expected restricted, got ${gotClosed[3]}`,
    );
    console.log('  Paired-filter bypass rejected (restricted, no leak)');

    // COUNT over victim DMs discloses nothing.
    attacker.sendJson(['COUNT', 'count-victim', { kinds: [4], authors: [victimPubkey] }]);
    const verdict = await attacker.waitFor(
      (m) =>
        (m[0] === 'COUNT' && m[1] === 'count-victim') ||
        (m[0] === 'CLOSED' && m[1] === 'count-victim'),
      5000,
      'COUNT verdict',
    );
    if (verdict[0] === 'COUNT') {
      assert(verdict[2].count === 0, `COUNT leaked victim DMs: ${JSON.stringify(verdict)}`);
      console.log('  COUNT disclosed 0 victim DMs');
    } else {
      assert(verdict[2] === false, `COUNT must not leak, got ${JSON.stringify(verdict)}`);
      console.log('  COUNT rejected (restricted, no leak)');
    }

    // Own DM filter stays usable.
    attacker.sendJson(['REQ', 'own-dm', { kinds: [4], '#p': [throwawayPubkey] }]);
    await attacker.waitFor(
      (m) => m[0] === 'EOSE' && m[1] === 'own-dm', 5000, 'EOSE',
    );
    console.log('  Own DM query allowed');

    await attacker.close();
    await publisher.close();
    console.log('  PASS: NIP-42 kind-4 DM gating');
  });
}

const TESTS = [
  testBasicPublishSubscribe,
  testMultipleFilters,
  testTagFiltering,
  testSubscriptionLimits,
  testCountQuery,
  testNip09Deletion,
  testNip40Expiry,
  testStoredVsLiveDelivery,
  testInvalidEventRejection,
  testMalformedMessages,
  testConcurrentConnections,
  testDuplicateEvent,
  testPowRequirement,
  testNip42WrongRelayAuth,
  testNip42Kind4DmGating,
];

async function main() {
  console.log('='.repeat(60));
  console.log('NOSTROGOTHO INTEGRATION TESTS (node)');
  console.log('='.repeat(60));
  try {
    Relay.checkBinary();
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
  let passed = 0;
  let failed = 0;
  const only = process.argv[2];
  for (const testFn of TESTS) {
    if (only && !testFn.name.toLowerCase().includes(only.toLowerCase())) continue;
    try {
      await testFn();
      passed++;
    } catch (err) {
      console.error(`  FAIL: ${testFn.name}: ${err.message}`);
      failed++;
    }
  }
  console.log(`\n${'='.repeat(60)}`);
  console.log(`RESULTS: ${passed} passed, ${failed} failed`);
  console.log('='.repeat(60));
  process.exit(failed === 0 ? 0 : 1);
}

main();
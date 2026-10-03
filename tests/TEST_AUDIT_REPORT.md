# Test Audit Report - nostrogotho

**Date:** 2026-10-02  
**Auditor:** Automated analysis  
**Scope:** All files in `tests/` directory  

---

## Executive Summary

| Category | Count | Critical | High | Medium | Low |
|----------|-------|----------|------|--------|-----|
| Tests not verifying claimed behavior | 7 | 2 | 3 | 2 | 0 |
| Missing/insufficient cleanup | 11 | 3 | 4 | 4 | 0 |
| Missing NIP references | 15 | 0 | 5 | 8 | 2 |
| Flaky/non-deterministic patterns | 6 | 1 | 2 | 3 | 0 |
| **Total** | **39** | **6** | **14** | **17** | **2** |

---

## 1. Tests Not Actually Verifying What They Claim

### 1.1 CRITICAL: `test_relay.c` - Only Tests Startup, Not Functionality
**File:** `tests/test_relay.c` (lines 1-63)

**Problem:** This test creates a relay, initializes storage, starts the manager, listens on a port, then immediately frees the manager and exits. It performs **zero** functional verification - no WebSocket connections, no EVENT/REQ/COUNT/EOSE flows, no NIP compliance checks.

**What it claims to test:** "Relay integration test"
**What it actually tests:** Binary loads and `mg_http_listen` succeeds.

```c
// Current - does nothing useful
int main() {
    storage_context_init_sqlite3(&storage_ctx);
    storage_ctx.init("./test_debug.sqlite");
    relay_config_init(&config);
    relay_t *relay = relay_create(&config, &storage_ctx);
    mg_mgr_init(&relay->manager);
    mg_http_listen(&relay->manager, listen_url, relay_event_handler, relay);
    mg_mgr_free(&relay->manager);  // Immediately shuts down
    return 0;
}
```

**Proposed Fix:** Either delete this file or convert it to a proper integration test using the existing `relay.js` harness. The Node.js tests in `test_integration.js` already cover this comprehensively.

---

### 1.2 CRITICAL: `test_crash.c` - Only Tests Handler Installation, Not Crash Handling
**File:** `tests/test_crash.c` (lines 1-22)

**Problem:** Calls `crash_install_handlers()` and `crash_print_stacktrace()` but **never triggers an actual crash**. The crash fixtures exist in `crash_fixtures.c` but are never run as part of the test suite.

```c
// Current - no crash actually occurs
int main(void) {
    crash_install_handlers();
    fprintf(stderr, "TEST crash: printing stack trace (expect frames below)\n");
    outer_frame();  // Just calls crash_print_stacktrace()
    fprintf(stderr, "TEST crash: stack trace printed OK\n");
    return 0;
}
```

**Proposed Fix:** 
1. Add a test that actually triggers each crash type (in a subprocess to not kill the test runner)
2. Verify the handler produces expected output
3. Integrate `crash_fixtures.c` as subprocess tests

---

### 1.3 HIGH: `test_auth.js` - Tests Happy Path Only
**File:** `tests/test_auth.js` (lines 1-43)

**Problem:** Only tests successful AUTH. Missing tests for:
- Wrong relay URL in AUTH event (NIP-42 § "relay" tag validation)
- Missing "relay" tag
- Replayed challenge (challenge must be single-use)
- Expired challenge
- Malformed AUTH event

**NIP-42 Reference:** `thirdparty/nips/42.md` - Sections on challenge format, relay tag, replay protection.

---

### 1.4 HIGH: `test_nip13.js` - Missing Negative Test Vectors
**File:** `tests/test_nip13.js` (lines 1-118)

**Problem:** Tests mined note (PASS) and unmined note (FAIL), but missing:
- Event with nonce tag but insufficient difficulty
- Event with wrong difficulty in nonce tag (e.g., claims 16 but only has 12)
- Event with multiple nonce tags (which one counts?)
- Kind != 1 events (NIP-13 applies to all kinds per spec)
- Events at exactly the difficulty boundary

---

### 1.5 HIGH: `test_hotreload.c` - Doesn't Test Actual Module Swap in Running Relay
**File:** `tests/test_hotreload.c` (lines 1-264)

**Problem:** Tests the loader mechanics (build, copy, load, ABI check, policy evaluation) but **never connects a WebSocket client** to verify the relay continues serving traffic during reload. The integration tests `test_hotreload_ws.js` and `test_hotreload_integration.js` do this, but the C unit test doesn't.

---

### 1.6 MEDIUM: `test_storage.c` - Placeholder Tests
**File:** `tests/test_storage.c` (lines 1-81)

**Problem:** 
- `test_get_event_by_id_memory()` is a no-op with comment "requires database"
- `test_filter_free_no_double_free()` manually constructs a filter instead of using `json_parse_filter`
- No tests for: event persistence, query by filter, deletion, COUNT, expiration cleanup

---

### 1.7 MEDIUM: `test_sha256.c` - Duplicates `test_crypto.c` Coverage
**File:** `tests/test_sha256.c` (lines 1-54)

**Problem:** Tests the exact same FIPS vectors already covered in `test_crypto.c::test_sha256_kat()`. This is redundant. `test_sha256.c` includes `crypto.c` directly while `test_crypto.c` links it - same code, same vectors.

---

## 2. Missing/Insufficient Cleanup (Test Databases & Artifacts)

### 2.1 CRITICAL: `test_relay.c` - Leaves `test_debug.sqlite*`
**File:** `tests/test_relay.c` (lines 19, 56-60)

```c
// Line 19: creates ./test_debug.sqlite
// Lines 56-60: cleanup only on success path
mg_mgr_free(&relay->manager);
remove("./test_debug.sqlite");
remove("./test_debug.sqlite-shm");
remove("./test_debug.sqlite-wal");
remove("./test_debug.sqlite-journal");
return 0;
```

**Issue:** If any `CHECK` fails before line 56, databases leak. No error-path cleanup.

---

### 2.2 CRITICAL: `test_integration.js` - Leaves Databases on Test Failure
**File:** `tests/test_integration.js` (lines 58-115, and 14 other test functions)

```javascript
// Each test creates: const relay = new Relay(7457);
// Relay.stop() cleans up, BUT:
// - If test throws before relay.stop(), DB leaks
// - No try/finally around individual tests in main()
```

**Evidence:** The `main()` function (lines 687-714) runs tests in a loop with try/catch but `relay.stop()` is inside each test's `finally`. If the test crashes before creating `relay` or during `relay.start()`, no cleanup occurs.

---

### 2.3 CRITICAL: `test_hotreload_ws.js` - DB Cleanup Only in finally, But Host Kill May Leave WAL
**File:** `tests/test_hotreload_ws.js` (lines 86-101, 162-163)

```javascript
const dbPath = path.join(ROOT, `test_hotreload_ws_${port}.sqlite`);
const cleanupDb = () => {
  for (const s of ['', '-shm', '-wal', '-journal']) {
    try { fs.unlinkSync(dbPath + s); } catch { /* ignore */ }
  }
};
// ...
} finally {
  host.kill();
  cleanupDb();  // Called AFTER host.kill() - but host may hold DB locks!
}
```

**Issue:** Killing the host process while it holds SQLite WAL locks can leave `-wal`/`-shm` files that cleanup can't remove on Windows.

---

### 2.4 HIGH: `test_ws.js` & `test_ws2.js` - Same Pattern
**Files:** `tests/test_ws.js` (lines 41-65), `tests/test_ws2.js` (lines 35-82)

```javascript
// Both create Relay, connect, but if Conn.open() throws, relay.stop() never called
if (!externalUri) {
  relay = new Relay(PORT);
  await relay.start();
}
const conn = await Conn.open(wsUrl, 10000);  // If this throws...
```

---

### 2.5 HIGH: `test_hotreload_integration.js` - No DB Cleanup At All
**File:** `tests/test_hotreload_integration.js` (lines 92-132)

```javascript
const relay = spawn(...);  // No -database arg shown, but relay creates one
// No cleanup of any database files anywhere in this file
```

---

### 2.6 HIGH: `test_nip13.js` - No DB Cleanup
**File:** `tests/test_nip13.js` (lines 60-104)

```javascript
const relay = new Relay(PORT);
await relay.start([], { MIN_POW_DIFFICULTY: String(DIFFICULTY) });
// No relay.stop() in finally block!
```

---

### 2.7 MEDIUM: `test_auth.js` - No DB Cleanup
**File:** `tests/test_auth.js` (lines 16-39)

```javascript
const relay = new Relay(PORT);
await relay.start();
// No finally block with relay.stop()
```

---

### 2.8 MEDIUM: `test_crypto.c` / `test_json_fuzz.c` / `test_nip_composition.c` - No Cleanup Needed (In-Memory Only)
**Status:** OK - These are pure in-memory unit tests.

---

### 2.9 MEDIUM: `test_hotreload.c` - Artifact Cleanup Only on Success Path
**File:** `tests/test_hotreload.c` (lines 176-188, 261)

```c
static void cleanup_artifacts(void) { ... }
int main(void) {
  // ...
  CHECK(build_module(...), "build generation 1");
  if (g_fail) {
    cleanup_artifacts();  // Only if build fails
    return 1;
  }
  // ... many CHECKs that can fail ...
  cleanup_artifacts();  // Only at end
}
```

**Issue:** If any `CHECK` in the middle fails, `g_fail` increments but execution continues, and `cleanup_artifacts()` at line 261 runs. **Actually this one IS correct** - cleanup runs at end regardless. But the early return at line 206-209 only cleans up on build failure.

---

### 2.10 LOW: `crash_fixtures.c` - No Cleanup Needed
**Status:** OK - Just triggers crashes for manual testing.

---

## 3. Missing NIP References

Each test should explicitly reference the NIP(s) it validates. Format: `// NIP-XX: <section>`

### 3.1 HIGH: `test_integration.js` - 14 Tests, Partial NIP Coverage

| Test Function | NIPs Covered | Missing Explicit References |
|---------------|--------------|----------------------------|
| `testBasicPublishSubscribe` | NIP-01 | None |
| `testMultipleFilters` | NIP-01 | None |
| `testTagFiltering` | NIP-01 | None |
| `testSubscriptionLimits` | NIP-01 (implementation limit) | None |
| `testCountQuery` | NIP-45 | None |
| `testNip09Deletion` | NIP-09 | **Has "NIP-09" in name only** |
| `testNip40Expiry` | NIP-40 | **Has "NIP-40" in name only** |
| `testStoredVsLiveDelivery` | NIP-01 | None |
| `testInvalidEventRejection` | NIP-01 (validation) | None |
| `testMalformedMessages` | NIP-01 (protocol) | None |
| `testConcurrentConnections` | NIP-01 | None |
| `testDuplicateEvent` | NIP-01 | None |
| `testPowRequirement` | NIP-13 | **Has "NIP-13" in name only** |
| `testNip42WrongRelayAuth` | NIP-42 | **Has "NIP-42" in name only** |
| `testNip42Kind4DmGating` | NIP-42 | **Has "NIP-42" in name only** |

---

### 3.2 HIGH: `test_nip13.js` - References NIP-13 But Not Specific Sections
**File:** `tests/test_nip13.js` (lines 1-9)

```javascript
/**
 * NIP-13 PoW acceptance test (difficulty 16). Port of test_nip13.py.
 *
 * Starts the relay with MIN_POW_DIFFICULTY=16, then:
 *   1. Publishes a kind-1 note mined to difficulty >= 16...
 *   2. Publishes a kind-1 note with no PoW at all -> expect OK false with a
 *      "pow:" rejection reason.
 */
```

**Missing:** References to specific NIP-13 sections:
- § "Proof of Work" - nonce tag format `["nonce", "<value>", "<difficulty>"]`
- § "Difficulty calculation" - leading zero bits of event ID
- § "Relay behavior" - MUST reject events below min difficulty

---

### 3.3 HIGH: `test_auth.js` - No NIP-42 Reference
**File:** `tests/test_auth.js` (lines 1-6)

```javascript
/**
 * Mission 1: pass a NIP-42 AUTH challenge.
 */
```

**Missing:** Specific NIP-42 sections being tested:
- Challenge format
- AUTH event kind (22242)
- Required tags: `["relay", <url>]`, `["challenge", <challenge>]`
- Relay URL validation
- Challenge single-use

---

### 3.4 HIGH: `test_hotreload_ws.js` / `test_hotreload_integration.js` - No NHR Spec Reference
**Files:** Both hot-reload tests

**Missing:** Reference to the NHR (Nostr Hot Reload) specification in `PLAN.md`:
- §1.1 "Hot Reload Without State Loss (NHR)"
- §1.3 "Host Services as ABI Boundary"
- Module `nhr_module_*` exports
- `pre_reload`/`post_reload` state transfer

---

### 3.5 MEDIUM: `test_crypto.c` - References NIPs in Comments Only
**File:** `tests/test_crypto.c` (lines 5, 394, 490)

```c
// Line 5: "full event validation (incl. NIP-26 delegation)"
// Line 394: "NIP-26 delegation through the full check_event path"
// Line 490: "NIP-13 difficulty"
```

**Issue:** Good references but should be formalized as test case documentation.

---

### 3.6 MEDIUM: `test_json_fuzz.c` - No NIP References
**File:** `tests/test_json_fuzz.c` (lines 1-5)

```c
/* Fuzz tests for src/json_util.c: json_array_parse + json_parse_event
 * (+ json_parse_filter as a bonus target — same harness).
 * ...
 * Deterministic structured fuzzing...
 */
```

**Missing:** References to NIP-01 message format specifications being fuzzed.

---

### 3.7 MEDIUM: `test_nip_composition.c` - Good Internal References, No NIP Mapping
**File:** `tests/test_nip_composition.c` (lines 1-20)

```c
/* Integration tests for src/nips/nip_capability.c composition rules.
 * A mock registry holding two CONFLICTING policies per type proves the
 * documented composition semantics:
 *   publication : AND  (any deny wins...)
 *   delivery    : veto (any veto wins...)
 *   ...
 */
```

**Missing:** Map each composition rule to the NIP that requires it:
- Publication policy → NIP-01, NIP-26, NIP-40, NIP-42
- Delivery policy → NIP-01, NIP-42
- Kind handlers → NIP-01, NIP-09, NIP-25, NIP-45, etc.
- Query policy → NIP-01, NIP-42, NIP-45
- Maintenance → NIP-01 (relay maintenance)

---

### 3.8 MEDIUM: `test_storage.c` - No NIP References
**File:** `tests/test_storage.c`

**Missing:** References to NIPs requiring storage:
- NIP-01 (event storage/query)
- NIP-09 (deletion)
- NIP-40 (expiration)
- NIP-45 (COUNT)

---

### 3.9 MEDIUM: `test_ws.js` / `test_ws2.js` - No NIP References
**Files:** Basic connectivity tests

**Missing:** NIP-01 (basic protocol), NIP-42 (AUTH)

---

### 3.10 LOW: `test_sha256.c` - No NIP Reference (SHA-256 is NIP-01 foundation)
**File:** `tests/test_sha256.c`

---

### 3.11 LOW: `test_crash.c` / `crash_fixtures.c` - No NIP Reference (Infrastructure)
**Status:** Acceptable - infrastructure tests.

---

### 3.12 LOW: `test_relay.c` - No NIP Reference
**File:** `tests/test_relay.c`

---

## 4. Flaky/Non-Deterministic Patterns

### 4.1 CRITICAL: `test_integration.js::testSubscriptionLimits` - Depends on Test Order
**File:** `tests/test_integration.js` (lines 177-226)

```javascript
// Creates 50 subscriptions on conn, then expects 51st to fail
for (let i = 0; i < 50; i++) {
  conn.sendJson(['REQ', `sub-${i}`, { kinds: [1] }]);
  await conn.waitFor(...);
}
conn.sendJson(['REQ', 'sub-51', { kinds: [1] }]);
const closed = await conn.waitFor(...);  // Expects CLOSED
```

**Problem:** If a previous test left subscriptions open on the same relay (unlikely since each test creates new relay), or if the limit changes, this breaks. The limit of 50 is an implementation detail, not protocol.

---

### 4.2 HIGH: `test_hotreload_ws.js` - Race Condition on Generation Detection
**File:** `tests/test_hotreload_ws.js` (lines 131-148)

```javascript
const before = loadedGenerations(host.pid);
if (!buildModule()) throw new Error('module rebuild failed');

const dl2 = Date.now() + 30000;
let after = before;
for (;;) {
  const current = loadedGenerations(host.pid);
  const fresh = [...current].filter((g) => !before.has(g));
  if (fresh.length > 0) { ... }
  if (Date.now() > dl2) throw new Error('host did not load a new module generation');
  await sleep(200);
}
```

**Problem:** Polling `fs.readdirSync` for new module files is racy. The host may load the module but not yet have created the file, or may have created it but not yet loaded it. No synchronization with host's actual reload completion.

---

### 4.3 HIGH: `test_hotreload_integration.js` - Same Race + Linux-Only
**File:** `tests/test_hotreload_integration.js` (lines 33-55, 76-89)

```javascript
function loadedGenerations(pid) {
  const prefix = `nhr_${pid}_`;
  // Checks build/ directory AND /proc/<pid>/maps
  // On Linux only - SKIPs on other platforms
}
```

**Problem:** Same polling race condition. Also `/proc/<pid>/maps` parsing is fragile.

---

### 4.4 MEDIUM: `test_json_fuzz.c` - Non-Deterministic Across Platforms
**File:** `tests/test_json_fuzz.c` (lines 38-48, 370-379)

```c
static uint64_t rng_state = 0x123456789abcdefULL;
// ...
if (argc > 2) seed = strtoull(argv[2], NULL, 0);
// ...
rng_state = seed ? seed : 1;
```

**Issue:** Good - uses deterministic seed. But `system()` calls to compiler (line 97-98) may behave differently across platforms. The fuzz test itself is deterministic given a seed.

---

### 4.5 MEDIUM: `test_crypto.c` - Depends on libsecp256k1 Behavior
**File:** `tests/test_crypto.c` (lines 63-84)

```c
static int test_xonly(const uint8_t seckey[32], uint8_t xonly[32]) {
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xp;
    int parity = 0;
    if (!secp256k1_keypair_create(sign_ctx, &kp, seckey)) return 0;
    if (!secp256k1_keypair_xonly_pub(sign_ctx, &xp, &parity, &kp)) return 0;
    if (!secp256k1_xonly_pubkey_serialize(sign_ctx, xonly, &xp)) return 0;
    return 1;
}
```

**Issue:** Uses libsecp256k1 for signing (deterministic with fixed aux_rand) but tests crypto.c's verification. This is actually a GOOD pattern (differential testing), not flaky.

---

### 4.6 LOW: `test_integration.js::testNip40Expiry` - Time-Dependent
**File:** `tests/test_integration.js` (lines 287-326)

```javascript
const now = Math.floor(Date.now() / 1000);
// Unexpired event (expiration in the future)
tags: [['expiration', String(now + 3600)]],
// Already-expired event
created_at: now - 1000,
tags: [['expiration', String(now - 100)]],
```

**Issue:** Uses wall clock time. If system clock changes or test runs slowly, could behave unexpectedly. Better to use fixed timestamps.

---

## 5. Architecture Compliance (Per PLAN.md)

### 5.1 Violation: Tests Bypass Host ABI Boundary
**PLAN.md §1.3:** "Module calls host via `Nhr_Host` function pointers... Host calls module via `Nhr_Module` exports"

**Violations:**
- `test_integration.js` tests the full relay binary, not individual NIP modules
- `test_nip_composition.c` tests `nip_capability.c` composition logic directly (correct - this IS the composition layer)
- `test_hotreload.c` tests the loader (`nhr_loader.c`) directly (correct)

**Issue:** No tests verify that NIP modules correctly use the `Nhr_Host` ABI (storage, crypto, connections via function pointers). All integration tests use the full relay binary.

---

### 5.2 Violation: No Tests for Capability-Based Composition
**PLAN.md §1.2:** "NIPs declare capabilities... Host composes capabilities at runtime via registry iteration"

**Status:** `test_nip_composition.c` thoroughly tests the composition logic. Good.

---

### 5.3 Violation: No Tests for Protocol/Transport Boundary
**PLAN.md §1.5:** "Transport layer handles low-level network... Protocol layer separates wire JSON from internal protocol objects"

**Status:** `test_json_fuzz.c` tests `json_util.c` (protocol layer). `test_ws.js`/`test_ws2.js` test transport. But no tests verify the boundary separation.

---

### 5.4 Violation: No Tests for REQ Filter → SQL Mapping
**PLAN.md §1.6:** "Composable Nostr REQ filter -> SQL query mapping"

**Status:** Not tested. `test_integration.js` tests query results but not the SQL generation.

---

### 5.5 Violation: Storage Layer Tests Incomplete
**PLAN.md §1.7:** "Storage layer provides abstraction over underlying database... No NIP logic should be implemented within the storage layer"

**Status:** `test_storage.c` only tests `escape_like` and `filter_free`. Missing tests for actual storage operations.

---

## 6. Proposed Fixes

### 6.1 Immediate (Critical) Fixes

#### Fix 1: Add Cleanup to All Node.js Test Files
Create a shared test helper in `relay.js`:

```javascript
// Add to relay.js
export async function withRelay(port, fn, extraArgs = [], envOverrides = {}) {
  const relay = new Relay(port);
  try {
    await relay.start(extraArgs, envOverrides);
    return await fn(relay);
  } finally {
    await relay.stop();
  }
}

// Usage in test files:
await withRelay(7457, async (relay) => {
  const { conn } = await relay.connectAndAuth(testSecretKey());
  // ... test logic
});
```

#### Fix 2: Delete or Replace `test_relay.c`
Replace with a proper integration test or delete. The Node.js tests are superior.

#### Fix 3: Enhance `test_crash.c` to Actually Test Crash Handling
```c
// Spawn crash_fixtures as subprocess, verify stack trace output
static void test_crash_handler_output(void) {
    // Run ./test_crash_fixtures null_deref as child process
    // Capture stderr, verify it contains expected frames
}
```

---

### 6.2 High-Priority Fixes

#### Fix 4: Add NIP References to All Test Files
Add standardized header to each test:

```javascript
/**
 * Test: <description>
 * NIPs: NIP-01 (event flow), NIP-42 (AUTH), NIP-45 (COUNT)
 * Spec sections: NIP-01 § "Communication", NIP-42 § "Authentication"
 * PLAN.md sections: §1.5 (Protocol/Transport), §1.6 (Filter->SQL)
 */
```

#### Fix 5: Expand `test_auth.js` with NIP-42 Negative Cases
```javascript
async function testWrongRelayAuth() { ... }
async function testMissingRelayTag() { ... }
async function testReplayedChallenge() { ... }
async function testExpiredChallenge() { ... }
```

#### Fix 6: Expand `test_nip13.js` with Boundary Tests
```javascript
function testExactDifficultyBoundary() { ... }
function testWrongDifficultyInNonceTag() { ... }
function testMultipleNonceTags() { ... }
function testNonKind1Events() { ... }
```

#### Fix 7: Fix Hot-Reload Race Conditions
Replace polling with host IPC notification:
```javascript
// Host should signal reload completion via WebSocket or file
// Test waits for signal instead of polling filesystem
```

---

### 6.3 Medium-Priority Fixes

#### Fix 8: Complete `test_storage.c`
Add tests for:
- Event insert/query/delete
- Filter → SQL mapping verification
- Expiration cleanup
- COUNT queries
- Concurrent access

#### Fix 9: Remove Duplicate `test_sha256.c`
Keep `test_crypto.c` which has broader coverage.

#### Fix 10: Map Composition Rules to NIPs in `test_nip_composition.c`
Add comments linking each composition rule to originating NIPs.

---

### 6.4 Low-Priority Fixes

#### Fix 11: Make `test_integration.js::testSubscriptionLimits` Configurable
Read limit from relay config instead of hardcoding 50.

#### Fix 12: Use Fixed Timestamps in `testNip40Expiry`
```javascript
const FIXED_NOW = 1700000000;
const fresh = testEvent({ tags: [['expiration', String(FIXED_NOW + 3600)]] });
const stale = testEvent({ created_at: FIXED_NOW - 1000, tags: [['expiration', String(FIXED_NOW - 100)]] });
```

---

## 7. Test Coverage Gap Analysis

| NIP | Coverage | Tests | Gaps |
|-----|----------|-------|------|
| NIP-01 | Good | test_integration.js (8 tests) | Filter→SQL mapping, protocol boundary |
| NIP-02 | None | - | Contact verification |
| NIP-03 | None | - | OpenTimestamps |
| NIP-04 | None | - | Encrypted DMs |
| NIP-05 | None | - | DNS mapping |
| NIP-09 | Partial | test_integration.js::testNip09Deletion | Deletion of non-existent, auth on deletion |
| NIP-10 | None | - | Deletion requests |
| NIP-11 | None | - | Relay metadata |
| NIP-12 | None | - | Generic tag queries |
| NIP-13 | Good | test_nip13.js, test_integration.js::testPowRequirement | Boundary cases, non-kind-1 |
| NIP-15 | None | - | Marketplace |
| NIP-16 | None | - | Event treatment |
| NIP-25 | None | - | Reactions |
| NIP-26 | Good | test_crypto.c::test_delegation | Delegation in integration flow |
| NIP-40 | Good | test_integration.js::testNip40Expiry | Expiry cleanup job |
| NIP-42 | Good | test_auth.js, test_integration.js (2 tests) | Challenge expiry, multiple challenges |
| NIP-45 | Good | test_integration.js::testCountQuery | COUNT with filters, pagination |
| NIP-50 | None | - | Search |
| NIP-51 | None | - | Lists |
| NIP-57 | None | - | Lightning zaps |

---

## 8. Recommended Test Structure Reorganization

```
tests/
├── unit/                    # Pure C unit tests (no external deps)
│   ├── test_crypto.c        ✓
│   ├── test_json_util.c     ✓
│   ├── test_nip_composition.c  ✓
│   ├── test_sha256.c        → REMOVE (dup)
│   ├── test_storage.c       → EXPAND
│   └── test_crash.c         → ENHANCE
├── fuzz/                    # Fuzz tests
│   └── test_json_fuzz.c     ✓
├── integration/             # Node.js full-relay tests
│   ├── test_integration.js  ✓ (add NIP refs)
│   ├── test_auth.js         → EXPAND
│   ├── test_nip13.js        → EXPAND
│   ├── test_ws.js           → USE withRelay()
│   ├── test_ws2.js          → USE withRelay()
│   ├── test_hotreload_ws.js → FIX RACE
│   └── test_hotreload_integration.js → FIX RACE + CLEANUP
├── hotreload/               # C hot-reload unit tests
│   └── test_hotreload.c     → ADD WS CLIENT
├── fixtures/                # Crash fixtures (manual)
│   └── crash_fixtures.c     ✓
├── relay.js                 ✓ (add withRelay helper)
└── TEST_AUDIT_REPORT.md     (this file)
```

---

## 9. Action Items Priority Order

1. **[P0]** Add `withRelay()` helper to `relay.js` and migrate all Node.js tests
2. **[P0]** Fix DB cleanup in all Node.js tests (use `withRelay`)
3. **[P0]** Delete `test_relay.c` or convert to integration test
4. **[P0]** Enhance `test_crash.c` to actually test crash handler
5. **[P1]** Add NIP references to all test files (standardized header)
6. **[P1]** Expand `test_auth.js` with NIP-42 negative cases
7. **[P1]** Expand `test_nip13.js` with boundary tests
8. **[P1]** Fix hot-reload race conditions (IPC instead of polling)
9. **[P2]** Complete `test_storage.c` with real storage tests
10. **[P2]** Remove duplicate `test_sha256.c`
11. **[P2]** Map composition rules to NIPs in `test_nip_composition.c`
12. **[P3]** Add missing NIP coverage (NIP-02, 03, 04, 05, 10, 11, 12, 15, 16, 25, 50, 51, 57)
13. **[P3]** Make subscription limit test configurable
14. **[P3]** Use fixed timestamps in time-dependent tests

---

## Appendix: NIP Reference Quick Links

| NIP | File | Title |
|-----|------|-------|
| 01 | `thirdparty/nips/01.md` | Basic Protocol Flow |
| 02 | `thirdparty/nips/02.md` | Contact Verification |
| 04 | `thirdparty/nips/04.md` | Encrypted DMs |
| 05 | `thirdparty/nips/05.md` | DNS Mapping |
| 09 | `thirdparty/nips/09.md` | Event Deletion |
| 10 | `thirdparty/nips/10.md` | Deletion Requests |
| 11 | `thirdparty/nips/11.md` | Relay Metadata |
| 12 | `thirdparty/nips/12.md` | Generic Tag Queries |
| 13 | `thirdparty/nips/13.md` | Proof of Work |
| 25 | `thirdparty/nips/25.md` | Reactions |
| 26 | `thirdparty/nips/26.md` | Delegation |
| 40 | `thirdparty/nips/40.md` | Event Expiration |
| 42 | `thirdparty/nips/42.md` | Authentication |
| 45 | `thirdparty/nips/45.md` | COUNT Queries |
| 50 | `thirdparty/nips/50.md` | Search |
| 51 | `thirdparty/nips/51.md` | Lists |
| 57 | `thirdparty/nips/57.md` | Lightning Zaps |

---

*End of Report*
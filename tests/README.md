# Test Suite

Every test in this folder runs under one command, with each outcome verified:

```
nob -test            # Windows and Linux (auto-detects)
nob win -test        # force target
```

`nob -test` builds the relay first (the JS suites spawn it themselves),
then runs three phases -- C suites, Node.js suites -- and fails if ANY
suite exits nonzero. No network and no pre-running relay needed, except a
C compiler on PATH and (for the JS phase) Node 18+; missing `node_modules`
is installed automatically via `npm --prefix tests install`.

`tests/hotreload_live_smoke.js` is the only file NOT run by `-test`: it is
interactive by design (it idles 20s for a manual module rebuild). Its
automated counterpart is `test_hotreload_ws.js`.

## Suites

### C (compiled with relay-identical flags to `build/test_<name>(.exe)`)

| Suite | File | What it proves |
|---|---|---|
| crypto | `test_crypto.c` | SHA-256 NIST vectors; hex encode/decode incl. uppercase, odd/overflow/non-hex rejection and exhaustive round-trips; event-ID canonical serialization byte-identical to OS-hashed vectors; Schnorr sign (libsecp256k1, in-test) vs verify (`crypto.c`) incl. tamper matrix; full `check_event` incl. NIP-26 delegation accept + condition/signature rejection; `json_escape` table; NIP-13 difficulty |
| sha256 | `test_sha256.c` | FIPS 180-4 vectors (`""`, `"abc"`, 56-byte, 1M `'a'`) through the public `sha256()` API |
| storage | `test_storage.c` | `escape_like` boundaries; `filter_free` ownership |
| json_util | `test_json_util.c` | Security regressions: 40-id filter intactness, ~65 KB builder boundedness/termination, oversized-tag rejection, size prediction, hex64 enforcement, empty-filter defaults, builder number format |
| json_fuzz | `test_json_fuzz.c` | Deterministic structured fuzzing of `json_array_parse`, `json_parse_event`, `json_parse_filter`: 200k mutated protocol frames asserting bounds, free-safety, determinism, and (Windows) heap integrity. Reproduce any case: `build/test_json_fuzz 1 <seed> -v <N>`; single baseline seed: extra 6th arg |
| composition | `test_nip_composition.c` | `nip_capability.c` rules with two conflicting mock policies per type: publication/delivery/query AND (deny wins either order), kind-handler AND (reject wins either order), first-wins for EOSE/metadata, OR for auth hints, broadcast for challenges/maintenance, clear/re-register swap, NULL-safety |
| hotreload | `test_hotreload.c` + `hr_test_policy.c` | Builds a real module DLL (allow policy), loads it via the platform loader with full ABI-symbol validation, verifies sends are permitted; rebuilds with a deny policy **while v1 is loaded**, unloads, reloads, verifies sends are rejected; refuses a bad-ABI module and a missing file |
| relay | `test_relay.c` | Boot smoke test: storage init + `relay_create` + listen on :7457, then exit (artifacts removed) |

### Node.js (`node tests/<script>`, also via `npm --prefix tests run test:all`)

| Suite | File | What it proves |
|---|---|---|
| auth | `test_auth.js` | NIP-42 AUTH challenge round trip against a spawned relay |
| nip13 | `test_nip13.js` | NIP-13 PoW mining accepted / unmined rejected (`-min-pow 8`) |
| integration | `test_integration.js` | 15 end-to-end scenarios: publish/subscribe, filters, tags, limits, COUNT, NIP-09 deletion, NIP-40 expiry, stored/live equivalence, invalid events, malformed messages, concurrency, duplicates, PoW, wrong-relay AUTH, kind-4 DM gating |
| hotreload_integration | `test_hotreload_integration.js` | Linux: two live module publications preserve socket + REQ/EOSE. Self-SKIPs elsewhere (exit 0) |
| ws | `test_ws.js` | AUTH + REQ/EOSE round trip (spawns own relay on :7472; `--uri` probes a running one) |
| ws2 | `test_ws2.js` | REQ + id-filtered REQ + COUNT with response assertions (own relay on :7473; `--uri` override) |
| hotreload_ws | `test_hotreload_ws.js` | Live reload over WS: hot host up, REQ/EOSE pre-reload, module rebuilt, new `nhr_<pid>_*` generation observed, same socket REQ/EOSE post-reload |

Shared helpers live in `tests/relay.js` (relay lifecycle, queued WS client,
nostr-tools signing).

## Conventions for new tests

- One file per unit under test, `PASS:`/`FAIL:` lines, summary count,
  nonzero exit on any failure. `nob -test` trusts exit codes only.
- Crypto/signing tests: sign in-test with libsecp256k1 directly (fixed
  keys + fixed aux randomness = deterministic), verify through `crypto.c`
  -- never assert the code against itself. Hash vectors must come from an
  independent implementation (e.g. OS hash of the exact byte string).
- Fuzz targets stay deterministic (fixed seed) and fast (<60s default);
  print the failing input on violation.
- Mock policies over real composition functions, not re-implementations.
- JS tests spawn their own relays on fixed ports (7457+); keep new ports
  clear of existing ones and always `stop()` the relay in a `finally`.

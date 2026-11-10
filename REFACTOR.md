# Refactor: audit and plan (c99-systems-engineering)

Scope: first-party code only (`src/`, `src/ngws/`, `src/nips/`, `tools/*.c`,
`tests/`). Vendored `thirdparty/` (uSockets, SQLite, libsecp256k1) is out of
scope beyond the patches already recorded in `thirdparty/VENDOR.md`.
Constraints kept: wire behavior, config keys, the four duplicate guards,
exactly one SQLite writer thread, `db_sync = full` default, performance
within noise. The platform contract is in `PLATFORM.md`.

## 1. Architecture before (64e20a7)

Threads: N I/O loops (ngws on uSockets, SO_REUSEPORT), W protocol workers
(one shard each: subscriptions, REQ queries on a read-only SQLite
connection, broadcast matching), ONE writer (the only read-write SQLite
connection, batched commits), one WAL checkpointer.

| File | Lines | Layer(s) it mixes |
|---|---|---|
| `src/main.c` | 164 | orchestration + config-file parsing + CLI |
| `src/backend_ngws.c` | 933 | transport callbacks, cross-thread outbox, worker queues and threads, batch signature pre-verification (raw JSON scanning), inline load shedding (raw JSON scanning + reply building), admission policy, the writer thread and its batch dedupe set, the checkpointer, runtime options and their parser, `server_run` |
| `src/relay_core.c` | 716 | protocol engine: REQ/EVENT/CLOSE/COUNT, subscription index, fan-out matching, plugin dispatch |
| `src/relay_conn.c/.h` | 122 | connection handle, refcounts, shared event bodies |
| `src/ngws/ngws.c/.h` | 1224 | WebSocket server: uSockets glue, HTTP upgrade, frame state machine, output corking/coalescing, backlog budgets |
| `src/ws_proto.c/.h` | 214 | framing primitives: SHA-1, base64, header encode/parse, SIMD unmask, UTF-8 |
| `src/json_lite.c`, `src/json_util.c` | 1198 | JSON scanning, Nostr filter/event parsing, the response builder |
| `src/crypto.c`, `src/schnorr_batch.c` | 1055 | id hashing, canonical serialization, Schnorr verify, batch verify |
| `src/storage.c/.h` | 1800 | SQLite schema, prepared statements, queries, NIP-09/40 storage ops |
| `src/dedupe.c/.h` | 160 | lock-striped in-flight/recent id set |
| `src/nips/*.c` | ~1600 | self-registering NIP plugins |
| `src/nostrogotho.c/.h` | 518 | event/filter/tag data types and their lifetimes |
| `tools/ngload.c`, `tools/ngws_bench_server.c` | 611 | load generator, ngws echo/broadcast bench server |

## 2. Violations found, ranked by risk

### High (memory safety, wrong output)

1. **JSON control-character escape writes a NUL into output.**
   `json_builder_escape_string` reserves 6 bytes for `\u00XX` and calls
   `snprintf(..., 6, ...)`, which writes only `\u00X` plus a NUL, then
   advances `pos` by 6. Any string with a control byte other than
   `\b \f \n \r \t` (e.g. U+0001 in `content`) is serialized with an
   embedded NUL and a truncated escape: broken stored/broadcast JSON.
2. **Unchecked size arithmetic before allocation** (sizes derived from peer
   input or counts, no overflow check): `relay_tags_parse`
   (`strlen + 2*cap + 1`, `cap * sizeof`), `relay_body_new` (`len + 1`),
   the outbox growth loop (`nc *= 2` unbounded), `bset` allocation,
   `job_new` (`sizeof + len + 1`), the fallback `relay_conn_send_event`
   (`9 + sub + 1 + body + 1`), ngws read/message/backlog growth loops,
   `canonical_tags_json` (`strlen * 6 + 4` per element), `json_raw_string`,
   `escape_like`, the NIP-09 `DELETE ... IN (...)` SQL size, tag/tags
   arrays in `nostrogotho.c` (`n * sizeof`), dedupe ring (`per * 32`).
   Today most are bounded indirectly by the 5 MiB message cap; none is
   checked where it is computed.
3. **Silent OOM paths that leave inconsistent state.**
   `relay_core_on_open`: a failed `calloc` leaves `conn->core == NULL`; the
   connection stays open and every message is then ignored without an
   answer. `index_add`: a failed `calloc` leaves the subscription linked in
   the shard list but not in the index (it never receives events, and
   `n_subs` bookkeeping goes wrong). `dedupe_init`: partial allocation is
   leaked when a later stripe fails.

### Medium (ownership, thread-safety, hidden state)

4. **Hidden globals with undocumented thread ownership** in
   `backend_ngws.c`: options, worker array, writer queue, stats, the
   per-batch id set and its generation counter, `srv`, `info_doc` - all
   file-scope, touched by different threads, no statement of which thread
   owns what. Same pattern, smaller, in `relay_core.c` (shard tables are
   owner-thread-only, publisher/admission hooks are set-once).
5. **Ownership not stated at API boundaries**: `relay_conn_send_event`
   (who holds the body reference), `relay_bcast_new` (moves `ev`'s heap
   fields), publish hook (transfers `bcast` and a connection reference),
   `json_builder_finish` (pointer into the builder), storage callbacks
   (borrowed for the call only). Some are in comments, none in one
   consistent format.
6. **Stale or wrong header docs**: `storage.h` says "NOT thread-safe, use a
   mutex" while the design is one connection per thread
   (`thread_open`) with a single writer; `json_util.h`, `json_lite.h`,
   `dedupe.h`, `ws_proto.h`, `nips/nip01.h`, `server.h` say nothing about
   thread-safety, ownership or error behavior.

### Medium (structure)

7. **Monolithic `backend_ngws.c`**: one 933-line file runs four thread
   roles and parses raw Nostr JSON on the I/O thread (shedding) and on the
   workers (pre-verification), mixing protocol parsing with I/O and policy.
   `writer_thread` is a 122-line function mixing queueing, linger policy,
   duplicate guard, commit, OK replies and fan-out handoff.
8. **Config contract spread over two files**: `main.c` parses the
   `key = value` file and routes `db_sync` to storage and every other key to
   `server_config_set` in the backend, which owns its own size parser. No
   single list of keys, ranges or error reporting (the error says only
   "invalid config line").
9. **Inconsistent error semantics**: mostly `bool` (true = success), with
   `int` tri-states in a few places (`ws_parse_header` 1/0/-1, storage
   `STORE_*`), `size_t` sentinels (`(size_t)-1` in `jl_unescape`) and
   silent `void` failures (outbox OOM drops the frame without a trace).

### Low (language level, warnings)

10. **C11 constructs**: `<stdatomic.h>` in 6 files, `_Atomic`, `_Alignas`;
    GNU `__thread` used directly in 6 files. Build was `-std=gnu11`.
11. **Strict-warning baseline** (`tools/strict_check.sh`, gnu99 + the
    strict set): 69 warnings in first-party code (24 `-Wconversion`,
    20 `-Wsign-conversion`, 17 `-Wpedantic` (C11 atomics/alignas),
    8 `-Wstrict-prototypes`), plus 134 from vendored libsecp256k1 reported
    against us because `schnorr_batch.c` includes it with a relative
    quoted path. Vendored code was compiled in the same command as ours,
    so per-file warning policy was impossible.
12. Dead code: `nip40_plugin_init` (never referenced);
    `tools/bench/ngws_wslay_variant.c` (historical wslay comparison, not
    built).

## 3. Module map after (target reached)

| Layer | Modules |
|---|---|
| platform | `src/platform/ng_platform.h` (compiler gate, `NG_THREAD_LOCAL`, `NG_ALIGNED`, `NG_STATIC_ASSERT`, ctz), `ng_atomic.h` (struct-wrapped `__atomic`), `ng_alloc.h` (overflow-checked sizes and allocation) |
| transport | `src/ngws/ngws.c` (uSockets glue, HTTP upgrade, frame state machine, corked output, backlog budgets) - not split further (see 5.4) |
| framing (pure) | `src/ws_proto.c` (header encode/parse, unmask, UTF-8, SHA-1/base64) |
| protocol (pure) | `src/relay_wire.c` (raw-message helpers: overload replies, signature triple extraction), `src/json_lite.c`, `src/json_util.c`, `src/crypto.c`, `src/schnorr_batch.c` |
| core | `src/relay_core.c` (protocol engine, subscriptions, matching), `src/relay_conn.c`, `src/dedupe.c`, `src/nips/` |
| storage | `src/storage.c` |
| config | `src/ng_config.c` (one key table, pure line/size parsing, file loader with line/key/status errors), `src/ng_status.h` (error codes) |
| orchestration | `src/main.c` (CLI), `src/backend_ngws.c` (264 lines: ngws callbacks, admission, inline shedding, thread setup/teardown), `src/ngb_conn.h` (connection object + field ownership), `src/ngb_outbox.c` (worker/writer -> loop output and the connection lifetime rule), `src/ngb_workers.c` (sharded workers, job queues, batch pre-verification), `src/ngb_writer.c` (the single writer as take / commit / finish steps, and the checkpointer) |

Functional core / imperative shell: parsing and validation of untrusted
bytes (`ws_proto`, `relay_wire`, `json_*`, `config` line parsing) are pure
functions with unit tests; threads, queues and sockets live in the shell
modules and call into them.

## 4. Plan (one cohesive commit each, full gate after each)

1. Audit (this file), `PLATFORM.md`, `tools/strict_check.sh`.
2. Platform adapters; C11 atomics/alignas/TLS converted to the contract;
   first-party code built as gnu99 with the strict warning set; vendored
   code built as separate objects with its own flags.
3. Config module with one key table and precise errors.
4. Overflow-checked allocation everywhere sizes are computed; OOM paths made
   consistent; the JSON escape bug fixed (with tests).
5. Split `backend_ngws.c` into outbox / workers / writer / wire modules
   with narrow headers; orchestration stays in `backend_ngws.c`.
6. Remaining strict warnings fixed at the site; header contracts
   (ownership, thread-safety, errors) in every public header.
7. Boundary/fragmentation tests: WebSocket header parse at every split
   point and length-encoding boundary, wire helpers, config parser, JSON
   escapes; `ws_split_fuzz.py` joins the suite.

## 5. Results (Nov 10 2026, CST)

Branch `usockets`, local commits only (nothing pushed):

| Commit | Step |
|---|---|
| bb999f9 | 1. audit, PLATFORM.md, `tools/strict_check.sh` |
| 30990de | 2. platform adapters, gnu99 + strict flags for our code, vendored code as separate objects (own flags), dead `nip40_plugin_init` removed |
| 8991ee3 | 3. config module (`ng_config.[ch]`, `ng_status.h`), C tests |
| 735c1cd | 4. checked size arithmetic, OOM paths answered, JSON escape fix, int64 timestamps in storage, hidden C test failures exposed |
| 3b23367 | 5. backend split (outbox / workers / writer / wire), `test_relay_wire.c` |
| 732f863 | 6. strict warnings 37 -> 0, header contracts, `relay_bcast_new` leak + partial-tags fan-out fix |
| 287cf74 | 7. `test_ws_proto.c`, `ws_split_fuzz.py` in the suite, `dedupe_init` partial cleanup |
| (this commit) | ngload OOM handling (cppcheck), this section |

### 5.1 Violations fixed

1. JSON control-byte escape (json_util.c and the same pattern in
   crypto.c): direct `\u00XX` writes; a C test and a test_core round trip
   (`ctl\x01\x1f\x7f end`, live broadcast + REQ). The base binary fails
   that round trip ("Invalid \uXXXX escape").
2. Every computed allocation size in our code goes through
   `ng_size_add/mul/flex` or `ng_malloc_*`/`ng_realloc_array`/`ng_grow_cap`;
   the outbox record length is bounded to 32 bits explicitly.
3. OOM paths: open failure -> NOTICE + close (core and backend), index
   insert failure -> CLOSED "error: server unavailable", message job
   failure -> inline OK false / CLOSED / NOTICE, `dedupe_init` frees only
   what it initialized, the unchecked per-loop `calloc` is gone (static
   per-loop table), `relay_bcast_new` consumes the event on every path and
   refuses to fan out with partially parsed tags.
4. Thread ownership of every file-scope variable in the backend modules
   is stated where it is declared; each module owns its own state.
5. Ownership/threading/errors contracts in storage.h, json_util.h,
   json_lite.h, dedupe.h, ws_proto.h, server.h, crypto.h, relay_core.h,
   relay_conn.h, ngws.h, nip_plugin.h, nip01.h and all new headers.
6. storage.h's wrong "NOT thread-safe" note replaced by the real model.
7. backend_ngws.c 933 -> 264 lines; `writer_thread` split into
   `writer_take` / `writer_commit` / `writer_finish`; raw JSON scanning
   moved to pure `relay_wire.c` with unit tests.
8. One config key table with ranges and precise errors.
10. No C11 constructs left in our code; builds as gnu99.
11. Strict warnings 69 -> 0 (`tools/strict_check.sh`); vendored
    secp256k1 no longer reported against us (134 -> 0, via `-isystem`).
12. `nip40_plugin_init` removed.
Also: storage `created_at`/`now` were truncated through `int` (fixed,
int64); `tools/run_ctests.sh` ignored FAIL lines, which hid two failing
C tests (fixed, tests corrected).

### 5.2 Gates

- Functional suite (`tools/run_all_tests.sh`) after every commit:
  test_core 17/17, test_ws, dedupe 23/23 in both modes, config, nip13,
  listen_backlog 4/4, overload 25/25, RFC 6455 strict 80/80, and (from
  step 7) ws_split_fuzz 804 messages / 200 rounds. C tests: 8/8
  (config_parse, crypto, json_util, relay_wire, schnorr_batch, sha256,
  storage, ws_proto).
- ASan+UBSan (`NG_SAN=address,undefined`): full suite + C tests (built
  with the sanitizers), `log_path` capture: 0 reports, 0 leaks (method
  checked against a deliberate leak).
- TSan (`NG_SAN=thread`): full suite plus a load run (32 x 8 pipelined
  publish, 300-subscriber fan-out at 2000 events/s with shedding, churn):
  0 reports.
- cppcheck 2.22 (`--enable=warning,portability,performance`, the
  standalone binary from the `cppcheck` PyPI wheel; apt mirror was
  down): src/ + tools/ngload.c 0 findings (base: 1 in src, 15 in
  ngload); 20 remain in tests (unchecked malloc in test code).
- gcc 14 `-fanalyzer` over src/ (no clang/scan-build on the host): 4
  reports, all checked as false positives (J_MSG/J_OPEN always carry a
  connection; `keys[i][k]` is written by `filter_keys` for k < nk[i];
  the bset is freed by the last unref).

### 5.3 Performance (same host, interleaved base 64e20a7 vs new, non-PGO -O3 -march=native -flto)

| Case | base | new | uWS |
|---|---|---|---|
| echo 64 B, c100 P8, 2 threads (msg/s, 3 runs) | 3.00 / 3.03 / 3.12M | 3.01 / 3.03 / 3.06M | 2.82 / 2.82 / 2.91M |
| echo 4 KB (msg/s) | 1.42 / 1.43 / 1.43M | 1.37 / 1.43 / 1.44M | 1.05 / 1.05 / 1.06M |
| fan-out 1M/s offered, 1k subs + 20k idle, io=4: delivered, p50 / p99 | 1.00M; 2.75 / 27.5, 2.26 / 11.3 ms | 1.00M; 2.52 / 26.5, 2.23 / 7.1 ms | - |
| fan-out 4M/s offered (5 runs): delivered, p50 median, p99 median, RSS end median | 4.00M; 4.72 ms; 38.8 ms; 119 MB | 4.00M; 4.85 ms; 38.8 ms; 128 MB | - |
| publish FULL sync, 64 x 16 (events/s, 3 runs) | 34.6 / 41.3 / 40.1k | 36.7 / 41.5 / 42.3k | - |

No case moved beyond run-to-run noise (4M fan-out p99 ranges: base
30-53 ms, new 33-44 ms; RSS base 104-156 MB, new 122-141 MB). Raw output:
`/workspace/bench/gate-results/` on the bench host (not in the repo).

### 5.4 Remaining (not done, by priority)

- Outbox allocation failure still drops the frame being queued (now
  documented in ngb_outbox.h). A correct fix closes the connection from
  the loop; not done because it changes wire behavior under OOM.
- `json_builder_t` truncates silently at 64 KiB (documented; callers that
  can exceed it size first). An explicit overflow flag would touch every
  builder user.
- Error conventions are documented (ng_status.h: bool / NULL /
  `ng_status_t`) and used by the config module; older tri-states
  (`ws_parse_header` 1/0/-1, storage `STORE_*`, `jl_unescape` sentinel)
  were not converted.
- `ngws.c` (1088 lines) is not split into transport and framing-state
  modules; `storage.c` (1468 lines) and `relay_core.c` keep long
  functions and owner-thread-only shard tables (documented in
  relay_core.h).
- Strict flags apply in every build of our code; `-Werror` only with
  `NG_WERROR=1`.
- cppcheck findings in test code (unchecked malloc) left as is.

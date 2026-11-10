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

## 3. Target module map

| Layer | Modules |
|---|---|
| platform | `src/platform/ng_platform.h`, `ng_atomic.h`, `ng_alloc.h` |
| transport | `src/ngws/ngws.c` (uSockets glue, HTTP upgrade, corked output) |
| framing | `src/ws_proto.c` (pure: header encode/parse, unmask, UTF-8, SHA-1/base64) |
| protocol (pure) | `src/relay_wire.c` (raw-message helpers used before full parsing: overload replies, signature triple extraction), `src/json_lite.c`, `src/json_util.c`, `src/crypto.c` |
| core | `src/relay_core.c` (protocol engine, subscriptions, matching), `src/relay_conn.c`, `src/dedupe.c`, `src/nips/` |
| storage | `src/storage.c` (+ the single writer in `src/relay_writer.c`) |
| orchestration | `src/main.c` (CLI), `src/config.c` (config file contract), `src/backend_ngws.c` (transport callbacks, admission, `server_run`), `src/relay_outbox.c` (cross-thread output), `src/relay_workers.c` (worker queues/threads), `src/relay_writer.c` (writer + checkpointer threads) |

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

Results are recorded in section 5 when done.

# Benchmarks

All numbers from one 8-core x86-64 Linux VM (~16 GB RAM, shared with other
workloads), loopback networking. Server pinned to CPUs 0-3, `ngload` to CPUs
4-7 (`taskset`). Runs 3-6 s after 1 s warmup, repeated 2-3x; ranges shown.
ngws/relay: gcc `-O3 -march=native -flto=auto`. uWS reference
(`tools/bench/uws_ref.cpp`, uWebSockets + uSockets, 4 threads, SO_REUSEPORT)
built with clang (zig cc) `-O3 -march=native` — only used for benchmarking.
Client: `build/ngload` (pure C, epoll, multithreaded, multiple source IPs).
Scripts: `tools/bench/*.sh`; events from `tools/bench/genev.py`.

## Final head-to-head: ngws (PGO) vs uWebSockets (Nov 7 2026)

`tools/bench/h2h.sh 3 ngws=<pgo bench server> uws=<uws_ref>`, summarized with
`tools/bench/h2h_summ.py`. Server pinned to CPUs 0-1 (2 loop threads; CPU 0
for 1-thread cases), `ngload` 6 threads on CPUs 2-7, 4 s per run, 3 reps,
runs interleaved ngws/uWS. ngws: `tools/bench/pgo_build.sh` (gcc -O3
-march=native -flto + PGO). uWS: `tools/bench/uws_ref.cpp` (clang -O3
-march=native). Median [min-max]; CPU = server CPU% (200 = both cores busy);
latency in µs.

| Case | ngws msg/s | uWS msg/s | ngws CPU | uWS CPU | ngws p50 / p99 | uWS p50 / p99 |
|---|---|---|---|---|---|---|
| echo 16 B, 100 conns, P8 | **3.42M** [3.34-3.45M] | 3.20M [3.16-3.23M] | 200 | 200 | 227 / 479 | 242 / 471 |
| echo 64 B | **3.36M** [3.32-3.44M] | 3.12M [3.12-3.12M] | 200 | 200 | 240 / 422 | 254 / 455 |
| echo 512 B | **2.98M** [2.96-3.00M] | 2.86M [2.85-2.89M] | 200 | 200 | 262 / 549 | 279 / 598 |
| echo 4 KB | **1.60M** [1.57-1.61M] | 1.24M [1.24-1.26M] | 200 | 199 | 463 / 1032 | 573 / 1311 |
| echo 64 KB | 46.7k [39.4-48.8k] | 48.3k [48.1-49.6k] | 83 | 83 | 15.3 ms / 36.7 ms | 15.3 ms / 32.5 ms |
| echo 1 MB | 4.2k [4.2-4.4k] | 4.3k [4.2-4.4k] | 199 | 199 | 176 ms / 449 ms | 172 ms / 487 ms |
| echo 64 B, 1 server thread | **1.72M** [1.70-1.75M] | 1.60M [1.59-1.67M] | 100 | 100 | 459 / 512 | 496 / 557 |
| broadcast 1k subs, closed loop P4, 64 B (deliveries/s) | **940k** [934-944k] | 917k [916-921k] | 100 | 100 | 6357 / 8389 | **5046 / 7274** |
| broadcast 1k subs @2000 msg/s, 64 B | 2.00M | 2.00M | 100 | 100 | **4063 / 7209** | 4522 / 8651 |
| broadcast 10k subs @200 msg/s, 64 B | 2.01M | 2.00M | 96 | 96 | **48.8 ms / 99.6 ms** | 53.0 ms / 103.8 ms |
| broadcast 10k subs @100 msg/s, 512 B | 1.00M | 1.00M | 96 | 96 | **51.4 ms / 103.8 ms** | 57.7 ms / 113.2 ms |
| churn, 200 concurrent (connect+upgrade+echo+close /s) | **168k** [168-172k] | 165k [164-166k] | 196 | 197 | 1180 / 2458 | 1196 / 2785 |
| fixed 100k msg/s, 2k conns, 64 B | 100k | 100k | 46 | 47 | 1458 / **3047** | **1327** / 3277 |
| fixed 300k msg/s, 2k conns, 64 B | 300k | 300k | 146 [139-160] | 146 [138-161] | 1540 / 3768 | **1409 / 3277** |
| idle 100k conns, bytes/conn | 244 | **240** | 0 | 0 | - | - |

ngws leads on small/medium echo (+4% to +29%), single-thread echo (+7%),
closed-loop broadcast throughput (+2.5%), broadcast latency at fixed rate
(-6..-17% p99), and churn (+2%). uWS still leads on: 64 KB echo (+3% median;
ngws had one low run), 1 MB echo by ~2% (within noise), closed-loop broadcast
latency (p50 -21%: ngws coalesces more per write, trading latency for
throughput at saturation), fixed-load echo p50 (-9%) and p99 at 300k/s, and
idle memory (4 B/conn less).

### Relay publish (BLOB ids, PGO not used for the relay)

`tools/bench/pub.sh build/main <conns> 16`, ev1500k pre-signed unique kind-1
events, fresh DB, 3 reps. Latency = EVENT sent → OK (after COMMIT).

| Load | EVENT/s | OK p50 / p99 / p999 | server CPU (4 cores) | previous (5c7b709, hex ids) |
|---|---|---|---|---|
| 64 conns × 16 in flight | **57.0k** [52.5-57.8k] | 16.5 / 33.6 / 106 ms | 328% | 43-48k |
| 256 conns × 16 in flight | **66.2k** [64.4-66.3k] | 57.1 / 167.8 / 180 ms | 357% | 50-52k |

0 rejected in every run.

### Optimization changelog (from commit history)

| Commit | Change | Measured effect |
|---|---|---|
| c379096 | ngws on uSockets, pure-C RFC 6455 layer; ngload | replaces mongoose |
| 00ec72f | relay on ngws; shared broadcast bodies, subscription index | fanout 1k subs: fell behind → 1.99M deliv/s kept up |
| e328b0e | strict duplicate guards (batch set, in-flight/recent set, UNIQUE, replaceable admission) | 23/23 dedupe checks |
| 5c7b709 | writer: 4 KiB pages, sync=NORMAL, off-thread checkpoints, persistent stmts, batch 4096 | publish 21-24k → 43-52k ev/s |
| 2b3870b | ids/pubkeys/sigs as 32/32/64-byte BLOBs, no compat code | publish → 57k / 66k ev/s (this run) |
| ab4cb5d | SIMD unmask (AVX2/SSE2/NEON), SIMD UTF-8 validation, RFC 6455 close checks | conformance 80/80 |
| b8c0e7b | coalesce a socket's consecutive frames into one iovec; mallopt for large frames | 512 B echo gap 5% → 1.3%; 1 MB echo +40% |
| 5deb8cc | PGO build (NG_PGO=gen/use, pgo_build.sh) | small echo +2-5% |
| 301630b | flush a socket's replies at the end of its own on_data | p99 at fixed load -20..35% |
| afb575d | frames ≥ 64 KiB sent straight from caller buffer | 1 MB echo -16% server CPU |
| 704a208 | plain send() when one iovec is queued | small echo +3-7% |
| 7732693 | send_shared extends a contiguous tail iovec | broadcast closed loop +5%, p50 -25% |
| 638f9ba | relay: event bodies ≤ 2 KiB copied into one contiguous frame per subscriber | fanout 1k subs p99 11.9-17.6 → 10.1-11.1 ms; 5k subs p99 69-84 → 51-55 ms |
| da8ef95 | PGO use: -fprofile-correction | fixes PGO build failure (inconsistent threaded value profiles) |

### Caveats

- One shared 8-core VM, loopback, client and server on the same host: treat
  numbers as relative. Run-to-run noise is ~2-5%; differences inside that
  (64 KB, 1 MB, fixed-load p50) are not significant.
- 64 KB echo is client-bound (server ~83% of 200%), so it compares little.
- 1 MB echo at 100 conns × P8 keeps ~800 MB in flight; latencies are queueing.
- uWS is built with clang, ngws with gcc + PGO; uWS has no PGO here.
- Relay publish is bound by Schnorr verification and the single SQLite
  writer, not the transport; synchronous=NORMAL on the writer (OK after
  COMMIT; power loss can drop the last batches). These historical results
  used NORMAL; the current default is FULL (`db_sync=normal` in
  `nostrogotho.conf` opts into the benchmark durability mode).
- Sanitizers (Nov 7): TSan and ASan builds pass test_core, test_ws, test_ws2,
  dedupe (both modes), nip13, RFC 6455 80/80, ws_split_fuzz, relay
  fanout+publish, ngload echo (512 B, 70 KB) and broadcast: 0 reports. An
  ngload-only race (early-stop counter) and exit leaks were fixed in 2f19b6c.

## Earlier results

### Raw WebSocket: ngws vs uWebSockets (4 server threads, before b8c0e7b)

| Case | ngws + wslay codec | ngws + native codec (shipped) | uWS |
|---|---|---|---|
| echo, 100 conns, P8, 4096 B | 1.08-1.13M msg/s, ~185% CPU | 1.09-1.11M msg/s, ~160% CPU | 1.01-1.03M msg/s, ~190% CPU |
| echo, 2000 conns, P1, 64 B | 764-777k | 770-788k | 754-758k |
| echo, 16 B | 5.69-5.92M | 5.80-6.00M | 5.79-5.96M |
| echo, 1 server thread, 64 B | 1.51-1.55M | 1.57-1.61M | 1.43-1.53M |
| echo, 65536 B | 72.6k msg/s, 243% CPU | 75.4k msg/s, 146% CPU | 73.1k msg/s, 127% CPU |
| broadcast, 1000 subs, closed loop | 843-879k deliv/s | 816-859k | 833-906k |
| idle 50k / 100k conns | — | 231 / 228 B/conn, 0% CPU | 241 / 240 B/conn |

Broadcast p50 latency ≈ 6.6-7 ms for all three. Codec decision: the native
`src/ws_proto.c` codec (zero-copy, 8-byte unmask) matched or beat wslay
everywhere and used far less CPU on large frames, so wslay was not kept.

## Relay (Nostr): before vs after

64 pubs P16 for `nostr-pub` (pre-signed, unique kind-1 events, fresh DB, every
event signature-verified and committed by the single SQLite writer);
`nostr-fanout` subscribers REQ `{"kinds":[1],"limit":0}`, publishers at a fixed
offered rate, latency = publish → delivery.

| Metric | original transport (ecaf2ab `main`) | old uSockets backend (ecaf2ab) | ngws (this branch) |
|---|---|---|---|
| nostr-pub EVENT/s (accepted) | 8.3k | 20.3k | 22.1k |
| fanout 1000 subs @2000 ev/s: deliveries/s | 470k (fell behind) | 416k (fell behind) | **1.99M** (kept up) |
| ... p50 / p99 / p999 latency | 3.05 s / 5.3 s / 5.3 s | 3.3 s / 5.6 s / 5.8 s | **6.4 ms / 22 ms / 37 ms** |
| ... server RSS at end | 85 MB | 1300 MB | 25 MB |
| fanout 5000 subs @500 ev/s: deliveries/s | 533k | 328k | **2.50M** |
| ... p50 / p99 / p999 | 3.96 s / 5.8 s / 6.0 s | 3.7 s / 6.4 s / 6.4 s | 36 ms / 64 ms / 91 ms |
| idle conns, bytes/conn | 32.7 KB (stalled at 9761/10k) | 571 B (10k) | 596 B (50k) |

Publishing is bound by Schnorr verification + the single writer, not the
transport (server ~205% of 4 CPUs).

## Sanitizers

`NG_SAN=thread ./nob` / `NG_SAN=address ./nob` produce `build/*_thread` /
`build/*_address`. Under test_core, test_ws2, live broadcast and ngload
pub/fanout/hold: 0 ThreadSanitizer warnings, 0 ASan/LSan errors.

## Writer tuning + duplicate guards (Nov 2026)

`tools/bench/pub.sh <bin> <conns> <pipeline>`: 1.5M unique pre-signed
kind-1 events, fresh DB on the root disk (virtio), server CPUs 0-3, client
4-7, 6 s. Latency = EVENT sent → its OK (OK is sent only after COMMIT).

| Load | before (e04b0cc) | after |
|---|---|---|
| 64 conns × 16 in flight: EVENT/s | 21.3k | 43-48k |
| ... OK latency p50 / p99 | 47 ms / 60 ms | 19 ms / 35-120 ms |
| 256 × 16: EVENT/s | 23.7k | 50-52k |
| 16 × 1 (light): EVENT/s | 11.4k | 15.5-20k |
| ... OK latency p50 / p99 / p999 | 1.13 / 4.3 / 9.4 ms | 0.7-0.85 / 1.4-1.5 / 4.2 ms |
| fanout 1000 subs @2000 ev/s p50/p99 | 6.2 / 11.7 ms | 6.6 / 10.4 ms |
| fanout 5000 subs @500 ev/s p50/p99 | 38 / 105 ms | 38 / 56 ms |

Writer CPU before: ~82% busy, of which COMMIT was the largest part (WAL
autocheckpoint with fsync inside COMMIT, 1 MiB pages). What changed:
- page_size 1 MiB → 4 KiB (new DBs; each insert rewrites whole dirty pages);
- historical writer connection `synchronous=NORMAL` (current default is FULL;
  set `db_sync=normal` in the runtime config to reproduce; was the per-connection default
  FULL), `wal_autocheckpoint=0`, WAL checkpoints on a separate thread
  (PASSIVE every 250 ms; RESTART only past 1 GiB of WAL);
- prepared statements reused (`sqlite3_prepare_v3 PERSISTENT` + reset);
- broadcast body serialization + tag parsing moved from the writer to the
  worker that verified the event; fan-out is one job per worker per batch;
- redundant `kindidx` and `pubkeyprefix` indexes replaced by one
  `(pubkey, kind)` index (also serves replaceable lookups);
- batch cap 1024 → 4096 (NG_BATCH_MAX); a size/time linger exists
  (NG_LINGER_US / NG_BATCH_MIN) but is off: COMMIT cost here scales with
  dirtied pages (≈ events), not commits, so lingering only added latency.

Remaining tail: the RESTART checkpoint holds the write lock through a DB
fsync (~100-250 ms on this disk), once per ~1 GiB of WAL (~120k events).
Pure-PASSIVE (`NG_WAL_RESTART_FRAMES` huge) has max ≈ 16 ms but lets the WAL
grow without bound under non-stop writes.

Duplicate guards: `tools/run_dedupe_tests.sh` (23 checks, with and without
the in-flight/recent set), clean under TSan and ASan.


## Configurable durable writer default (Nov 7, 2026, CST)

The writer now defaults to `synchronous=FULL`. Set `db_sync=full` (default)
or `db_sync=normal` in `nostrogotho.conf`, or select a file with
`--config path`. `NG_SYNC` no longer overrides the file. The startup connection
also uses FULL. Publish OK remains after COMMIT and duplicate guards are unchanged.

Quick durability comparison: same local shared 8-core host, release `./nob`
build (GCC `-O3 -march=native -flto=auto`, no PGO), fresh databases on the
root disk for each run. Server pinned to CPUs 0–3, client to 4–7; 64 publishing
connections, pipeline 16, 4 client threads, 6 seconds per run, pre-signed events
from `ev1500k.txt`. Order: FULL, NORMAL, FULL, NORMAL. These are short exploratory
runs, not production capacity claims.

| Writer mode | Run 1 events/s | Run 2 events/s | Mean events/s |
|---|---:|---:|---:|
| FULL (default) | 48,989 | 53,057 | 51,023 |
| NORMAL (opt-in) | 66,599 | 66,282 | 66,441 |

All four runs had zero rejections. Build, `test_core.py`, `test_ws.py`,
`test_ws2.py`, `test_nip13.py`, and `tools/run_dedupe_tests.sh` (both dedupe
modes) passed with the FULL default. `tests/test_config.py` passed all 11 startup
cases (defaults, both valid settings, comments/whitespace, invalid/missing files).

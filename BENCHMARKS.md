# Benchmarks

All numbers from one 8-core x86-64 Linux VM (~16 GB RAM, shared with other
workloads), loopback networking. Server pinned to CPUs 0-3, `ngload` to CPUs
4-7 (`taskset`). Runs 3-6 s after 1 s warmup, repeated 2-3x; ranges shown.
ngws/relay: gcc `-O3 -march=native -flto=auto`. uWS reference
(`tools/bench/uws_ref.cpp`, uWebSockets + uSockets, 4 threads, SO_REUSEPORT)
built with clang (zig cc) `-O3 -march=native` — only used for benchmarking.
Client: `build/ngload` (pure C, epoll, multithreaded, multiple source IPs).
Scripts: `tools/bench/*.sh`; events from `tools/bench/genev.py`.

## Raw WebSocket: ngws vs uWebSockets (4 server threads)

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
- writer connection `synchronous=NORMAL` (was the per-connection default
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

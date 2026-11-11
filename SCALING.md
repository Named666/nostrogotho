# Relay connection scaling and bottleneck diagnostic

## Verdict

**100,000 concurrent idle relay WebSockets passed, with zero connect errors or
unexpected disconnects. One million concurrent users is NOT validated.** The
next requested plateau (250,000) was rejected by the memory safety preflight,
not reached and failed. 500,000 and 1,000,000 were not attempted. The process
FD hard limit independently prevents 1M in one relay process on this box.

Run date: 2026-11-07, America/Chicago (CST). Baseline source: `06a0d72` on
`usockets`; tooling/diagnostic changes committed locally as `8639f42`. These are new **full relay** measurements, not the earlier ngws
microbenchmark results, and not a new µWebSockets comparison.

## Machine and limits

- KVM Linux 6.12.113+, eight Intel Xeon vCPUs, one thread/core; 15.63 GiB RAM,
  **no swap**. Other box services remained running. Approximately 3.4–3.6 GiB
  MemAvailable before the actual ramp, not the full installed RAM.
- Relay pinned to CPUs 0–3: `NG_IO_THREADS=2`, `NG_WORKERS=4`, **exactly one
  SQLite writer** and one PASSIVE checkpointer. Clients pinned to CPUs 4–7,
  four generator threads. No nginx or TLS in the measurement path.
- SQLite WAL, explicit `db_sync = full`; optimized build via `./nob`
  (`-O3 -march=native -flto=auto`). Isolated temporary database at each step;
  the checkout database was not touched.
- Soft/hard `RLIMIT_NOFILE`: 524,288 / 524,288. Both processes use the hard
  limit. Attempt to raise to 1,048,576: `not allowed to raise maximum limit`.
- `fs.file-max=9223372036854775807`; `fs.nr_open=1048576`.
- Ephemeral ports: 32768–60999, **28,232 per source IP/destination tuple**.
  ngload already supports `-i`; 2, 5, and 8 distinct 127.0.0.x source addresses
  were used at 10k, 50k, and 100k. Bind errors are now checked and counted.
- `tcp_mem=190791 254388 381582` pages (about 745 / 994 / 1491 MiB at 4 KiB).
  `tcp_rmem=4096 131072 6291456`, `tcp_wmem=4096 16384 4194304` bytes.
  `somaxconn=4096`. Sysctl paths are read-only; no global tunables changed.
- Agent cgroup has no memory/CPU max; physical-host MemAvailable is the
  safety constraint. `/proc/slabinfo` is denied. `perf` is not installed;
  gprof and `/proc` thread sampling were used instead.

## Method and results

Fresh relay per plateau. First establish N idle connections, wait **30 seconds
without application traffic**, then add approximately 1% of N broad kind-1
subscribers (`REQ` with `limit:0`, one publisher) for 12 seconds at 3 events/s.
This sidecar means **N idle + subscribers + one publisher**, not exactly N total
and not 100% subscribed. After it exits, publish for eight seconds using 64
connections × 16 in-flight, with different event IDs. Idle sockets remain for
62 seconds after connection establishment. A separate 100k idle run then
held for **158 seconds**, crossing the default 120-second ping deadline:
100,000 remained open, zero failures/drops, RSS 61.4 → 64.0 MiB, relay/client
CPU each ~1%. This covers one ping cycle, not a multi-hour soak. All EVENTs are valid pre-signed
Schnorr events; no signature or dedupe bypass. Publish rate counts accepted OKs.

RSS is measured immediately after opening idle sockets, before publish/cache
warm-up. Bytes/connection subtract the fresh relay RSS. CPU is sampled per
thread. Safety policy keeps **2 GiB MemAvailable**, with a 15% projection
margin before starting a larger plateau. No OOM was induced.

| Idle N | Source IPs | Connect seconds / rate | Connect errors / drops | Idle relay RSS | Incremental relay B/conn | Subscribers | Deliveries/s | Delivery p50 / p99 | Accepted publish/s |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10,000 | 2 | 0.34 / 29.4k/s | 0 / 0 | 11.84 MiB | 635 | 100 | 308 | 2.425 / 4.391 ms | 36,049 |
| 50,000 | 5 | 0.75 / 66.7k/s | 0 / 0 | 33.91 MiB | 589 | 500 | 1,541 | 3.113 / 5.112 ms | 29,349 |
| 100,000 | 8 | 1.10 / 90.9k/s | 0 / 0 | 61.39 MiB | 583 | 1,000 | 3,081 | 3.867 / 6.685 ms | 29,996 |
| 250,000 | — | **not attempted: projected memory** | — | — | — | — | — | — | — |
| 500,000 | — | **not attempted after memory stop** | — | — | — | — | — | — | — |
| 1,000,000 | — | **not attempted; memory and FD limit** | — | — | — | — | — | — | — |

Each low-rate fanout run accepted 37 events and delivered all 37 × subscriber
count within the measurement window. No rejected EVENTs. Publish ACK p50/p99:
20.97/101.71 ms, 28.84/91.23 ms, 23.33/95.42 ms, respectively. Relay RSS at the
end of publish was 144.7 / 146.7 / 176.7 MiB; this includes SQLite caches,
allocator retention and event-processing buffers, so it is not idle cost.

At the 100k plateau, minimum observed MemAvailable was **2,411 MiB**. After
cleanup, available memory was 3,618,545,664 bytes. Measured two-endpoint
anonymous+kernel cost was 9,367 B/connection; projected 250k cost with margin
was **2,693,018,112 bytes**, leaving only 883 MiB—below the 2 GiB reserve.
This is an environment safety ceiling, **not a discovered relay connection
capacity ceiling**. Three short runs do not establish a trend in publish
throughput; filesystem and shared-host variability matter.

## Memory: why 244 bytes was not a million-user budget

Cgroup deltas include **both loopback TCP endpoints**, client FD/epoll state
and unrelated background noise. They cannot be attributed entirely to the
server. RSS includes shared mappings, so small-count per-connection estimates
have fixed-cost noise. Kernel deltas are best interpreted at 100k.

| N | Relay incremental B/conn | Generator RSS B/conn (includes fixed cost) | Kernel B/pair | Unreclaimable slab B/pair | Reclaimable slab B/pair | Anonymous + kernel B/pair |
|---:|---:|---:|---:|---:|---:|---:|
| 10k | 635 | 884 | 8,334 | 6,230 | 2,082 | 9,648 |
| 50k | 589 | 697 | 8,194 | 6,108 | 2,080 | 9,442 |
| 100k | 583 | 672 | 8,133 | 6,050 | 2,080 | 9,367 |

At 100k the kernel increment is ~776 MiB, versus ~56 MiB incremental relay
RSS and ~64 MiB client RSS. TCP `alloc` rose to ~200k sockets. The IPv4
`inuse` counter alone shows ~100k because the dual-stack listener's accepted
sockets also appear in `sockstat6`. TCP `mem` fluctuated near zero to a few MiB;
**that field measures queued TCP pages, not socket structs, FD tables, epoll
entries or all slab memory**. It is not a complete kernel memory budget.
The cgroup `sock` delta at the idle snapshot was approximately zero despite
~8 KiB/pair of kernel growth. No fabricated precision by socket/slab class:
`slabinfo` is unavailable, and the division between endpoints is an estimate.

The previous ~244 B figure described the plain ngws layer only. The full relay
adds connection/protocol/AUTH state. Behind nginx there are roughly **three
on-host TCP endpoints per user** (public nginx socket, nginx upstream socket,
relay socket), not one: naively extending this measurement gives ~12 KiB/user
kernel bookkeeping alone, **before TLS, nginx, active buffers and queues**.
Use this only for initial sizing; measure the actual TLS topology.

## Bottleneck diagnostic

### Optimized full-sync relay at 100k idle

During the quiet 30-second interval, every relay thread was approximately 0%
CPU (100 Hz accounting resolution). With 1k subscribers at 3 events/s, aggregate
relay CPU was only ~2%. During the eight-second publishing phase, the relay
used ~181% CPU: worker threads roughly 30% each while active (26% averaged
across the larger sampled interval), writer about 48% averaged, I/O loops
about 1% each. No accept/I/O thread was pegged by idle connections.

The writer's built-in wall-clock statistics over the entire 100k stage:
**dispatch 1.17 s, COMMIT 6.44 s, post/broadcast 0.49 s**, 241,187 processed
events in 541 batches (average 445.8). COMMIT dominates writer wall time.
The writer is the serialized durable-write stage, but it was **not measured
at 100% CPU** in the optimized run. Do not confuse disk/fsync waiting with
CPU saturation. Preserve FULL durability; improve storage latency and measured
batching rather than adding SQLite writers.

### Sampling profiles

A separate `-O2 -g -pg -no-pie` build, still FULL sync, was exercised with
100k idle connections, then 1k subscribers × 300 events/s, and separately
closed-loop publishing. Profiling changes code generation and adds significant
call instrumentation overhead. **Do not use its 16.3k publish/s as a production
capacity result.** Flat samples include setup and teardown; gprof call counts
are not trustworthy in multithreaded programs. Percentages below are sampled
user-space time, excluding time sleeping/in the kernel/shared libraries.

- Publishing: `secp256k1_gej_double` 28.27%, `gej_add_ge_var` 14.73%,
  `gej_add_zinv_var` 6.29%, `fe_sqrt` 6.29%, `ecmult_strauss_wnaf` 5.23%.
  Signature verification dominates sampled CPU. JSON parse 2.14%, WAL checksum
  2.14%, followed by SQLite record compare/VM/B-tree work. No justification
  for weakening verification. Keep cheap dedupe checks before crypto.
- Fanout: body retain 9.84%, connection unref 9.02%, `run_outtask` 7.87%,
  connection retain 6.72%, `loop_post` 5.25%, `flush` 3.93%. Refcount/cache-line
  traffic and per-delivery output work are significant candidates. Batching
  lifetime references by outtask/loop could help, but needs race/slow-reader
  tests; no speculative lifetime rewrite was made.
- Profiled fanout I/O loops used 56% and 59% CPU; workers 15–21%, writer 3.6%.
  Profiled publishing used ~87% writer CPU, 42–45% per worker, I/O 1–2%.
  Instrumentation made the serialized writer hotter; this is not evidence
  that the optimized writer was CPU-pegged.
- `/proc` 100 ms wait-channel sampling found epoll waits on idle I/O loops,
  condition/futex waits on workers, and `folio_wait_bit_common` /
  `jbd2_log_wait_commit` during durable writes. Futex observations alone
  **cannot distinguish condition-variable sleep from mutex contention**.
  Neither a mutex-contention rate nor exact syscall counts/latencies were
  available without perf/lock tracing. No evidence here supports declaring
  the queues lock-free of contention.
- Fanout performs a send/writev path per recipient; logical deliveries are
  not free, even if the body is shared. Distribution across I/O loops and
  frontend shards is the scale-out lever, not SQLite writer proliferation.

A separate optimized (non-profiled) 300 events/s × 1k subscriber test with
100k idle sockets delivered **299,937/s**, p50 **2.195 ms**, p99 **7.864 ms**,
relay CPU **116%**, client CPU **107%**, no connection drops or EVENT rejects.
There were 4,511,168 deliveries and 4,512 ACKs: the small difference from
ACKs × subscribers is a measurement-end/drain uncertainty, not proof of loss
or perfect delivery. The low-rate runs have exact delivery completeness.

### High-fanout ceiling probe (optimized final build)

With 100k idle sockets plus 1k broad subscribers, increasing to **1,000
EVENTs/s** achieved **999,496 deliveries/s** for 15 seconds, p50 **5.571 ms**,
p99 **8.913 ms**, 0 rejects, 0 connection failures/drops. Total relay CPU was
227%, client 207%, minimum MemAvailable 2,621 MiB, final relay RSS 99.5 MiB.
15,005 ACKs versus 15,001,174 measured deliveries leaves 3,826 deliveries
unaccounted at the measurement boundary (~0.026%); this is not a loss audit.

The named I/O threads were **96.7% / 97.7% of a core**, including **91.2% /
91.1% system CPU** and only 5.5% / 6.7% user CPU. Worker utilization was
4.4–10.1%, writer 8.0%, checkpointer 0.2%. This is the strongest observed
**fanout bottleneck: the two I/O loops saturate in the kernel send/socket
path**, not the SQLite writer or filter workers. Increasing I/O loops and
physical cores, sharding connection ownership, and measuring kernel syscall
costs are the next experiments. More workers alone will not solve this case.
The exact syscall mix and lock contention still need perf/trace measurement.

**One million deliveries/s is not one million connections/users.** This test
has 1,000 active subscribers, each receiving ~1,000 events/s, alongside 100k
idle connections; it does not show the latency of sending one event to 1M
subscribers. No higher rate was claimed: the I/O cores are already nearly
saturated at the probe's offered rate.

## Failure points and remedies

| Constraint / observation | Concrete limit or evidence | Remedy / next test |
|---|---|---|
| Host memory safety | 250k projected to leave 883 MiB, policy requires 2 GiB | Dedicated larger relay host; put generators on separate hosts; use live RSS + kernel/cgroup tracking |
| Process descriptors | hard 524,288; raising refused | Admin/systemd/container limits and `fs.nr_open` above intended per-process total; split acceptors if necessary |
| Source port space | 28,232 tuples/IP here, not an assumed 64k | Existing multi-source bind (`-i`); ~72 source IPs for 1M at <=15k/IP; multiple generator machines/addresses |
| Accept surge | was vendored uSockets `listen(...,512)`; sysctl cap 4096 | **Done (a9f71c9):** `listen_backlog` config, default = `net.core.somaxconn`; still pace reconnect storms |
| TCP payload memory | tcp_mem high ~1.46 GiB on this host; defaults permit large autotuned per-socket buffers | Dedicated-host sizing; test modest buffers with realistic RTT/BDP, monitor TCP memory pressure/drops; idle socket structs cannot be tuned away with SO_RCVBUF |
| Full-sync serialized write path | COMMIT 6.44 s of 8.10 s writer timed work | Low-latency durable NVMe, batching measurements under a latency SLO, keep one writer |
| Verification CPU | secp256k1 arithmetic dominates sampled publish CPU | **Done (5e22ba3):** verification runs on all workers, with BIP-340 batch verification per job list; still never skips checks |
| Fanout amplification | ~1M deliveries/s pegs both I/O cores (~97%, mostly system CPU); output/refcount work scales with recipients | **Done (a89b4b8):** `io_threads` default = cores, no per-delivery refcount atomics; kernel send cost remains the floor |
| Slow readers / overload | was: 32 MiB per-socket cutoff, unbounded worker/writer queues | **Done (08c7170):** per-connection and process budgets, slowest-reader shedding, bounded queues, CLOSED/OK false "error: ..."; per-identity quotas still open |
| Expensive REQ / database growth (not tested) | Readers execute queries on worker threads; tiny fresh DB in this test | Query time/row/result-byte limits; mature-database read load and long WAL/checkpoint tests |
| Keepalive timer sweep / reconnect herd | default 120 s ping timeout; timer walks sockets | Test multiple ping cycles, jitter reconnection/keepalive scheduling, watch event-loop lag |
| Profiling visibility | no perf; slabinfo denied | Repeat on staging host with perf stat/record, scheduler/lock and syscall tracing; separate kernel time and TCP allocation classes |

## Changes made

- Pure-C ngload now releases the two empty 4 KiB handshake buffers in hold
  mode instead of retaining them per idle client; it reallocates for pings as
  needed. This removes up to ~8 KiB/client of avoidable generator retention.
  Hold epoll sleep is 100 ms rather than 1 ms. No relay semantics changed.
- Check bind failures; report connect errno counters plus connected/dropped
  counts. Existing multi-source-IP option reused, no new dependency.
- Linux thread names (`ng-worker-N`, `ng-writer`, `ng-checkpoint`, `ng-io-N`)
  added for future operational diagnostics. No write parallelism introduced.
- Reproducible bounded `tools/bench/scaling.py` and `diagnose.py`; raw logs,
  specs and flat profiles under `tools/bench/scaling-results/`.

## Overload, fan-out, backlog and verification work (Nov 10, 2026, CST)

Four commits on `usockets` (not pushed), each followed by the full suite.
Numbers come from the same shared 8-core VM, relay on CPUs 0-3 and clients
on 4-7, 1 k subscribers plus 20 k idle sockets for fan-out and 64 publishers
x 16 in flight with FULL sync for publish. Other agents were using the host,
so treat run-to-run spread of 10-20% as noise. Raw summaries are in
`tools/bench/scaling-results/nov10-*.txt`.

### 1. Bounded output and slow readers (08c7170)

Config keys (with K/M/G suffixes):

| Key | Default | What it does |
|---|---|---|
| `conn_out_max` | 4M | Per-connection output budget. Over it, the connection is closed. Above half of it, REQ gets `CLOSED` and EVENT gets `OK false` with "error: output backlog too large, read faster". |
| `total_out_max` | 1G | Process-wide budget (socket backlogs plus posted outboxes). At 75%, ngws closes the largest backlogs over 64 KiB until usage is under 50%. At 90%, workers refuse new REQ/EVENT. |
| `worker_queue_max` | 16M | Bytes queued per worker. When full, the I/O thread answers inline with "error: relay overloaded, try again later" and never blocks. |
| `writer_queue_max` | 65536 | EVENTs queued for the single writer. Over it, `OK false` with the overload error. |
| `conn_pending_max` | 1024 | Unprocessed messages per connection. |

- Stored-event replies to a REQ are capped at `conn_out_max/2` bytes. EOSE
  still follows.
- `tests/test_overload.py` passes 25/25 and covers:
  - (A) one non-reading subscriber among a publisher and a fast subscriber: the slow reader is closed after about 1.9 MB of about 12 MB, the others get 1500/1500.
  - (B) four non-reading subscribers over the total budget: all four are closed, every EVENT is answered, and the relay recovers.
  - (C) a slow reader under its limit gets CLOSED / OK false for new work.
  - (D) a REQ flood: 292 of 300 are shed inline with CLOSED, and each is answered exactly once.
  - (E) writer queue overflow: 296 OK false, then accepted on retry.
  - (F) an oversize message is shed by the I/O thread.

Fan-out overload (rate 4000 and 8000 events/s, i.e. 4M or 8M deliveries/s offered):

| | before (33cdf36) | after |
|---|---|---|
| 1k subs, rate 4000, io=2 | 3.3-3.7M/s delivered, p50 134-369 ms, p99 1.1-3.1 s, RSS 0.7-1.7 GB and growing | 4.0M/s, p50 10.6-11.3 ms (after item 2) |
| rate 8000 | stopped by the 2 GiB headroom guard (unbounded growth) | io=4: 4.08M/s, 707 lagging subscribers closed at `conn_out_max`, 12 k EVENTs refused with OK false, p50 285 ms / p99 3.0 s, RSS 2.06 GB, bounded. io=2: 3.29M/s, 48 k refused, p50 512 ms / p99 4.3 s, RSS 2.40 GB |

Peak RSS under sustained overload is about 2x `total_out_max`, because the
budget counts payload bytes while allocator retention and kernel socket
buffers (up to `tcp_wmem[2]`, about 4 MB per socket on loopback) sit on top.

### 2. Fan-out send path (a89b4b8)

- `io_threads` defaults to the number of usable CPUs (`sched_getaffinity`).
  Connections spread across the loops with SO_REUSEPORT.
- Each event body is serialized and framed once and shared.
- Outbox records no longer take per-recipient connection references:
  deferred unrefs are released after the outbox flush, and the final free
  is a FIFO task on the connection's own loop.
- Body references are taken once per run of records and released in bulk.

1k subscribers plus 20 k idle sockets, workers=4, deliveries/s and
publish-to-delivery latency:

| Offered | before, io=2 | after, io=2 | after, io=3 | after, io=4 |
|---|---|---|---|---|
| 1M/s | 1.0M/s, p50 6.3-7.1 ms, p99 15-21 ms | 1.0M/s, p50 7.1-8.4 ms | p50 3.8-4.3 ms, p99 10-18 ms | p50 2.7-2.8 ms, p99 6.9-21.8 ms |
| 4M/s | 3.3-3.7M/s (saturated), p50 134-369 ms, p99 1.1-3.1 s | 4.0M/s, p50 10.6-11.3 ms, p99 33-40 ms | 4.0M/s, p50 6.7 ms | 4.0M/s, p50 5.2-5.3 ms, p99 12-34 ms |

- I/O thread CPU at 1M/s drops from about 90% per thread (io=2) to 60-68%
  (io=4). It is still about 90% system time: kernel `send` is the floor.
- One earlier baseline run did reach 4M/s at p50 8.8 ms, so the saturation
  point at io=2 sits close to 4M/s on this host.

### 3. Listen backlog (a9f71c9)

- `listen_backlog` (0 = `net.core.somaxconn`, capped by it) replaces the
  vendored uSockets `listen(..., 512)`.
- The patch is recorded in `thirdparty/VENDOR.md`.
- The startup line prints the effective `backlog=`.
- `tests/test_listen_backlog.py` reads the listener's Send-Q from `ss`
  (4/4).

30 k-connection burst:

| | before (512) | after (4096 = somaxconn) |
|---|---|---|
| Time to connect all | 2.5-3.4 s | 0.7-1.4 s |
| ListenOverflows | about 15.6 k | 0-839 |
| Failed connects | 1 | 0 |

### 4. Signature verification (5e22ba3)

- Verification already ran on the worker pool; a connection is pinned to one
  worker, `shard = id % workers`.
- Each worker now batch-verifies the EVENTs of a job list before processing
  them (`src/schnorr_batch.c`, built on the vendored secp256k1's
  `ecmult_multi_var`):
  - 128-bit randomizers from a tagged hash
  - lifted pubkeys cached
  - chunks of up to 256; failures are bisected down to groups of 4
- Proven `(sig, id, pubkey)` triples go into a thread-local table that
  `signature_verify` consults. The id is still recomputed from the
  serialization, so a triple that doesn't match byte for byte still gets the
  individual check.
- Events that admission would shed are skipped.
- `NG_BATCH_VERIFY=0` turns it off.

Microbenchmark, one core, against individual `secp256k1_schnorrsig_verify`
(about 26-33 k sig/s on this host):

| Batch size | 8 | 16 | 32 | 64 | 128 | 256 | 512 |
|---|---|---|---|---|---|---|---|
| Speedup, 256-bit randomizers (first version) | 1.12x | 1.11x | 1.13x | 1.16x | 1.31x | 1.44x | 1.43x |
| Speedup, 128-bit randomizers, no key cache | 1.19x | 1.31x | 1.28x | 1.29x | 1.35x | 1.57x | 1.66x |
| Speedup, 128-bit randomizers plus key cache (repeated keys) | 1.50x | 1.57x | 1.60x | 1.72x | 1.79x | 2.08x | 2.22x |

Publish with FULL sync, 64 connections x 16 in flight, 6 s, events/s:

| Config | before (33cdf36) | item 4, batch off | item 4, batch on |
|---|---|---|---|
| default workers, 64 authors | 27.9 / 35.4 / 35.2 k | 34.9 / 40.0 / 36.9 k | 33.8 / 39.2 / 39.9 k |
| default workers, all distinct authors | 31.5 / 30.0 k | 32.5 / 31.9 k | 32.4 / 31.8 k |
| workers=1 (verify-bound), 64 authors | 23.8 / 23.0 k | 23.1 / 22.8 / 23.7 / 23.5 k | 34.0 / 30.0 / 34.4 / 32.0 k |
| workers=1, distinct authors | 24.4 / 24.1 k | 23.4 / 22.4 / 24.2 / 22.4 k | 30.0 / 24.9 / 28.8 / 26.3 k |

- At the default worker count, publish with FULL sync is bound by the
  writer, not by verification:
  - the writer thread is at 76-84% CPU
  - COMMIT/fsync takes about 4.5-5 s of each 7 s
  - throughput is flat within noise
- Batch verification still lowers worker CPU per event by roughly 10-20%
  (for example 4 x 44% → 4 x 35% at the same rate).
- When verification is the bottleneck (one worker), batch on vs off is about
  +40% with repeated authors and +10-25% with all-distinct authors.
- The baseline sized its pools from `nproc`, so it ran 8 workers even under
  `taskset -c 0-3`. The new default reads the affinity mask, giving 4 workers
  here. The baseline's verify-bound rows use `NG_WORKERS=1`.
- An earlier FULL-sync measurement on Nov 7 (BENCHMARKS.md) showed 49-53 k on
  a quieter host. Disk and host contention explain the lower absolute values
  today; compare within a table only.

### 5. Writer cost of the NIP-01 tag index and NIP-50 search (e6c656a, 9b1c4fc)

The tag index (182fe68) and the FTS5 search index (2f1138c) both add writes to
the one writer thread. Two changes recover most of that cost:

- FTS5 is fed once per batch with one `INSERT ... SELECT` before COMMIT (and
  before any DELETE in the same batch). It no longer uses a per-row trigger.
- Only `tag_index_letters` (default e,p,a,q,t,d,h,k) are indexed, capped at
  `tag_index_max_per_event` (default 2000). Other letters, and tags past the
  cap, are answered from the tags JSON.

Publish with FULL sync, 64 connections x 16 in flight, relay on CPUs 0-3.
Events/s, median of 3 interleaved runs (18:46-18:52 CST, runs in
`/workspace/bench/gate-results/perf2-pub.txt`):

| dataset | d2f276e (no tag/search index) | 04f344e | d8d8a31 | d8d8a31 vs 04f344e |
|---|---|---|---|---|
| ev1500k (1 tag, content "0") | 45,492 | 29,580 | 48,332 | +63% |
| ev400k_tags (4 tags with hints) | 43,310 | 20,193 | 25,070 | +24% |
| ev400k_text (25-word content) | 40,519 | 17,054 | 24,121 | +41% |

Tagged and text events still cost about 40% compared with having no index.
That is the price of O(log N) `#e`/`#p` lookups and search. The fan-out and
echo results at d8d8a31 match the earlier baselines:

- fan-out: 1.99M/s for 1k subscribers and 2.50M/s for 5k
- uncapped fan-out: 3.98M/s of 4M/s offered
- 50k idle connections: 666 B/conn
- echo: 3.15M/s at 64 B and 1.59M/s at 4 KB

### Still open

- One busy connection's verification remains serialized on its worker.
- Peak RSS can exceed the budget by about 2x (see above).
- REQ `limit:0` still returns up to 500 stored events (now byte-capped).
- There are no per-identity quotas.

## Production starting point for one million concurrent users

This is **a tuning proposal, not certified capacity**. Registered users and
simultaneous sockets are different. Define active fraction, events/s, average
and worst-case recipients/event, historical-read demand, event size and p99
SLO first. A million broad subscribers × 3 events/s means **3M deliveries/s**,
not 3 events/s; at ~400 B/event it is already ~1.2 GB/s application payload
(~9.6 Gbit/s) before TCP/TLS framing. Plan fanout shards and network headroom.

1. Start with a dedicated **64–128 GiB staging footprint** (or multiple
   frontend nodes), separate load-generator hosts, fast durable storage and
   enough physical CPU/network. Validate actual nginx/TLS memory; the kernel
   extrapolation is not an allocation guarantee. Keep one owner/writer per
   database and partition/replicate fanout frontends around that owner.
2. For a single-process million-socket backend, example admin/systemd limits:
   `fs.nr_open=2097152`, `fs.file-max>=8000000`,
   `LimitNOFILE=2097152`. Count nginx's two FDs/user plus relay's one FD/user;
   upstream connections consume source ports as well. Use multiple upstream
   relay IPs/listen ports and/or explicitly distributed proxy source IPs:
   **a single nginx source IP → one upstream IP:port still runs out of
   ephemeral ports**, even when public client IPs are diverse.
3. Example nginx starting shape: `worker_processes auto;`,
   `worker_rlimit_nofile 1048576;`, and
   `events { worker_connections 524288; use epoll; }`. Each proxied WebSocket
   uses roughly two worker connections; do not equate worker_connections to
   users. Set WebSocket Upgrade/Connection headers, HTTP/1.1 upstream,
   `proxy_buffering off`, suitable 300 s read/send timeouts, TCP_NODELAY, and
   an explicit listen backlog. Tune TLS handshake/session memory and rate-limit
   reconnect storms. Validate the nginx build/version and upstream tuple plan.
4. On a **dedicated** host, start testing `somaxconn=65535`,
   `tcp_max_syn_backlog=65535`, `ip_local_port_range="1024 65535"` with
   reserved-service-port exclusions; raise the application's listen backlog
   too. Do not enable insecure reuse tricks to hide tuple exhaustion.
   Trial `tcp_rmem="4096 32768 262144"` and
   `tcp_wmem="4096 16384 262144"` only against realistic WAN latency/loss:
   too-small caps hurt BDP/throughput. Size tcp_mem for that host, not this
   VM's values. Avoid arbitrary global sysctl changes on a shared box.
5. Before a 1M claim: distributed 250k/500k/1M ramps, hours-long soak through
   several keepalive/checkpoint cycles, nginx TLS, realistic bandwidth/RTT,
   slow/non-reading clients, broad-subscription hotspots, reconnect storms,
   reader workloads and a mature database. Alert on event-loop lag, queue
   bytes/age, writer batch/commit latency, WAL size, TCP/slab memory, FD usage,
   rejects, disconnects and p99 end-to-end delivery.

## Validation

Final optimized relay build succeeded. `test_core.py`: **15/15** checks;
`test_dedupe.py`: **23/23** with the recent/in-flight set enabled and **23/23**
with `NG_DEDUPE_RECENT=0`; `test_ws.py`: connected and received AUTH;
`tests/rfc6455_conformance.py` against the echo transport: **80/80 strict**;
`tests/test_config.py`: **11/11** startup cases (19 after the Nov 10
config keys; see the section above for the current suite). Dedupe runs used fresh FULL-sync
databases. Python WebSocket/crypto tests used the existing
`/workspace/ngvenv/bin/python` environment. Refused-connection diagnostics
were also checked separately. No changes were pushed.

## Reproduction and uncertainty

```sh
./nob
# Generate /workspace/bench/ev400k.txt first if absent:
# /workspace/ngvenv/bin/python tools/bench/genev.py 400000 /workspace/bench/ev400k.txt
cc -O3 -march=native -std=gnu11 tools/ngload.c -pthread -lm -o build/ngload_soak
python3 tools/bench/scaling.py
# Profile build command is recorded in scaling-results/profile-build.txt.
python3 tools/bench/diagnose.py --relay "$PWD/build/main_profile" --gprof --case fanout
python3 tools/bench/diagnose.py --relay "$PWD/build/main_profile" --gprof --case publish
python3 tools/bench/diagnose.py --relay "$PWD/build/main" --case fanout --rate 1000 --label=-1000
python3 tools/bench/diagnose.py --relay "$PWD/build/main" --case keepalive --duration 150
```

Loopback is not a WAN. Server and generator share memory, kernel and a VM;
CPU pinning isolates scheduling groups, not kernel/LLC/storage effects.
Loopback TIME_WAIT reuse is enabled (`tcp_tw_reuse=2`), so repeated ramp
connection turnover is not representative of arbitrary WAN reconnects. One
short sample per plateau, rounded connection times, 100 Hz CPU counters,
100 ms wait snapshots and finite histograms limit precision. Fanout latency
starts before the client send, so includes queueing/validation/commit/delivery,
not just transport. Publisher OK ordering and final measurement boundaries
introduce small count/timing uncertainty. These measurements **do not prove
1M users**, real-network performance, overload safety or long-term stability.

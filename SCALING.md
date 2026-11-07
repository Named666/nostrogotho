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
| Accept surge | vendored uSockets `listen(...,512)`; sysctl cap 4096 | Expose/increase actual listen backlog as well as somaxconn; pace reconnect storms, test burst acceptance; sysctl alone does not remove 512 |
| TCP payload memory | tcp_mem high ~1.46 GiB on this host; defaults permit large autotuned per-socket buffers | Dedicated-host sizing; test modest buffers with realistic RTT/BDP, monitor TCP memory pressure/drops; idle socket structs cannot be tuned away with SO_RCVBUF |
| Full-sync serialized write path | COMMIT 6.44 s of 8.10 s writer timed work | Low-latency durable NVMe, batching measurements under a latency SLO, keep one writer |
| Verification CPU | secp256k1 arithmetic dominates sampled publish CPU | Scale validation workers/cores, keep early dedupe; never skip signature checks |
| Fanout amplification | ~1M deliveries/s pegs both I/O cores (~97%, mostly system CPU); output/refcount work scales with recipients | Shard fanout/connection ownership; investigate batched refs; benchmark popular broad subscriptions |
| Slow readers / overload (code risk, not induced) | 32 MiB per-socket output cutoff; writer/worker job queues lack a global admission budget | Add per-connection/per-identity quotas, small configurable backlog budgets, aggregate queue limits and load shedding before production; 1M × 32 MiB is untenable |
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
`tests/test_config.py`: **11/11** startup cases. Dedupe runs used fresh FULL-sync
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

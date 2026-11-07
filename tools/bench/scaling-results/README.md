# Scaling evidence — 2026-11-07 (CST)

See `../../../SCALING.md` for interpretation, method and limitations.

- `summary.json`: compact ramp measurements, inferred named thread roles and CPU.
- `results.json.gz`: original per-second ramp snapshots, RSS, per-thread CPU and
  cgroup kernel/slab counters. The stop at 250k is an actual safety preflight;
  500k/1M entries in summary are explicitly unattempted, not observed failures.
- `specs.json`: machine/limit probe, including refused hard-FD-limit increase.
- `10000-*`, `50000-*`, `100000-*`: relay, idle, fanout and publish raw summaries.
- `diag-fanout-*`: optimized 300 events/s × 1k subscribers at 100k idle.
- `diag-fanout-1000-*`: optimized 1000 events/s × 1k subscribers; named I/O
  threads and user/system CPU show saturation near 1M deliveries/s.
- `diag-keepalive-*`: 158-second 100k idle validation across first ping deadline.
- `gprof-*`: separate instrumented diagnostics, never production throughput.
  Flat histogram reports contain unreliable multithreaded call counts; use
  sampled percentages cautiously. The profile includes startup/teardown.
- `*-summary.json`: compact diagnostic CPU/wait-channel results.
- `*.json.gz`: archived raw snapshots, gzip-compressed to keep the repo small.
- `profile-build.txt`: compiler invocation (run from repository root).
- `regressions.json`, `test-*.log`: final test evidence.

Read compressed data with Python, for example:

```python
import gzip, json
with gzip.open('results.json.gz', 'rt') as f:
    data = json.load(f)
```

Rerunning the harness writes new uncompressed JSON/logs; it does not update the
archived compressed snapshots automatically. Avoid mixing runs when comparing.
Cgroup deltas include both loopback endpoints and background activity. Original
ramp snapshots predate added thread names; roles in summary follow the fixed
thread-creation order in backend_ngws.c. Use the named high-rate diagnostic as
the stronger attribution of fanout CPU. No test touched the checkout database.

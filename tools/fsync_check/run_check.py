#!/usr/bin/env python3
"""Fsync-before-OK check: relay under LD_PRELOAD=fsync_trace.so, N concurrent
publishers, then verify for every OK true: its event's WAL frames were
pwritten, and an fdatasync/fsync on the WAL started after that pwrite and
completed before the OK was handed to the socket."""
import os, sys, threading, time, bisect, json
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests"))
import ngtest
from ngtest import Key, WS, Relay
TR = "/tmp/fsync_trace_%d.log" % os.getpid()
coalesce = sys.argv[1] if len(sys.argv) > 1 else ""
env = {"LD_PRELOAD": os.environ.get("FSYNC_TRACE_SO", os.path.abspath(os.path.dirname(__file__)) + "/fsync_trace.so"), "FSYNC_TRACE": TR}
if coalesce: env["NG_WAL_COALESCE"] = coalesce
if os.path.exists(TR): os.unlink(TR)
conf = sys.argv[2] + "\n" if len(sys.argv) > 2 else ""
r = Relay(conf, env=env)
id2probe = {}; lock = threading.Lock(); oks = [0]
def worker(t, n):
    w = WS(r.port); k = Key()
    for i in range(n):
        p = t * 1000 + i
        e = k.ev("durprobe-%06d payload" % p, 1, [])
        with lock: id2probe[e["id"][:16]] = "%06d" % p
        m = w.publish(e)
        if m and m[2] is True:
            with lock: oks[0] += 1
T, N = 16, 150
ths = [threading.Thread(target=worker, args=(t, N)) for t in range(T)]
t0 = time.time(); [x.start() for x in ths]; [x.join() for x in ths]
r.stop()
W = {}; nw = 0; syncs = []; sends = []; s0 = {}
for line in open(TR, errors="replace"):
    f = line.split()
    if f[0] == "W":
        nw += 1
        for p in f[4:]:
            if p.isdigit(): W.setdefault(p, int(f[1]))
    elif f[0] == "S0" and f[4] == "1": s0[(f[2], f[3])] = int(f[1])
    elif f[0] == "S1" and f[4] == "1":
        syncs.append((s0.pop((f[2], f[3])), int(f[1]), int(f[5])))
    elif f[0] == "O":
        for i in f[3:]: sends.append((int(f[1]), i))
syncs.sort(key=lambda s: s[1])
ends = [s[1] for s in syncs]
bad = []; checked = 0
for ts, i in sends:
    p = id2probe.get(i)
    if p is None: continue
    tw = W.get(p)
    if tw is None: bad.append((i, "no WAL pwrite before OK")); continue
    # a successful sync that started after the pwrite and ended before the send
    k = bisect.bisect_right(ends, ts)
    ok = any(syncs[j][0] >= tw and syncs[j][2] == 0 for j in range(k - 1, -1, -1) if syncs[j][1] >= tw)
    checked += 1
    if not ok: bad.append((i, "OK sent before a WAL fsync covering its frames"))
mode = coalesce or "default(on)"
res = ({"NG_WAL_COALESCE": mode, "conf": conf.strip() or "defaults (db_sync = full)", "published": T * N, "ok_true": oks[0], "ok_true_traced": checked,
                  "wal_pwrites": nw, "wal_syncs": len(syncs), "violations": len(bad), "sample": bad[:3]})
print(json.dumps(res))
os.unlink(TR)
sys.exit(1 if bad or res["ok_true"] != T * N else 0)

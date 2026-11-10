#!/usr/bin/env python3
"""Crash durability with synchronous=FULL and the WAL write-coalescing VFS:
every event answered OK true before a SIGKILL is present after restart."""
import signal, sys, threading, time
sys.path.insert(0, __import__("os").path.dirname(__file__))
from ngtest import Key, WS, Relay, check, summary

r = Relay()
keys = [Key() for _ in range(8)]
acked = set(); lock = threading.Lock(); stop = False

def pub(k):
    w = WS(r.port); n = 0; sent = {}
    try:
        while not stop:
            batch = [k.ev(f"d{n + i}", 1, [["p", keys[(n + i) % 8].pk, "wss://x"], ["t", "dur"]]) for i in range(32)]
            n += 32
            w.send(*[["EVENT", e] for e in batch])
            for _ in batch:
                m = w.recv(5)
                if m is None: return
                if m[0] == "OK" and m[2]:
                    with lock: acked.add(m[1])
    except OSError:
        pass

ts = [threading.Thread(target=pub, args=(k,)) for k in keys]
for t in ts: t.start()
time.sleep(2.5)
r.p.send_signal(signal.SIGKILL); r.p.wait()
stop = True
for t in ts: t.join()
check("events acknowledged before the kill", len(acked) > 1000, len(acked))
r.log.close(); r.start()
w = WS(r.port); ids = sorted(acked); found = 0
for i in range(0, len(ids), 200):
    evs, end = w.req(f"q{i}", {"ids": ids[i:i + 200], "limit": 500}); w.send(["CLOSE", f"q{i}"])
    found += len(evs)
check("every acknowledged event survived SIGKILL", found == len(ids), f"{found}/{len(ids)}")
evs, end = w.req("t", {"#t": ["dur"], "limit": 1}, verb="COUNT")
check("tag index consistent with the events", end and end[0] == "COUNT" and end[2]["count"] >= len(ids), end)
r.stop()
check("no SQL errors logged", "SQL error" not in r.logtext(), r.logtext()[-300:])

# synchronous=NORMAL commits do not sync the WAL: the shim must flush at the
# wal-index barrier, so an OK'd event is visible to other connections at once.
r = Relay("db_sync = normal\n")
a, b = WS(r.port), WS(r.port); k = Key(); miss = 0
for i in range(300):
    e = k.ev(f"n{i}", 1, [["t", "vis"]])
    m = a.publish(e)
    evs, _ = b.req(f"v{i}", {"ids": [e["id"]]}); b.send(["CLOSE", f"v{i}"])
    if not (m and m[2] and len(evs) == 1): miss += 1
check("NORMAL sync: every OK'd event immediately readable elsewhere", miss == 0, f"misses={miss}")
r.stop()
check("no SQL errors logged (NORMAL)", "SQL error" not in r.logtext(), r.logtext()[-300:])
sys.exit(summary())

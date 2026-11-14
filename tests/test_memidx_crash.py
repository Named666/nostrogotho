#!/usr/bin/env python3
"""tag_index = memory crash equivalence: after SIGKILL mid-publish (with
deletes and replaceable updates in flight), the memory index answers every
tag query exactly like (a) a clean restart from its snapshot, (b) a full
rebuild without the snapshot, (c) a corrupted snapshot (rejected, rebuilt)
and (d) the same database under tag_index = sqlite."""
import os, shutil, signal, sys, threading, time
sys.path.insert(0, os.path.dirname(__file__))
from ngtest import Key, WS, Relay, check, summary

keys = [Key() for _ in range(8)]
targets = ["%064x" % (0xabc0000 + i) for i in range(12)]
topics = ["t%d" % i for i in range(5)]
r = Relay("tag_index_snapshot_secs = 1\n")
acked = []; lock = threading.Lock(); stop = False

def pub(ki):
    k = keys[ki]; w = WS(r.port); n = 0; mine = []
    try:
        while not stop:
            batch = []
            for i in range(24):
                j = n + i
                if j % 11 == 5 and mine:                       # NIP-09 delete of an own event
                    batch.append(k.ev("", 5, [["e", mine[j % len(mine)]]]))
                elif j % 13 == 7:                              # replaceable: replaces the previous one
                    batch.append(k.ev("", 3, [["p", keys[(j + x) % 8].pk] for x in range(3)]))
                else:
                    kind = (1, 7, 6)[j % 3]
                    tags = [["e", targets[j % 12]], ["p", keys[j % 8].pk], ["t", topics[j % 5]]]
                    if j % 4 == 0: tags.append(["e", targets[(j * 7) % 12], "", "reply"])
                    batch.append(k.ev("c%d-%d" % (ki, j), kind, tags, ca=1700000000 + j // 3))
            n += 24
            w.send(*[["EVENT", e] for e in batch])
            for e in batch:
                m = w.recv(5)
                if m is None: return
                if m[0] == "OK" and m[2] and e["kind"] in (1, 6, 7): mine.append(e["id"])
            with lock: acked.extend(mine[-5:])
    except OSError:
        pass

ts = [threading.Thread(target=pub, args=(i,)) for i in range(8)]
for t in ts: t.start()
time.sleep(3.5)
r.p.send_signal(signal.SIGKILL); r.p.wait()
stop = True
for t in ts: t.join()
check("events acknowledged before the kill", len(acked) > 200, len(acked))
snap = r.db + "-tagidx"
check("a background snapshot existed at the kill", os.path.exists(snap))

QUERIES = []
for v in targets: QUERIES += [{"#e": [v], "limit": 500}, {"#e": [v], "kinds": [7], "limit": 50}]
for k in keys: QUERIES += [{"#p": [k.pk], "limit": 500}, {"#p": [k.pk], "kinds": [1, 6], "limit": 30}]
for t in topics: QUERIES += [{"#t": [t], "limit": 500}, {"#t": [t, topics[0]], "kinds": [1], "limit": 20}]
QUERIES += [{"#e": targets[:4], "#t": [topics[1]], "limit": 500}, {"#p": [keys[0].pk], "authors": [keys[1].pk], "limit": 500}]

def answers(rel):
    w = WS(rel.port); out = []
    for i, f in enumerate(QUERIES):
        evs, end = w.req("q%d" % i, f, timeout=20); w.send(["CLOSE", "q%d" % i])
        out.append([e["id"] for e in evs])
        _, c = w.req("c%d" % i, {k: v for k, v in f.items() if k != "limit"}, verb="COUNT", timeout=20)
        out.append(c[2]["count"] if c and c[0] == "COUNT" else None)
    w.close()
    return out

def restart(rel, conf=None):
    rel.log.close()
    if conf is not None: open(rel.conf, "w").write(conf)
    rel.start()

restart(r)                                  # snapshot (~1 s old) + replay after a SIGKILL
a = answers(r)
check("after SIGKILL: loaded the snapshot and replayed", "memidx: snapshot" in r.logtext(), r.logtext()[-400:])
check("queries return rows", sum(len(x) for x in a if isinstance(x, list)) > 500)
r.stop()                                    # clean shutdown writes a covering snapshot
restart(r); b = answers(r); r.stop()
check("clean restart from the shutdown snapshot == after SIGKILL", a == b)
os.unlink(snap)
restart(r); c = answers(r); r.stop()
check("full rebuild (snapshot removed) == after SIGKILL", a == c and "memidx: rebuilt" in r.logtext())
data = bytearray(open(snap, "rb").read()); data[len(data) // 2] ^= 0x5a; open(snap, "wb").write(bytes(data))
restart(r); d = answers(r); r.stop()
check("corrupt snapshot rejected and rebuilt, same answers", a == d and "unusable" in r.logtext())
copy = os.path.join(r.dir, "s.sqlite"); shutil.copy(r.db, copy)
for ext in ("-wal", "-shm"):
    if os.path.exists(r.db + ext): shutil.copy(r.db + ext, copy + ext)
s = Relay("tag_index = sqlite\n", db=copy); e = answers(s); s.stop()
diff = [QUERIES[i // 2] for i in range(len(a)) if a[i] != e[i]]
check("tag_index = sqlite on the same database == memory", a == e, diff[:2])
check("no SQL errors logged", "SQL error" not in r.logtext() + s.logtext())
sys.exit(summary())

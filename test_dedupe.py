"""
Duplicate-guard tests for the single-writer path.

  1. one event sent concurrently from many connections -> exactly one row,
     one non-duplicate OK, every subscriber receives it exactly once
  2. the same event pipelined N times on one connection (same writer batch)
  3. duplicate after commit -> ["OK", id, true, "duplicate: ..."], no broadcast
  4. replaceable (kind 0 / 10002) versions racing inside one batch -> only
     the newest survives, ties broken by lowest id, losers never broadcast
  5. addressable (kind 30000) per d-tag, missing d == empty d
  6. NIP-09: a deleted event (and an id deleted before it arrived) cannot be
     re-inserted by its author

Usage: RELAY_URL=ws://127.0.0.1:7447 RELAY_DB=/path/db.sqlite python test_dedupe.py
"""
import asyncio, hashlib, json, os, sqlite3, time
import websockets
from coincurve import PrivateKey

URL = os.environ.get("RELAY_URL", "ws://127.0.0.1:7447")
DB = os.environ["RELAY_DB"]
results = []

def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"[{'PASS' if cond else 'FAIL'}] {name} {detail}")

def mk(sk, kind, content, tags=None, created_at=None):
    tags = tags or []
    pk = sk.public_key.format(compressed=True)[1:].hex()
    ca = created_at or int(time.time())
    ser = json.dumps([0, pk, ca, kind, tags, content], separators=(",", ":"), ensure_ascii=False)
    eid = hashlib.sha256(ser.encode()).hexdigest()
    return {"id": eid, "pubkey": pk, "created_at": ca, "kind": kind, "tags": tags,
            "content": content, "sig": sk.sign_schnorr(bytes.fromhex(eid)).hex()}

def rows(sql, *a):
    c = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    try: return c.execute(sql, a).fetchall()
    finally: c.close()

async def conn():
    ws = await websockets.connect(URL, max_size=None)
    await asyncio.wait_for(ws.recv(), 3)          # AUTH challenge
    return ws

async def collect(ws, secs, pred=lambda m: True):
    out, end = [], time.time() + secs
    while True:
        left = end - time.time()
        if left <= 0: return out
        try: m = json.loads(await asyncio.wait_for(ws.recv(), left))
        except asyncio.TimeoutError: return out
        if pred(m): out.append(m)

async def subscribers(n, flt):
    subs = [await conn() for _ in range(n)]
    for i, s in enumerate(subs):
        await s.send(json.dumps(["REQ", f"s{i}", flt]))
        await collect(s, 0.3)                      # drain EOSE
    return subs

async def oks(ws, n, t=5):
    got, end = [], time.time() + t
    while len(got) < n and time.time() < end:
        m = json.loads(await asyncio.wait_for(ws.recv(), end - time.time()))
        if m[0] == "OK": got.append(m)
    return got

async def t_concurrent(sk):
    tag = os.urandom(6).hex()
    subs = await subscribers(3, {"#t": [tag]})
    ev = mk(sk, 1, "concurrent", [["t", tag]])
    pubs = [await conn() for _ in range(50)]
    msg = json.dumps(["EVENT", ev])
    await asyncio.gather(*(p.send(msg) for p in pubs))
    res = [m for r in await asyncio.gather(*(oks(p, 1) for p in pubs)) for m in r]
    fresh = [m for m in res if m[2] is True and m[3] == ""]
    dups = [m for m in res if m[2] is True and m[3].startswith("duplicate:")]
    check("concurrent: 50 OK replies, all true", len(res) == 50 and all(m[2] for m in res), str(len(res)))
    check("concurrent: exactly one fresh OK, 49 duplicate:", len(fresh) == 1 and len(dups) == 49, f"{len(fresh)}/{len(dups)}")
    got = await asyncio.gather(*(collect(s, 1.0, lambda m: m[0] == "EVENT") for s in subs))
    check("concurrent: each subscriber got it exactly once", [len(g) for g in got] == [1, 1, 1], str([len(g) for g in got]))
    check("concurrent: exactly one row", rows("SELECT count(*) FROM event WHERE id=unhex(?)", ev["id"])[0][0] == 1)
    for p in pubs + subs: await p.close()

async def t_same_batch(sk):
    tag = os.urandom(6).hex()
    subs = await subscribers(2, {"#t": [tag]})
    ev = mk(sk, 1, "batch", [["t", tag]])
    p = await conn()
    for _ in range(20): await p.send(json.dumps(["EVENT", ev]))
    res = await oks(p, 20)
    fresh = [m for m in res if m[3] == ""]
    check("same batch: 20 OK true, exactly one fresh", len(res) == 20 and all(m[2] for m in res) and len(fresh) == 1,
          str([m[3][:9] for m in res][:4]))
    got = await asyncio.gather(*(collect(s, 1.0, lambda m: m[0] == "EVENT") for s in subs))
    check("same batch: one broadcast per subscriber", [len(g) for g in got] == [1, 1])
    check("same batch: one row", rows("SELECT count(*) FROM event WHERE id=unhex(?)", ev["id"])[0][0] == 1)

    # 3. duplicate after commit
    await p.send(json.dumps(["EVENT", ev]))
    r = await oks(p, 1)
    check("after commit: OK true duplicate:", r and r[0][2] is True and r[0][3].startswith("duplicate:"), str(r))
    got = await asyncio.gather(*(collect(s, 0.7, lambda m: m[0] == "EVENT") for s in subs))
    check("after commit: not re-broadcast", [len(g) for g in got] == [0, 0])
    for w in subs + [p]: await w.close()

async def t_replaceable(sk, kind):
    pk = sk.public_key.format(compressed=True)[1:].hex()
    base = int(time.time()) - 100
    subs = await subscribers(1, {"authors": [pk], "kinds": [kind]})
    old = mk(sk, kind, "old", created_at=base)
    new1 = mk(sk, kind, "new-a", created_at=base + 10)
    new2 = mk(sk, kind, "new-b", created_at=base + 10)
    winner = min(new1, new2, key=lambda e: e["id"])
    p = await conn()
    for e in (new1, old, new2, new1):                 # one pipelined burst -> one batch
        await p.send(json.dumps(["EVENT", e]))
    res = await oks(p, 4)
    check(f"kind {kind} race: 4 OK true", len(res) == 4 and all(m[2] for m in res), str([(m[1][:6], m[3][:12]) for m in res]))
    left = rows("SELECT lower(hex(id)) FROM event WHERE pubkey=unhex(?) AND kind=?", pk, kind)
    check(f"kind {kind} race: one row, newest + lowest id wins", left == [(winner["id"],)], str(left))
    got = await collect(subs[0], 1.0, lambda m: m[0] == "EVENT")
    ids = [m[2]["id"] for m in got]
    check(f"kind {kind} race: loser 'old' never broadcast", old["id"] not in ids and winner["id"] in ids and len(ids) == len(set(ids)), str(len(ids)))
    await p.send(json.dumps(["EVENT", old]))
    r = await oks(p, 1)
    check(f"kind {kind}: older version later -> OK true duplicate:", r and r[0][2] and r[0][3].startswith("duplicate:"), str(r))
    for w in subs + [p]: await w.close()

async def t_addressable(sk):
    pk = sk.public_key.format(compressed=True)[1:].hex()
    base = int(time.time()) - 100
    a1 = mk(sk, 30000, "a1", [["d", "a"]], base)
    a2 = mk(sk, 30000, "a2", [["d", "a"]], base + 5)
    b1 = mk(sk, 30000, "b1", [["d", "b"]], base)
    n1 = mk(sk, 30000, "nod", [], base)
    e1 = mk(sk, 30000, "emptyd", [["d", ""]], base + 1)   # replaces the no-d one
    p = await conn()
    for e in (a2, b1, a1, n1, e1): await p.send(json.dumps(["EVENT", e]))
    res = await oks(p, 5)
    check("addressable: 5 OK true", len(res) == 5 and all(m[2] for m in res), str([m[3] for m in res]))
    left = sorted(r[0] for r in rows("SELECT lower(hex(id)) FROM event WHERE pubkey=unhex(?) AND kind=30000", pk))
    check("addressable: newest per d-tag (a2, b1, empty-d)", left == sorted([a2["id"], b1["id"], e1["id"]]), str(len(left)))
    await p.close()

async def t_deletion(sk):
    p = await conn()
    ev = mk(sk, 1, "to delete")
    future = mk(sk, 1, "deleted before it arrived", created_at=int(time.time()) - 5)
    await p.send(json.dumps(["EVENT", ev])); await oks(p, 1)
    d = mk(sk, 5, "", [["e", ev["id"]], ["e", future["id"]]])
    await p.send(json.dumps(["EVENT", d])); await oks(p, 1)
    check("deletion: target removed", rows("SELECT count(*) FROM event WHERE id=unhex(?)", ev["id"])[0][0] == 0)
    await p.send(json.dumps(["EVENT", ev]))
    r = await oks(p, 1)
    check("deletion: re-insert refused", r and r[0][2] is False and r[0][3].startswith("blocked:"), str(r))
    await p.send(json.dumps(["EVENT", future]))
    r = await oks(p, 1)
    check("deletion: pre-deleted id refused", r and r[0][2] is False and r[0][3].startswith("blocked:"), str(r))
    check("deletion: no rows", rows("SELECT count(*) FROM event WHERE id IN (unhex(?),unhex(?))", ev["id"], future["id"])[0][0] == 0)
    await p.close()

async def main():
    sk = PrivateKey()
    await t_concurrent(sk)
    await t_same_batch(sk)
    await t_replaceable(PrivateKey(), 0)
    await t_replaceable(PrivateKey(), 10002)
    await t_addressable(PrivateKey())
    await t_deletion(PrivateKey())
    ok = sum(1 for _, c in results if c)
    print(f"{ok}/{len(results)} passed")
    raise SystemExit(0 if ok == len(results) else 1)

asyncio.run(main())

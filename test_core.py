"""
Backend-agnostic functional test for the core relay path.

Covers: connect + AUTH challenge, EVENT -> OK, REQ returns stored events then
EOSE (exact ["EOSE",sub]), live broadcast to a second subscriber, CLOSE stops
delivery, duplicate EVENT, bad signature, replaceable kind 0 replacement,
NIP-42 AUTH, COUNT, WS ping/pong, fragmented message, oversize message.

Usage: RELAY_URL=ws://127.0.0.1:7447 python test_core.py   (relay already running)
"""
import asyncio, hashlib, json, os, sys, time
import websockets
from coincurve import PrivateKey

URL = os.environ.get("RELAY_URL", "ws://127.0.0.1:7447")
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

async def recv(ws, t=3):
    return json.loads(await asyncio.wait_for(ws.recv(), t))

async def until(ws, pred, t=3):
    end = time.time() + t
    while time.time() < end:
        m = await recv(ws, end - time.time())
        if pred(m): return m
    raise asyncio.TimeoutError

async def main():
    sk = PrivateKey()
    async with websockets.connect(URL, max_size=None) as a, websockets.connect(URL, max_size=None) as b:
        ca = await recv(a); await recv(b)
        check("AUTH challenge on open", ca[0] == "AUTH" and len(ca[1]) == 16, str(ca))

        tag = os.urandom(6).hex()
        await b.send(json.dumps(["REQ", "live", {"kinds": [1], "#t": [tag]}]))
        m = await recv(b)
        check("EOSE exact shape", m == ["EOSE", "live"], str(m))

        ev = mk(sk, 1, "hello " + tag, [["t", tag]])
        await a.send(json.dumps(["EVENT", ev]))
        ok = await until(a, lambda m: m[0] == "OK")
        check("EVENT accepted", ok == ["OK", ev["id"], True, ""], str(ok))
        live = await until(b, lambda m: m[0] == "EVENT")
        check("live broadcast", live[1] == "live" and live[2]["id"] == ev["id"])

        await a.send(json.dumps(["EVENT", ev]))
        ok = await until(a, lambda m: m[0] == "OK")
        check("duplicate -> OK true duplicate:", ok[2] is True and ok[3].startswith("duplicate:"), str(ok))

        bad = dict(ev); bad["sig"] = "00" * 64
        bad["content"] = "tampered"
        await a.send(json.dumps(["EVENT", bad]))
        ok = await until(a, lambda m: m[0] == "OK")
        check("bad id/sig rejected", ok[2] is False and ok[3].startswith("invalid"), str(ok))

        await a.send(json.dumps(["REQ", "past", {"ids": [ev["id"]]}]))
        m1 = await recv(a); m2 = await recv(a)
        check("REQ returns stored event", m1[0] == "EVENT" and m1[2]["id"] == ev["id"], str(m1)[:60])
        check("then EOSE", m2 == ["EOSE", "past"], str(m2))

        await a.send(json.dumps(["COUNT", "c", {"ids": [ev["id"]]}]))
        m = await until(a, lambda m: m[0] == "COUNT")
        check("COUNT", m == ["COUNT", "c", {"count": 1}], str(m))

        # control bytes survive storage and fan-out (JSON \u00XX escapes)
        await b.send(json.dumps(["REQ", "ctl", {"kinds": [1], "#t": [tag + "c"]}])); await until(b, lambda m: m[0] == "EOSE")
        ctl = mk(sk, 1, "ctl\x01\x1f\x7f end", [["t", tag + "c"]])
        await a.send(json.dumps(["EVENT", ctl]))
        ok = await until(a, lambda m: m[0] == "OK")
        live = await until(b, lambda m: m[0] == "EVENT" and m[1] == "ctl")
        check("control-byte content broadcast intact", ok[2] is True and live[2]["content"] == ctl["content"], repr(live[2]["content"]))
        await a.send(json.dumps(["REQ", "ctlq", {"ids": [ctl["id"]]}]))
        m = await until(a, lambda m: m[0] == "EVENT" and m[1] == "ctlq")
        check("control-byte content stored intact", m[2]["content"] == ctl["content"] and m[2]["id"] == ctl["id"], repr(m[2]["content"]))

        # replaceable kind 0
        old = mk(sk, 0, '{"name":"old"}', created_at=int(time.time()) - 10)
        new = mk(sk, 0, '{"name":"new"}')
        for e in (old, new):
            await a.send(json.dumps(["EVENT", e])); await until(a, lambda m: m[0] == "OK")
        await a.send(json.dumps(["REQ", "meta", {"kinds": [0], "authors": [new["pubkey"]]}]))
        got = []
        while True:
            m = await recv(a)
            if m[0] == "EOSE": break
            got.append(m[2]["id"])
        check("replaceable kept newest only", got == [new["id"]], str(got))

        # CLOSE stops live delivery
        await b.send(json.dumps(["CLOSE", "live"]))
        await asyncio.sleep(0.3)
        ev2 = mk(sk, 1, "after close", [["t", tag]])
        await a.send(json.dumps(["EVENT", ev2])); await until(a, lambda m: m[0] == "OK")
        try:
            m = await recv(b, 1); check("CLOSE stops delivery", False, str(m))
        except asyncio.TimeoutError:
            check("CLOSE stops delivery", True)

        # NIP-42 AUTH
        auth = mk(sk, 22242, "", [["relay", os.environ.get("SERVICE_URL", "")], ["challenge", ca[1]]])
        await a.send(json.dumps(["AUTH", auth]))
        m = await until(a, lambda m: m[0] == "OK")
        check("AUTH processed (OK reply)", m[1] == auth["id"], str(m))

        # ping/pong
        pong = await a.ping(b"hi"); await asyncio.wait_for(pong, 3)
        check("WS ping/pong", True)

    # fragmented frame via raw protocol
    async with websockets.connect(URL, max_size=None) as c:
        await recv(c)
        await c.send(iter(['["REQ","fr', 'ag",{"kinds":[1],"limit":1}]']))
        got = await until(c, lambda m: m[0] == "EOSE")
        check("fragmented message reassembled", got == ["EOSE", "frag"], str(got))

    # oversize message closes with 1009 (limit 5 MiB)
    try:
        async with websockets.connect(URL, max_size=None) as d:
            await recv(d)
            await d.send("[" + " " * (6 * 1024 * 1024) + "]")
            await asyncio.wait_for(d.recv(), 5)
            await asyncio.wait_for(d.recv(), 5)
            check("oversize closes", False)
    except websockets.ConnectionClosed as e:
        check("oversize closes", e.rcvd is None or e.rcvd.code in (1009, 1000), f"code={e.rcvd.code if e.rcvd else None}")
    except Exception as e:
        check("oversize closes", False, repr(e))

asyncio.run(main())
failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed")
sys.exit(1 if failed else 0)

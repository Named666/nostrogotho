#!/usr/bin/env python3
"""NIP behavior tests against a live relay (one relay per section).
Usage: tests/test_nips.py [section ...]   (default: all sections)"""
import json, sys, time
sys.path.insert(0, __import__("os").path.dirname(__file__))
from ngtest import Key, WS, Relay, check, summary

SECTIONS = {}
def section(fn): SECTIONS[fn.__name__] = fn; return fn


@section
def tags():
    """NIP-01 tag filters via the tag index (A1)."""
    r = Relay(); w = WS(r.port); k = Key(); other = Key()
    hint = k.ev("mention with relay hint", 1, [["p", other.pk, "wss://relay.example"]])
    plain = k.ev("plain mention", 1, [["p", other.pk]])
    root = k.ev("root")
    reply = k.ev("reply", 1, [["e", root["id"], "wss://relay.example", "reply"], ["p", k.pk]])
    react = k.ev("+", 7, [["e", root["id"]], ["p", k.pk], ["k", "1"]])
    for e in (hint, plain, root, reply, react): w.publish(e)
    evs, end = w.req("p", {"#p": [other.pk]})
    check("#p matches tags with and without a relay hint", {e["id"] for e in evs} == {hint["id"], plain["id"]}, end)
    evs, _ = w.req("e", {"#e": [root["id"]], "kinds": [1]})
    check("#e matches a marker tag, kinds checked", [e["id"] for e in evs] == [reply["id"]])
    evs, _ = w.req("e2", {"#e": [root["id"]], "#k": ["1"]})
    check("two tag names AND", [e["id"] for e in evs] == [react["id"]])
    evs, _ = w.req("multi", {"#p": [other.pk, k.pk]})
    ids = [e["id"] for e in evs]
    check("multi-value tag filter: each event once", len(ids) == len(set(ids)) == 4, len(ids))
    evs, end = w.req("long", {"#title": ["x"]})
    check("multi-letter tag filter refused (NIP-01 indexes single letters)", end and end[0] == "CLOSED", end)
    # replaceable overwrite drops the old version's tag rows
    f1 = k.ev("", 3, [["p", other.pk]], ca=int(time.time()) - 10)
    f2 = k.ev("", 3, [["p", k.pk]])
    w.publish(f1); w.publish(f2)
    evs, _ = w.req("f", {"kinds": [3], "#p": [other.pk]})
    check("replaced kind 3 no longer matches its old p tags", evs == [])
    evs, _ = w.req("f2", {"kinds": [3], "#p": [k.pk]})
    check("current kind 3 matches", [e["id"] for e in evs] == [f2["id"]])
    # NIP-01 ordering: newest first, ties by lowest id
    t = int(time.time()) - 100
    a, b = k.ev("tie a", 1, [["t", "tie"]], ca=t), k.ev("tie b", 1, [["t", "tie"]], ca=t)
    w.publish(a); w.publish(b)
    evs, _ = w.req("tie", {"#t": ["tie"]})
    check("equal created_at ordered by lowest id", [e["id"] for e in evs] == sorted([a["id"], b["id"]]))
    r.stop()


@section
def limit0():
    """NIP-01 limit:0 returns no stored events, then live ones (A2)."""
    r = Relay(); w = WS(r.port); k = Key()
    old = k.ev("stored"); w.publish(old)
    evs, end = w.req("z", {"authors": [k.pk], "limit": 0})
    check("limit:0 -> EOSE with no stored events", evs == [] and end and end[0] == "EOSE", (evs, end))
    live = k.ev("live"); WS(r.port).publish(live)
    m = w.recv()
    check("limit:0 subscription still gets live events", m and m[0] == "EVENT" and m[2]["id"] == live["id"], m)
    w.send(["CLOSE", "z"])
    evs, end = w.req("one", {"authors": [k.pk], "limit": 1})
    check("limit:1 -> newest only", [e["id"] for e in evs] == [live["id"]], evs)
    evs, end = w.req("c", {"authors": [k.pk], "limit": 0}, verb="COUNT")
    check("COUNT ignores limit:0", end and end[0] == "COUNT" and end[2]["count"] == 2, end)
    r.stop()


@section
def limits():
    """Configurable limits: tags (A3), content/event size, subscriptions."""
    r = Relay(); w = WS(r.port); k = Key()
    many = [["p", Key().pk] for _ in range(3000)]
    m = w.publish(k.ev("", 3, many))
    check("kind 3 with 3000 p tags accepted", m and m[2] is True, m and m[3])
    m = w.publish(k.ev("", 3, [["t", str(i)] for i in range(5001)]))
    check("5001 tags -> OK false invalid:", m and m[0] == "OK" and m[2] is False and m[3].startswith("invalid:"), m and m[3])
    art = k.ev("x" * (200 << 10), 30023, [["d", "long"], ["title", "NIP-23"]])
    m = w.publish(art)
    check("200 KiB long-form content accepted", m and m[2] is True, m and m[3])
    m = w.publish(k.ev("y" * (300 << 10), 30023, [["d", "big"]]))
    check("300 KiB content -> OK false invalid:", m and m[2] is False and m[3].startswith("invalid:"), m and m[3])
    big = k.ev("", 9735, [["description", json.dumps({"content": "z" * 3000, "tags": [["p", k.pk]] * 20})], ["p", k.pk]])
    m = w.publish(big)
    check("zap-receipt style 4 KB tag element accepted", m and m[2] is True, m and m[3])
    # canonical id: escapes and whitespace in the client's tags are normalized
    tags = [["t", "caf\u00e9 \"q\" /"], [], ["emoji", "\U0001f600"]]
    ev = k.ev("", 1, tags)
    raw = json.dumps(ev, ensure_ascii=True, indent=1)        # \uXXXX, surrogates, whitespace
    w.send_raw(json.dumps(["EVENT", json.loads(raw)], ensure_ascii=True).replace('"tags": [', '"tags":  [ '))
    m = w.recv()
    check("non-canonical tag JSON (\\u escapes, empty tag) verifies", m and m[0] == "OK" and m[2] is True, m)
    subs = [w.req(f"s{i}", {"kinds": [1], "limit": 0}) for i in range(30)]
    check("30 open subscriptions (home feed) allowed", all(e and e[0] == "EOSE" for _, e in subs))
    r.stop()
    r = Relay("max_event_tags = 3\nmax_content_length = 1K\nmax_subscriptions = 2\nmax_event_size = 4K\n")
    w = WS(r.port)
    m = w.publish(k.ev("", 1, [["t", "a"]] * 4))
    check("max_event_tags = 3 enforced", m and m[2] is False and "3 tags" in m[3], m and m[3])
    m = w.publish(k.ev("a" * 1025))
    check("max_content_length = 1K enforced", m and m[2] is False and "1024" in m[3], m and m[3])
    m = w.publish(k.ev("", 1, [["t", "a" * 1500], ["t", "b" * 1500], ["t", "c" * 1500]]))
    check("max_event_size = 4K enforced", m and m[2] is False and "4096" in m[3], m and m[3])
    w.req("a", {"limit": 0}); w.req("b", {"limit": 0})
    _, end = w.req("c", {"limit": 0})
    check("max_subscriptions = 2: third REQ CLOSED", end and end[0] == "CLOSED", end)
    _, end = w.req("a", {"limit": 0})
    check("re-using an open subscription id is allowed", end and end[0] == "EOSE", end)
    r.stop()


@section
def nip26():
    """NIP-26 delegation is not supported (deprecated NIP, removed)."""
    r = Relay(); w = WS(r.port); delegator = Key(); delegatee = Key()
    ev = delegatee.ev("delegated", 1, [["delegation", delegator.pk, "kind=1", "00" * 64]])
    m = w.publish(ev)
    check("event with a delegation tag is stored as a plain event (tag not verified)", m and m[2] is True, m)
    evs, _ = w.req("d", {"authors": [delegator.pk]})
    check("authors:[delegator] does not match delegated events", evs == [], evs)
    evs, _ = w.req("d2", {"authors": [delegatee.pk]})
    check("authors:[signer] matches", [e["id"] for e in evs] == [ev["id"]])
    w.publish(delegator.ev("", 5, [["e", ev["id"]]]))
    evs, _ = w.req("d3", {"ids": [ev["id"]]})
    check("delegator cannot delete the delegatee's event", len(evs) == 1)
    r.stop()


if __name__ == "__main__":
    for name in sys.argv[1:] or SECTIONS:
        print(f"-- {name}: {SECTIONS[name].__doc__}")
        SECTIONS[name]()
    sys.exit(summary())

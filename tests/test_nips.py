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

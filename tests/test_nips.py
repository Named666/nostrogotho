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
    old = k.ev("stored", ca=int(time.time()) - 10); w.publish(old)
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
def complexity():
    """Home-feed sized REQs (A6) and CLOSED reasons over the limits (A5)."""
    r = Relay(); w = WS(r.port); pub = WS(r.port)
    follows = [Key() for _ in range(3)] 
    authors = [Key().pk for _ in range(1997)] + [f.pk for f in follows]
    for f in follows: pub.publish(f.ev("stored"))
    evs, end = w.req("home", {"authors": authors, "kinds": [1]})
    check("2000-author home feed REQ -> stored events + EOSE", len(evs) == 3 and end and end[0] == "EOSE", (len(evs), end))
    live = follows[-1].ev("live"); pub.publish(live)
    m = w.recv()
    check("live event from the 2000th author is delivered (index keeps every author)", m and m[0] == "EVENT" and m[2]["id"] == live["id"], m)
    w.send(["CLOSE", "home"])
    ids = [Key().pk for _ in range(99)]
    late = follows[0].ev("late id"); ids.append(late["id"])
    _, end = w.req("ids", {"ids": ids})
    pub.publish(late); m = w.recv()
    check("live match on the 100th id of an ids filter", m and m[0] == "EVENT" and m[2]["id"] == late["id"], m)
    w.send(["CLOSE", "ids"])
    _, end = w.req("big", {"authors": [Key().pk for _ in range(5001)]})
    check("5001 authors in one filter -> CLOSED error:", end and end[0] == "CLOSED" and end[2].startswith("error:"), end)
    _, end = w.req("many", *[{"kinds": [i]} for i in range(21)])
    check("21 filters -> CLOSED error: too many filters", end and end[0] == "CLOSED" and "too many filters" in end[2], end)
    _, end = w.req("bad", {"kinds": [1]}, {"authors": ["abc"]})
    check("one malformed filter -> CLOSED invalid: (not silently dropped)", end and end[0] == "CLOSED" and end[2].startswith("invalid:"), end)
    _, end = w.req("cnt", {"authors": [Key().pk for _ in range(5001)]}, verb="COUNT")
    check("COUNT over the limits -> CLOSED", end and end[0] == "CLOSED", end)
    _, end = w.req("", {"kinds": [1]})
    check("empty subscription id -> CLOSED invalid:", end and end[0] == "CLOSED" and end[2].startswith("invalid:"), end)
    r.stop()
    r = Relay("max_req_authors = 10\nmax_filters = 2\nmax_filter_items = 8\n"); w = WS(r.port)
    _, end = w.req("a", {"authors": [Key().pk for _ in range(6)]}, {"authors": [Key().pk for _ in range(6)]})
    check("max_req_authors = 10: 2x6 authors -> CLOSED", end and end[0] == "CLOSED" and "authors" in end[2], end)
    _, end = w.req("b", {"#t": [str(i) for i in range(9)]})
    check("max_filter_items = 8: 9 tag values -> CLOSED", end and end[0] == "CLOSED", end)
    _, end = w.req("c", {"#t": [str(i) for i in range(8)]}, {"kinds": [1]})
    check("within the configured limits -> EOSE", end and end[0] == "EOSE", end)
    r.stop()


@section
def okreasons():
    """Invalid events answer OK false with NIP-01 prefixes (A4)."""
    r = Relay(); w = WS(r.port); k = Key()
    def pub(ev):
        w.send_raw(json.dumps(["EVENT", ev])); return w.recv()
    ev = k.ev("sig"); ev["sig"] = ("0" if ev["sig"][0] != "0" else "1") + ev["sig"][1:]
    m = pub(ev); check("bad signature -> OK false invalid: bad signature", m and m[0] == "OK" and m[1] == ev["id"] and m[2] is False and m[3] == "invalid: bad signature", m)
    ev = k.ev("id"); ev["content"] = "tampered"
    m = pub(ev); check("wrong id -> OK false invalid: event id ...", m and m[0] == "OK" and m[2] is False and m[3].startswith("invalid: event id"), m)
    ev = k.ev("kind"); ev["kind"] = 70000
    m = pub(ev); check("kind 70000 -> OK false invalid: kind", m and m[0] == "OK" and m[1] == ev["id"] and m[3].startswith("invalid: kind"), m)
    ev = k.ev("tags"); ev["tags"] = [["t", 5]]
    m = pub(ev); check("non-string tag element -> OK false invalid: tags", m and m[0] == "OK" and m[3].startswith("invalid: tags"), m)
    ev = k.ev("pk"); ev["pubkey"] = "XYZ"
    m = pub(ev); check("malformed pubkey -> OK false invalid: pubkey", m and m[0] == "OK" and m[3].startswith("invalid: pubkey"), m)
    ev = k.ev("noid"); del ev["id"]
    m = pub(ev); check("no id -> NOTICE invalid:", m and m[0] == "NOTICE" and m[1].startswith("invalid:"), m)
    ok = k.ev("dup"); w.publish(ok); m = w.publish(ok)
    check("duplicate -> OK true duplicate:", m and m[2] is True and m[3].startswith("duplicate:"), m)
    victim = k.ev("to delete"); w.publish(victim); w.publish(k.ev("", 5, [["e", victim["id"]]]))
    m = w.publish(victim)
    check("deleted event republished -> OK false blocked:", m and m[2] is False and m[3].startswith("blocked:"), m)
    m = w.publish(k.ev("protected", 1, [["-"]]))
    check("protected event unauthenticated -> OK false auth-required:", m and m[2] is False and m[3].startswith("auth-required:"), m)
    m = w.publish(k.ev("future", ca=int(time.time()) + 3600))
    check("created_at too far in the future -> OK false invalid:", m and m[2] is False and m[3].startswith("invalid:"), m)
    r.stop()


def nip11_doc(r):
    head, body = r.http("/", {"Accept": "application/nostr+json"})
    return head, json.loads(body)


@section
def nip11():
    """NIP-11 document from nostrogotho.conf + limits (A7)."""
    r = Relay()
    head, d = nip11_doc(r)
    check("NIP-11 served with application/nostr+json", "application/nostr+json" in head.lower(), head.splitlines()[:3])
    check("software and version present", d.get("software", "").startswith("https://") and d.get("version"), d)
    lim = d.get("limitation", {})
    check("limitation reflects runtime limits", lim.get("max_subscriptions") == 100 and lim.get("max_event_tags") == 5000
          and lim.get("max_content_length") == 256 << 10 and lim.get("max_limit") == 500 and lim.get("default_limit") == 500
          and lim.get("auth_required") is False and lim.get("created_at_upper_limit") == 900, lim)
    check("supported_nips does not claim NIP-26", 26 not in d.get("supported_nips", []), d.get("supported_nips"))
    r.stop()
    op = Key()
    conf = (f"relay_name = Test Relay\nrelay_description = A \"quoted\" description\nrelay_pubkey = {op.pk}\n"
            "relay_contact = mailto:ops@example.com\nrelay_icon = https://example.com/i.png\n"
            "relay_countries = US, CA\nlanguage_tags = en\nposting_policy = https://example.com/p\n"
            "relay_url = wss://relay.example.com\nmin_pow_difficulty = 0\nmax_subscriptions = 7\n")
    r = Relay(conf)
    _, d = nip11_doc(r)
    check("configured identity fields", d.get("name") == "Test Relay" and d.get("description") == 'A "quoted" description'
          and d.get("pubkey") == op.pk and d.get("contact") == "mailto:ops@example.com" and d.get("icon") == "https://example.com/i.png"
          and d.get("posting_policy") == "https://example.com/p", d)
    check("comma lists become arrays", d.get("relay_countries") == ["US", "CA"] and d.get("language_tags") == ["en"], d)
    check("configured limit in limitation", d["limitation"]["max_subscriptions"] == 7, d["limitation"])
    # NIP-42 with relay_url set
    k = Key(); w = WS(r.port)
    m = w.auth(k, "wss://other.example.com")
    check("AUTH with another relay's URL -> OK false invalid: relay tag", m and m[2] is False and "relay tag" in m[3], m)
    w2 = WS(r.port); m = w2.auth(k, "WSS://Relay.Example.com/")
    check("AUTH relay tag compare ignores case and trailing slash", m and m[2] is True, m)
    w3 = WS(r.port); w3.challenge = "0" * 16; m = w3.auth(k, "wss://relay.example.com")
    check("AUTH with a wrong challenge -> OK false invalid: challenge", m and m[2] is False and "challenge" in m[3], m)
    r.stop()
    try:
        Relay("relay_pubkey = nothex\n"); started = True
    except RuntimeError:
        started = False
    check("invalid relay_pubkey -> relay refuses to start", not started)
    # NIP-42 without relay_url: works, warns at startup
    r = Relay(); w = WS(r.port)
    m = w.auth(k, "ws://127.0.0.1:%d" % r.port)
    check("AUTH works without relay_url (any ws(s):// relay tag)", m and m[2] is True, m)
    w2 = WS(r.port); m = w2.auth(k, "https://not-a-relay")
    check("AUTH without relay_url still rejects a non-ws relay tag", m and m[2] is False, m)
    check("startup warns that relay_url is unset", "relay_url is not set" in r.logtext())
    r.stop()


def hll_expect(pubkeys, value):
    import hashlib as _h
    if len(value) == 64: off = int(value[32], 16) + 8
    else: off = int(_h.sha256(value.encode()).hexdigest()[32], 16) + 8
    regs = [0] * 256
    for pk in pubkeys:
        b = bytes.fromhex(pk); z = 0
        for x in b[off + 1:]:
            if x == 0: z += 8; continue
            z += 8 - x.bit_length(); break
        regs[b[off]] = max(regs[b[off]], z + 1)
    return bytes(regs).hex()


@section
def nip45():
    """NIP-45 COUNT: gift-wrap gating like REQ, HyperLogLog (step 4)."""
    r = Relay(); w = WS(r.port); me = Key(); other = Key(); target = Key()
    followers = [Key() for _ in range(40)]
    for f in followers: w.publish(f.ev("", 3, [["p", target.pk]]))
    _, end = w.req("f", {"kinds": [3], "#p": [target.pk]}, verb="COUNT")
    want = hll_expect([f.pk for f in followers], target.pk)
    check("follower COUNT -> count 40 + hll", end and end[0] == "COUNT" and end[2].get("count") == 40, end)
    check("hll matches the NIP-45 algorithm", end and end[2].get("hll") == want, (end and end[2].get("hll", "")[:40], want[:40]))
    _, end = w.req("t", {"kinds": [1], "#t": ["nostr"]}, verb="COUNT")
    check("non-hex tag value -> hll from sha256 offset", end and len(end[2].get("hll", "")) == 512 and end[2]["count"] == 0, end)
    _, end = w.req("two", {"kinds": [3], "#p": [target.pk]}, {"kinds": [7]}, verb="COUNT")
    check("two filters -> plain count, no hll", end and end[2].get("count") == 40 and "hll" not in end[2], end)
    for rcpt in (me, me, other):
        w.publish(Key().ev("wrapped", 1059, [["p", rcpt.pk]]))
    _, end = w.req("dm", {"kinds": [1059], "#p": [me.pk]}, verb="COUNT")
    check("COUNT kind 1059 unauthenticated -> CLOSED auth-required:", end and end[0] == "CLOSED" and end[2].startswith("auth-required:"), end)
    _, end = w.req("all", {}, verb="COUNT")
    check("COUNT without kinds does not count gift wraps", end and end[0] == "COUNT" and end[2]["count"] == 40, end)
    m = w.auth(me, "ws://127.0.0.1")
    check("AUTH ok", m and m[2] is True, m)
    _, end = w.req("dm2", {"kinds": [1059], "#p": [me.pk]}, verb="COUNT")
    check("authenticated recipient counts own gift wraps", end and end[0] == "COUNT" and end[2]["count"] == 2, end)
    _, end = w.req("dm3", {"kinds": [1059], "#p": [other.pk]}, verb="COUNT")
    check("counting someone else's gift wraps -> CLOSED restricted:", end and end[0] == "CLOSED" and end[2].startswith("restricted:"), end)
    _, end = w.req("dm4", {"kinds": [1059]}, verb="COUNT")
    check("kind 1059 COUNT without #p -> CLOSED restricted:", end and end[0] == "CLOSED" and end[2].startswith("restricted:"), end)
    r.stop()


@section
def nip17():
    """NIP-17/59 gift wraps: auth-required CLOSED, recipient deletion (step 5)."""
    r = Relay(); w = WS(r.port); pub = WS(r.port); me = Key(); other = Key()
    wrapper = Key()
    mine = [Key().ev("wrap", 1059, [["p", me.pk]]) for _ in range(2)] + [wrapper.ev("wrap3", 1059, [["p", me.pk]])]
    theirs = Key().ev("wrap", 1059, [["p", other.pk]])
    for e in mine + [theirs]: pub.publish(e)
    w.challenge = None
    _, end = w.req("dm", {"kinds": [1059], "#p": [me.pk]})
    check("REQ kind 1059 before AUTH -> CLOSED auth-required:", end and end[0] == "CLOSED" and end[2].startswith("auth-required:"), end)
    check("... with an AUTH challenge to answer", w.challenge is not None)
    evs, end = w.req("any", {"limit": 50})
    check("kind-less REQ before AUTH never returns gift wraps", end and end[0] == "EOSE" and all(e["kind"] != 1059 for e in evs), end)
    m = w.auth(me, "ws://127.0.0.1")
    check("AUTH ok", m and m[2] is True, m)
    evs, end = w.req("dm2", {"kinds": [1059]})
    check("after AUTH only the recipient's own wraps are delivered", sorted(e["id"] for e in evs) == sorted(e["id"] for e in mine), len(evs))
    live_mine = Key().ev("live", 1059, [["p", me.pk]]); live_other = Key().ev("live", 1059, [["p", other.pk]])
    pub.publish(live_other); pub.publish(live_mine)
    m = w.recv()
    check("live: only the wrap addressed to me", m and m[0] == "EVENT" and m[2]["id"] == live_mine["id"], m)
    w.send(["CLOSE", "dm2"])
    m = pub.publish(other.ev("", 5, [["e", mine[0]["id"]]]))
    evs, _ = w.req("chk", {"ids": [mine[0]["id"]]})
    check("non-recipient cannot delete my gift wrap", len(evs) == 1)
    m = pub.publish(me.ev("", 5, [["e", mine[0]["id"]], ["k", "1059"]]))
    evs, _ = w.req("chk2", {"ids": [mine[0]["id"]]})
    check("recipient deletes a gift wrap (NIP-59)", m and m[2] is True and evs == [], (m, evs))
    m = pub.publish(mine[0])
    check("re-publishing the deleted wrap -> OK false blocked:", m and m[2] is False and m[3].startswith("blocked:"), m)
    pub.publish(wrapper.ev("", 5, [["e", mine[2]["id"]]]))
    evs, _ = w.req("chk3", {"ids": [mine[2]["id"]]})
    check("the wrap's own author can still delete it", evs == [], evs)
    r.stop()


@section
def nip62():
    """NIP-62 durable vanish: blocks re-publication across a SIGKILL restart (step 6)."""
    import signal
    r = Relay(); w = WS(r.port); k = Key(); other = Key(); now = int(time.time())
    old = k.ev("old", 1, [], ca=now - 100)
    wrap = Key().ev("wrap", 1059, [["p", k.pk]])
    for e in (old, wrap): w.publish(e)
    m = w.publish(k.ev("bye", 62, [["relay", "ALL_RELAYS"]], ca=now - 50))
    check("vanish request accepted", m and m[2] is True, m)
    evs, _ = w.req("a", {"ids": [old["id"], wrap["id"]]})
    check("author's events and wraps p-tagging them are gone", evs == [], evs)
    m = w.publish(old)
    check("re-publishing an erased event -> blocked:", m and m[2] is False and m[3].startswith("blocked:"), m)
    m = w.publish(k.ev("also old", 7, [["e", old["id"]]], ca=now - 60))
    check("any older event by the author -> blocked:", m and m[2] is False and m[3].startswith("blocked:"), m)
    m = w.publish(k.ev("new", 1, [], ca=now))
    check("events after the request are accepted", m and m[2] is True, m)
    m = w.publish(other.ev("x", 1, [], ca=now - 100))
    check("other authors unaffected", m and m[2] is True, m)
    r.stop(signal.SIGKILL); r.start(); w = WS(r.port)
    m = w.publish(old)
    check("vanish survives a SIGKILL restart", m and m[2] is False and m[3].startswith("blocked:"), m)
    m = w.publish(k.ev("not ours", 62, [["relay", "wss://elsewhere.example"]], ca=now + 1))
    evs, _ = w.req("b", {"authors": [k.pk], "kinds": [1]})
    check("a vanish for another relay deletes nothing", len(evs) == 1, evs)
    r.stop()


@section
def nip50():
    """NIP-50 search over the FTS5 index: ranking, limit after ranking, live, backfill (step 7)."""
    import sqlite3
    r = Relay(); w = WS(r.port); k = Key(); now = int(time.time())
    best = k.ev("nostr apps: the best nostr apps for nostr", 1, [], ca=now - 30)
    ok1 = k.ev("some nostr apps", 1, [], ca=now - 10)
    other = k.ev("bitcoin only", 1, [], ca=now - 5)
    art = k.ev("Long form about Nostr APPS", 30023, [["d", "x"]], ca=now - 20)
    dm = k.ev("nostr apps", 4, [["p", k.pk]], ca=now - 1)
    for e in (best, ok1, other, art, dm): w.publish(e)
    evs, end = w.req("s1", {"search": "nostr apps"})
    ids = [e["id"] for e in evs]
    check("search returns only matching, non-encrypted events", set(ids) == {best["id"], ok1["id"], art["id"]}, ids)
    check("best match first (not newest first)", ids and ids[0] == best["id"], ids)
    evs, _ = w.req("s2", {"search": "nostr apps", "limit": 1})
    check("limit applies after ranking", [e["id"] for e in evs] == [best["id"]], evs)
    evs, _ = w.req("s3", {"search": "NOSTR apps", "kinds": [30023]})
    check("search + kinds, case-insensitive", [e["id"] for e in evs] == [art["id"]], evs)
    evs, _ = w.req("s4", {"search": "include:spam nostr"})
    check("unsupported key:value extensions are ignored", len(evs) == 3, len(evs))
    evs, _ = w.req("s5", {"search": "app"})
    check("whole-word terms (no substring hits)", evs == [], evs)
    evs, end = w.req("s6", {"search": "\"; DROP TABLE event; --"})
    check("FTS syntax in the query is inert", end and end[0] == "EOSE", end)
    w.send(["COUNT", "c", {"search": "nostr"}]); m = w.recv()
    check("COUNT with search", m and m[0] == "COUNT" and m[2]["count"] == 3, m)
    pub = WS(r.port)
    w.send(["REQ", "live", {"search": "zaps", "since": now - 100}]); w.recv()
    pub.publish(k.ev("no match here", 1, [])); hit = k.ev("Zaps are great", 1, []); pub.publish(hit)
    m = w.recv()
    check("live events matched with the same terms", m and m[0] == "EVENT" and m[2]["id"] == hit["id"], m)
    _, d = nip11_doc(r)
    check("NIP-11 declares 50", 50 in d.get("supported_nips", []), d.get("supported_nips"))
    r.stop()
    db = sqlite3.connect(r.db)
    db.executescript("DROP TRIGGER event_fts_insert; DROP TRIGGER event_fts_delete; DROP TABLE event_fts;")
    db.close()
    r.start(); w = WS(r.port)
    evs, _ = w.req("s7", {"search": "nostr apps"})
    check("search index backfilled for an older database", len(evs) == 3, len(evs))
    r.stop()
    off = Relay("search = 0\n", db=r.db); w = WS(off.port)
    _, end = w.req("s8", {"search": "nostr"})
    check("search = 0: CLOSED unsupported:", end and end[0] == "CLOSED" and end[2].startswith("unsupported:"), end)
    _, d = nip11_doc(off)
    check("search = 0: NIP-11 omits 50", 50 not in d.get("supported_nips", []), d.get("supported_nips"))
    off.stop()
    db = sqlite3.connect(r.db)
    check("search = 0 drops the index", db.execute("SELECT count(*) FROM sqlite_master WHERE name LIKE 'event_fts%'").fetchone()[0] == 0)
    db.close()
    r.start(); w = WS(r.port)
    evs, _ = w.req("s9", {"search": "nostr apps"})
    check("re-enabled: index rebuilt", len(evs) == 3, len(evs))
    r.stop()


@section
def ratelimit():
    """Per-IP / per-pubkey GCRA rate limits and ban lists (step 8)."""
    import os, tempfile
    conf = ("rate_events_per_min_ip = 60\nrate_events_burst_ip = 5\n"
            "rate_events_per_min_pubkey = 60\nrate_events_burst_pubkey = 2\n"
            "rate_reqs_per_min_ip = 60\nrate_reqs_burst_ip = 3\n")
    r = Relay(conf); a = WS(r.port); b = WS(r.port); k1 = Key(); k2 = Key()
    res = [a.publish(k1.ev("x%d" % i)) for i in range(3)]
    check("per pubkey: burst 2, then rate-limited:", [m[2] for m in res] == [True, True, False] and res[2][3].startswith("rate-limited:"), res[2])
    res = [b.publish(k2.ev("y%d" % i)) for i in range(2)]
    check("another pubkey has its own budget", all(m[2] for m in res), res)
    m = b.publish(Key().ev("z"))
    check("per IP (shared by all connections): burst 5, then rate-limited:", m[2] is False and m[3].startswith("rate-limited:") and "IP" in m[3], m)
    ends = [a.req("q%d" % i, {"kinds": [1], "limit": 1})[1] for i in range(4)]
    check("REQ per IP: burst 3, then CLOSED rate-limited:", [e[0] for e in ends] == ["EOSE"] * 3 + ["CLOSED"] and ends[3][2].startswith("rate-limited:"), ends)
    time.sleep(1.1)
    m = a.publish(Key().ev("later"))
    check("budget refills over time", m[2] is True, m)
    r.stop()
    bad = Key()
    d = tempfile.mkdtemp()
    bf = os.path.join(d, "bans.txt")
    open(bf, "w").write("# test\npubkey %s\n" % bad.pk)
    r = Relay("ban_file = %s\n" % bf); w = WS(r.port)
    m = w.publish(bad.ev("hi"))
    check("banned pubkey -> OK false blocked:", m[2] is False and m[3].startswith("blocked:"), m)
    m = w.publish(Key().ev("hi"))
    check("others unaffected; limits off by default", m[2] is True, m)
    r.stop()
    r = Relay("banned_ips = 127.0.0.1\n"); w = WS(r.port)
    m = w.recv()
    while m and m[0] == "AUTH": m = w.recv()
    check("banned IP -> NOTICE blocked: and close", m and m[0] == "NOTICE" and m[1].startswith("blocked:"), m)
    r.stop()
    open(bf, "w").write("bogus line\n")
    try:
        Relay("ban_file = %s\n" % bf); ok = False
    except RuntimeError as e:
        ok = "invalid ban entry" in str(e)
    check("an invalid ban file stops startup with its line number", ok)


@section
def nip70():
    """NIP-70 protected events, declared in NIP-11 with 13 and 40 (step 9)."""
    r = Relay(); w = WS(r.port); k = Key(); other = Key()
    _, d = nip11_doc(r)
    sn = d.get("supported_nips", [])
    check("NIP-11 declares 13, 40 and 70", all(n in sn for n in (13, 40, 70)), sn)
    ev = k.ev("members only", 1, [["-"]])
    w.challenge = None
    m = w.publish(ev)
    check("unauthenticated -> OK false auth-required: + a fresh AUTH challenge",
          m[2] is False and m[3].startswith("auth-required:") and w.challenge, m)
    m = w.auth(other, "ws://127.0.0.1")
    m = w.publish(ev)
    check("authenticated as someone else -> restricted:", m[2] is False and m[3].startswith("restricted:"), m)
    w2 = WS(r.port); w2.auth(k, "ws://127.0.0.1")
    m = w2.publish(ev)
    check("authenticated as the author -> accepted", m[2] is True, m)
    rp = other.ev(json.dumps(ev), 6, [["e", ev["id"]], ["p", k.pk]])
    m = w2.publish(rp)
    check("repost embedding a protected event -> blocked:", m[2] is False and m[3].startswith("blocked:"), m)
    m = w2.publish(other.ev("", 6, [["e", ev["id"]], ["p", k.pk]]))
    check("repost without the embedded event is fine", m[2] is True, m)
    r.stop()


RELAY_SK = "0000000000000000000000000000000000000000000000000000000000000003"
RELAY_PK = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"


def keyed_relay(extra=""):
    import os, tempfile
    d = tempfile.mkdtemp(); kf = os.path.join(d, "relay.key")
    open(kf, "w").write(RELAY_SK + "\n"); os.chmod(kf, 0o600)
    return Relay("relay_secret_key_file = %s\n%s" % (kf, extra))


@section
def nip29():
    """NIP-29 relay-based groups (step 11, slice B)."""
    import signal
    r = keyed_relay(); w = WS(r.port)
    alice, bob, carol = Key(), Key(), Key()
    _, d = nip11_doc(r)
    check("NIP-11: self is the relay key, 29 declared", d.get("self") == RELAY_PK and 29 in d.get("supported_nips", []), d)
    m = w.publish(alice.ev("", 9007, [["h", "pizza"]]))
    check("create-group (9007)", m[2] is True, m)
    evs, _ = w.req("st", {"kinds": [39000, 39001, 39002, 39003], "#d": ["pizza"]})
    by = {e["kind"]: e for e in evs}
    check("relay publishes 39000-39003 signed by its own key", sorted(by) == [39000, 39001, 39002, 39003] and
          all(e["pubkey"] == RELAY_PK for e in evs), [(e["kind"], e["pubkey"][:8]) for e in evs])
    check("creator is admin (39001)", ["p", alice.pk, "admin"] in by[39001]["tags"], by[39001]["tags"])
    m = w.publish(bob.ev("", 9007, [["h", "pizza"]]))
    check("create of an existing id -> duplicate:", m[2] is False and m[3].startswith("duplicate:"), m)
    m = w.publish(bob.ev("", 39000, [["d", "pizza"], ["name", "pwned"]]))
    check("39000 from anyone but the relay -> blocked:", m[2] is False and m[3].startswith("blocked:"), m)
    m = w.publish(bob.ev("hi", 9, [["h", "nogroup"]]))
    check("h tag of an unknown group -> invalid:", m[2] is False and m[3].startswith("invalid:"), m)
    m = w.publish(bob.ev("open hello", 9, [["h", "pizza"]]))
    check("open group: anyone may write", m[2] is True, m)
    m = w.publish(bob.ev("", 9002, [["h", "pizza"], ["name", "Hacked"]]))
    check("edit-metadata by a non-admin -> restricted:", m[2] is False and m[3].startswith("restricted:"), m)
    m = w.publish(alice.ev("", 9002, [["h", "pizza"], ["name", "Pizza Lovers"], ["private"], ["restricted"], ["closed"]]))
    check("edit-metadata by the admin", m[2] is True, m)
    evs, _ = w.req("m", {"kinds": [39000], "#d": ["pizza"]})
    check("39000 updated", evs and ["name", "Pizza Lovers"] in evs[0]["tags"] and ["private"] in evs[0]["tags"], evs)
    m = w.publish(bob.ev("again", 9, [["h", "pizza"]]))
    check("restricted group: non-member write -> restricted:", m[2] is False and m[3].startswith("restricted:"), m)
    m = w.publish(bob.ev("", 9021, [["h", "pizza"]]))
    check("closed group: join without code -> restricted:", m[2] is False and m[3].startswith("restricted:"), m)
    m = w.publish(alice.ev("", 9009, [["h", "pizza"], ["code", "abc123"]]))
    check("create-invite by the admin", m[2] is True, m)
    m = w.publish(bob.ev("", 9021, [["h", "pizza"], ["code", "abc123"]]))
    check("join with the invite code", m[2] is True, m)
    a0 = WS(r.port); a0.auth(alice, "ws://127.0.0.1")
    evs, _ = a0.req("pu", {"kinds": [9000], "#h": ["pizza"], "#p": [bob.pk]})
    check("relay answers the join with a signed put-user (9000)", len(evs) == 1 and evs[0]["pubkey"] == RELAY_PK, evs)
    m = w.publish(bob.ev("", 9021, [["h", "pizza"], ["code", "abc123"]]))
    check("join as a member -> duplicate:", m[3].startswith("duplicate:"), m)
    msg = bob.ev("member hello", 9, [["h", "pizza"]])
    m = w.publish(msg)
    check("member writes", m[2] is True, m)
    c = WS(r.port)
    _, end = c.req("p1", {"#h": ["pizza"]})
    check("private group, unauthenticated REQ -> CLOSED auth-required:", end[0] == "CLOSED" and end[2].startswith("auth-required:"), end)
    c.auth(carol, "ws://127.0.0.1")
    evs, _ = c.req("p2", {"#h": ["pizza"]})
    check("private group, authenticated non-member reads nothing", evs == [], len(evs))
    b = WS(r.port); b.auth(bob, "ws://127.0.0.1")
    evs, _ = b.req("p3", {"#h": ["pizza"], "kinds": [9]})
    check("member reads the group", msg["id"] in [e["id"] for e in evs], len(evs))
    m = w.publish(bob.ev("", 9000, [["h", "pizza"], ["p", carol.pk]]))
    check("put-user by a plain member -> restricted:", m[2] is False and m[3].startswith("restricted:"), m)
    m = w.publish(alice.ev("", 9000, [["h", "pizza"], ["p", carol.pk, "moderator"]]))
    check("admin adds a moderator", m[2] is True, m)
    m = w.publish(carol.ev("", 9005, [["h", "pizza"], ["e", msg["id"]]]))
    check("moderator deletes a message (9005)", m[2] is True, m)
    evs, _ = b.req("p4", {"ids": [msg["id"]]})
    check("... it is gone", evs == [], evs)
    m = w.publish(bob.ev("", 9022, [["h", "pizza"]]))
    check("leave (9022)", m[2] is True, m)
    m = w.publish(bob.ev("after leaving", 9, [["h", "pizza"]]))
    check("after leaving: write -> restricted:", m[2] is False and m[3].startswith("restricted:"), m)
    r.stop(signal.SIGKILL); r.start(); w = WS(r.port)
    m = w.publish(bob.ev("after restart", 9, [["h", "pizza"]]))
    check("restart: state replayed (left member still out)", m[2] is False and m[3].startswith("restricted:"), m)
    m = w.publish(carol.ev("mod still here", 9, [["h", "pizza"]]))
    check("restart: moderator still a member", m[2] is True, m)
    _, end = WS(r.port).req("p5", {"#h": ["pizza"]})
    check("restart: still private", end[0] == "CLOSED", end)
    m = w.publish(alice.ev("", 9008, [["h", "pizza"]]))
    check("delete-group (9008) by the admin", m[2] is True, m)
    a = WS(r.port); a.auth(alice, "ws://127.0.0.1")
    evs, _ = a.req("p6", {"#h": ["pizza"], "kinds": [9]})
    evs2, _ = a.req("p7", {"#d": ["pizza"], "kinds": [39000]})
    check("its events and state are gone", evs == [] and evs2 == [], (len(evs), len(evs2)))
    m = w.publish(alice.ev("x", 9, [["h", "pizza"]]))
    check("writing to the deleted group -> invalid:", m[2] is False and m[3].startswith("invalid:"), m)
    r.stop()
    r = Relay(); w = WS(r.port)
    m = w.publish(alice.ev("", 9007, [["h", "g"]]))
    _, d = nip11_doc(r)
    check("without a relay key: unsupported:, 29 not declared", m[2] is False and m[3].startswith("unsupported:") and
          29 not in d.get("supported_nips", []), m)
    r.stop()


@section
def nip43():
    """NIP-43 relay membership (step 12)."""
    import signal, time as _t
    r = keyed_relay("nip43 = 1\nmembers_only = 1\ninvite_codes = abc, def\n")
    alice, bob = Key(), Key()
    _, d = nip11_doc(r)
    check("NIP-11: 43 declared, restricted_writes", 43 in d.get("supported_nips", []) and
          d.get("limitation", {}).get("restricted_writes") is True, d)
    w = WS(r.port)
    m = w.publish(alice.ev("hello", 1))
    check("members-only: non-member write -> restricted:", m[2] is False and m[3].startswith("restricted:"), m)
    m = w.publish(alice.ev("", 28934, [["-"], ["claim", "def"]]))
    check("claim before AUTH -> auth-required: (NIP-70)", m[2] is False and m[3].startswith("auth-required:"), m)
    w.auth(alice, "ws://127.0.0.1")
    m = w.publish(alice.ev("", 28934, [["-"], ["claim", "nope"]]))
    check("bad code -> restricted:", m[2] is False and m[3].startswith("restricted:"), m)
    m = w.publish(alice.ev("", 28934, [["-"], ["claim", "def"]], ca=int(_t.time()) - 1000))
    check("stale claim -> invalid:", m[2] is False and m[3].startswith("invalid:"), m)
    m = w.publish(alice.ev("", 28934, [["-"], ["claim", "def"]]))
    check("valid claim -> OK true info: welcome", m[2] is True and m[3].startswith("info: welcome"), m)
    evs, _ = w.req("ml", {"kinds": [13534]})
    check("relay publishes its 13534 member list", len(evs) == 1 and evs[0]["pubkey"] == RELAY_PK and ["-"] in evs[0]["tags"]
          and ["member", alice.pk] in evs[0]["tags"], evs)
    evs, _ = w.req("au", {"kinds": [8000], "#p": [alice.pk]})
    check("relay publishes 8000 add-user", len(evs) == 1 and evs[0]["pubkey"] == RELAY_PK, evs)
    m = w.publish(alice.ev("member hello", 1))
    check("member writes", m[2] is True, m)
    m = w.publish(alice.ev("", 28934, [["-"], ["claim", "abc"]]))
    check("claim as a member -> OK true duplicate:", m[2] is True and m[3].startswith("duplicate:"), m)
    m = WS(r.port).publish(bob.ev("", 13534, [["member", bob.pk]]))
    check("13534 from anyone but the relay -> blocked:", m[2] is False and m[3].startswith("blocked:"), m)
    r.stop(signal.SIGKILL); r.start()
    w = WS(r.port)
    m = w.publish(alice.ev("after restart", 1))
    check("restart: membership reloaded from 13534", m[2] is True, m)
    w.auth(alice, "ws://127.0.0.1")
    m = w.publish(alice.ev("", 28936, [["-"]]))
    check("leave request", m[2] is True, m)
    evs, _ = w.req("rm", {"kinds": [8001], "#p": [alice.pk]})
    evs2, _ = w.req("ml2", {"kinds": [13534]})
    check("relay publishes 8001 and an updated 13534", len(evs) == 1 and len(evs2) == 1 and
          ["member", alice.pk] not in evs2[0]["tags"], (evs, evs2))
    m = w.publish(alice.ev("after leaving", 1))
    check("after leaving: write -> restricted:", m[2] is False and m[3].startswith("restricted:"), m)
    r.stop()
    r = keyed_relay()
    _, d = nip11_doc(r)
    m = WS(r.port).publish(alice.ev("open relay", 1))
    check("nip43 off: 43 not declared, open writes", 43 not in d.get("supported_nips", []) and m[2] is True, m)
    r.stop()


@section
def nip67():
    """NIP-67 EOSE completeness hints (step 13)."""
    r = Relay("default_limit = 2\nmax_limit = 4\n"); w = WS(r.port)
    _, d = nip11_doc(r)
    check("NIP-11 declares 67", 67 in d.get("supported_nips", []), d.get("supported_nips"))
    a = Key()
    evs = [a.ev("n%d" % i, 1, ca=1700000000 + i) for i in range(4)]
    for e in evs: w.publish(e)
    got, end = w.req("all", {"authors": [a.pk], "kinds": [1], "limit": 4})
    check("limit == stored count -> [\"finish\"]", len(got) == 4 and end[2:] == [["finish"]], (len(got), end))
    got, end = w.req("cut", {"authors": [a.pk], "kinds": [1], "limit": 3})
    check("limit below stored count -> [\"more\"]", len(got) == 3 and end[2:] == [["more"]], (len(got), end))
    got, end = w.req("dflt", {"authors": [a.pk], "kinds": [1]})
    check("default_limit cap -> [\"more\"]", len(got) == 2 and "more" in end[2], (len(got), end))
    w.publish(a.ev("n4", 1, ca=1700000004))
    got, end = w.req("cap", {"authors": [a.pk], "kinds": [1], "limit": 50})
    check("max_limit cap below the client limit -> [\"more\"]", len(got) == 4 and "more" in end[2], (len(got), end))
    got, end = w.req("ids", {"ids": [evs[0]["id"]]})
    check("ids filter -> \"finish\"", len(got) == 1 and "finish" in end[2] and "more" not in end[2], end)
    got, end = w.req("two", {"ids": [evs[0]["id"]]}, {"authors": [a.pk], "kinds": [1], "limit": 1})
    check("any filter truncated -> [\"more\"]", "more" in end[2] and "finish" not in end[2], end)
    got, end = w.req("live", {"authors": [a.pk], "kinds": [1], "limit": 0})
    check("limit:0 (live only) -> neither hint", end[2] == [], end)
    got, end = w.req("gw", {"limit": 1, "kinds": [1]})
    check("no AUTH-gated data -> no \"auth\"", "auth" not in end[2], end)
    got, end = w.req("kl", {"limit": 10})
    check("kind-less REQ before AUTH (gift wraps withheld) -> \"auth\", challenge sent earlier",
          "auth" in end[2] and w.challenge is not None, (end, w.challenge))
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

#!/usr/bin/env python3
"""realgen.py - realistic Nostr load scenario (see gate-results/realload-model.md).

  realgen.py OUTDIR [--events N] [--preload P] [--users U] [--seed S]

Writes
  OUTDIR/preload.txt   the first --preload events (history to load before the run)
  OUTDIR/events.txt    the rest, in publish order; content starts with the decimal
                       line index within this file (ngload latency stamp). Kind mix,
                       tag shapes and sizes follow the model: notes, reactions,
                       reposts, zap receipts, NIP-17 gift wraps, profiles, follow
                       and relay lists, long-form, NIP-22 comments.
  OUTDIR/scenario.txt  one subscriber per line: class TAB frame TAB frame ...
                       (REQs a client sends on connect; "L*" ids stay open).
  OUTDIR/browse.txt    one REQ filter (JSON) per line: thread / profile / zap views
                       an active user opens while scrolling (closed at EOSE).
Population: 2000 signing keys (who publish, zipf by popularity) inside a universe
of 50000 pubkeys (follow and p-tag targets, zipf). Users are universe members.
"""
import hashlib, json, math, os, random, sys
from multiprocessing import Pool
from coincurve import PrivateKey

NK, NU = 2000, 50000
def h(s): return hashlib.sha256(s.encode()).hexdigest()
KEYS = None; PKS = None; UNIV = None
def init():
    global KEYS, PKS, UNIV
    KEYS = [PrivateKey(hashlib.sha256(b'rk%d' % k).digest()) for k in range(NK)]
    PKS = [k.public_key_xonly.format().hex() for k in KEYS]
    UNIV = PKS + [h('upk%d' % i) for i in range(NU - NK)]
def zipf(rng, n, s=1.2):
    u = rng.random(); return min(n - 1, max(0, int(n ** (u ** s)) - 1))
WORDS = ("gm nostr bitcoin the a relay zap freedom code coffee morning today love world post cat dog music "
         "art build ship pleb sats lightning wallet node privacy keys client note thread reply").split()
def text(rng, lo, hi): return " ".join(rng.choice(WORDS) for _ in range(rng.randint(lo, hi)))
T0 = 1760000000

def mk(args):
    lo, hi, seed, base = args
    init_needed = KEYS is None
    if init_needed: init()
    rng = random.Random(seed * 1000003 + lo)
    recent = []                                    # (id, author pk) of recent notes, for reactions
    out = []
    for i in range(lo, hi):
        ki = zipf(rng, NK); k = KEYS[ki]; pk = PKS[ki]
        x = rng.random(); tags = []; content = ""
        def target():
            if recent and rng.random() < 0.85:
                return recent[-1 - min(len(recent) - 1, zipf(rng, len(recent), 1.4))]
            return (h('old%d' % zipf(rng, 500000)), UNIV[zipf(rng, NU)])
        if x < 0.30:                                # kind 1 note (root or reply)
            kind = 1
            if rng.random() < 0.55:
                eid, apk = target()
                tags += [["e", eid, "", "root"], ["p", apk]]
                if rng.random() < 0.4: tags.append(["e", target()[0], "", "reply"])
            for _ in range(rng.choice([0, 0, 1, 1, 2, 4])): tags.append(["p", UNIV[zipf(rng, NU)]])
            for _ in range(rng.choice([0, 0, 0, 1, 2])): tags.append(["t", WORDS[zipf(rng, len(WORDS))]])
            content = text(rng, 2, 40) if rng.random() < 0.97 else text(rng, 150, 400)
        elif x < 0.65:                              # kind 7 reaction
            kind = 7; eid, apk = target(); tags = [["e", eid], ["p", apk], ["k", "1"]]; content = rng.choice(["+", "+", "🤙", "❤️"])
        elif x < 0.71:                              # kind 6 repost (embeds the note JSON)
            kind = 6; eid, apk = target(); tags = [["e", eid, "wss://relay.example"], ["p", apk]]
            content = json.dumps({"id": eid, "pubkey": apk, "kind": 1, "content": text(rng, 5, 40), "tags": [], "created_at": T0, "sig": "0" * 128})
        elif x < 0.76:                              # kind 9735 zap receipt (from a zapper service key)
            kind = 9735; k = KEYS[1999]; pk = PKS[1999]; eid, apk = target()
            desc = json.dumps({"kind": 9734, "content": "", "tags": [["p", apk], ["e", eid], ["amount", "21000"]], "pubkey": UNIV[zipf(rng, NU)]})
            tags = [["p", apk], ["e", eid], ["P", UNIV[zipf(rng, NU)]], ["bolt11", "lnbc210n1" + h('b%d' % i)[:180]], ["description", desc]]
        elif x < 0.81:                              # kind 1059 NIP-17 gift wrap to a user
            kind = 1059; k = PrivateKey(hashlib.sha256(b'eph%d' % i).digest()); pk = k.public_key_xonly.format().hex()
            tags = [["p", UNIV[rng.randrange(NU)]]]; content = "A" * rng.randint(900, 2400)
        elif x < 0.84:                              # kind 0 profile
            kind = 0; content = json.dumps({"name": "user%d" % ki, "about": text(rng, 5, 30), "picture": "https://img.example/%d.jpg" % ki, "nip05": "u%d@example.com" % ki, "lud16": "u%d@wallet.example" % ki})
        elif x < 0.855:                             # kind 3 follow list (100-2000 p tags)
            kind = 3; n = min(2000, max(20, int(rng.lognormvariate(math.log(250), 0.9))))
            tags = [["p", UNIV[zipf(rng, NU)]] for _ in range(n)]
        elif x < 0.87:                              # kind 10002 relay list
            kind = 10002; tags = [["r", "wss://relay%d.example" % rng.randrange(50)] for _ in range(rng.randint(2, 8))]
        elif x < 0.875:                             # kind 30023 long-form
            kind = 30023; tags = [["d", "a%d" % i], ["title", text(rng, 3, 8)], ["t", WORDS[zipf(rng, len(WORDS))]]]; content = text(rng, 400, 1500)
        elif x < 0.905:                             # kind 1111 NIP-22 comment
            kind = 1111; eid, apk = target()
            tags = [["E", eid, "", apk], ["K", "1"], ["P", apk], ["e", eid, "", apk], ["k", "1"], ["p", apk]]; content = text(rng, 2, 30)
        elif x < 0.93:                              # kind 5 deletion of own recent note
            kind = 5; tags = [["e", h('del%d' % i)], ["k", "1"]]
        else:                                       # misc: 1984 reports, 30078 app data, 10000 mutes, 9802 highlights, 31990..
            kind = rng.choice([30078, 30078, 10000, 9802, 1984, 31234, 10003, 30000])
            if kind in (30078, 31234, 30000): tags = [["d", "app%d" % rng.randrange(20)]]
            if kind in (10000, 10003, 30000): tags += [["p", UNIV[zipf(rng, NU)]] for _ in range(rng.randint(5, 80))]
            content = "x" * rng.randint(0, 3000) if kind == 30078 else text(rng, 0, 10)
        stamp = i - base if i >= base else i
        content = "%d %s" % (stamp, content) if kind not in (6, 0) else content
        if kind == 0: content = content[:-1] + ',"n":"%d"}' % i     # still valid JSON; latency stamp unused
        ca = T0 + i // 50
        ev = [0, pk, ca, kind, tags, content]
        s = json.dumps(ev, separators=(',', ':'), ensure_ascii=False)
        eid = hashlib.sha256(s.encode()).digest()
        out.append(json.dumps(["EVENT", {"id": eid.hex(), "pubkey": pk, "created_at": ca, "kind": kind, "tags": tags,
                                         "content": content, "sig": k.sign_schnorr(eid).hex()}], separators=(',', ':'), ensure_ascii=False))
        if kind == 1: recent.append((eid.hex(), pk)); recent = recent[-5000:]
    return out

def scenario(rng, nusers):
    lines = []
    for u in range(nusers):
        me = UNIV[rng.randrange(NU)]
        r = rng.random()
        if r < 0.55:                                # idle/background: notifications + DMs stay open
            fr = [["REQ", "Ln", {"kinds": [1, 6, 7, 9735], "#p": [me], "limit": 0}],
                  ["REQ", "Ld", {"kinds": [1059], "#p": [me], "limit": 0}]]
            cls = "idle"
        elif r < 0.95:                              # active client startup (Damus/Amethyst-like)
            nf = min(2000, max(30, int(rng.lognormvariate(math.log(300), 0.8))))
            follows = sorted({UNIV[zipf(rng, NU, 1.05)] for _ in range(nf)})
            fr = []
            for c in range(0, len(follows), 500):
                ch = follows[c:c + 500]
                fr.append(["REQ", "Lh%d" % (c // 500), {"kinds": [1, 6, 7, 30023, 9802], "authors": ch, "limit": min(500, 10 * len(ch))}])
            fr.append(["REQ", "Ln", {"kinds": [1, 6, 7, 9735], "#p": [me], "limit": 100}])
            fr.append(["REQ", "Ld", {"kinds": [1059], "#p": [me]}])
            fr.append(["REQ", "Lm", {"kinds": [0, 3, 10002, 10000], "authors": [me]}])
            for c in range(0, min(len(follows), 1000), 500):
                fr.append(["REQ", "P%d" % (c // 500), {"kinds": [0], "authors": follows[c:c + 500]}])   # closed at EOSE
            cls = "active"
        else:                                       # global / hashtag / bot feeds
            fr = [["REQ", "Lg", {"kinds": [1], "limit": 100}],
                  ["REQ", "Lt", {"kinds": [1], "#t": [rng.choice(WORDS) for _ in range(5)], "limit": 50}]]
            cls = "global"
        lines.append(cls + "\t" + "\t".join(json.dumps(f, separators=(',', ':')) for f in fr))
    return lines

def browse(rng, n):
    out = []
    for _ in range(n):
        r = rng.random()
        if r < 0.5:
            eid = h('old%d' % zipf(rng, 500000)) if rng.random() < 0.5 else h('x%d' % rng.randrange(10**9))
            out.append({"#e": [eid], "kinds": [1, 6, 7, 9735, 1111], "limit": 200})
        elif r < 0.8:
            out.append({"authors": [UNIV[zipf(rng, NU)]], "kinds": [1, 6], "limit": 50})
        else:
            out.append({"kinds": [0], "authors": [UNIV[zipf(rng, NU)] for _ in range(rng.randint(1, 30))]})
    return out

if __name__ == "__main__":
    a = sys.argv[1:]; d = a[0]
    opt = lambda k, v: int(a[a.index(k) + 1]) if k in a else v
    N, U, seed, P = opt("--events", 300000), opt("--users", 5000), opt("--seed", 1), opt("--preload", 0)
    os.makedirs(d, exist_ok=True); init()
    rng = random.Random(seed)
    with open(os.path.join(d, "scenario.txt"), "w") as f: f.write("\n".join(scenario(rng, U)) + "\n")
    with open(os.path.join(d, "browse.txt"), "w") as f: f.write("\n".join(json.dumps(b, separators=(',', ':')) for b in browse(rng, 20000)) + "\n")
    T = P + N; step = 10000
    ch = [(lo, min(lo + step, T), seed, P) for lo in range(0, T, step)]
    with Pool(8, initializer=init) as p, open(os.path.join(d, "preload.txt"), "w") as fp, open(os.path.join(d, "events.txt"), "w") as fe:
        for (lo, hi, _, _), r in zip(ch, p.imap(mk, ch)):
            for i, line in zip(range(lo, hi), r): (fp if i < P else fe).write(line + "\n")

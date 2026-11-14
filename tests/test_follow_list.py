#!/usr/bin/env python3
"""Follow lists of real clients (up to max_filter_items = 5000 authors): the
live index (sub_entry_t packs the value index into 15 bits) must find the
subscription by any of its authors, first, middle or last."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ngtest import Key, WS, Relay, check, summary
r = Relay(""); k = Key()
others = ["%064x" % (i + 1) for i in range(4999)]
for pos in (0, 2500, 4999):
    auth = others[:pos] + [k.pk] + others[pos:]
    auth = auth[:5000]
    c = WS(r.port); c.send(["REQ", "s", {"authors": auth, "limit": 0}])
    m = c.recv(10); check(f"EOSE pos {pos}", m and m[0] == "EOSE", m)
    p = WS(r.port); e = k.ev("hi %d" % pos, 1, []); p.send(["EVENT", e]); p.recv(5)
    m = c.recv(5); check(f"live delivery with 5000 authors, ours at {pos}", m and m[0] == "EVENT" and m[2]["id"] == e["id"], m)
    c.close(); p.close()
r.stop(); sys.exit(summary())

"""Focused RFC 6455 server conformance test (raw sockets, no ws library).
Run against an echo server:  python tests/rfc6455_conformance.py [host] [port]
Modeled on Autobahn|Testsuite sections 1-7 (framing, pings, reserved bits,
opcodes, fragmentation, UTF-8, close handling). Exit code 0 if all pass."""
import os, socket, struct, sys, time
HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9001
res = []
STRICT = os.environ.get("STRICT", "1") != "0"

def conn():
    s = socket.create_connection((HOST, PORT), timeout=3)
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d: raise IOError("closed in handshake")
        buf += d
    head, rest = buf.split(b"\r\n\r\n", 1)
    assert b" 101 " in head.split(b"\r\n")[0], head
    assert b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" in head
    return s, rest

def frame(op, payload=b"", fin=True, rsv=0, mask=True, length=None):
    b0 = (0x80 if fin else 0) | (rsv << 4) | op
    n = len(payload) if length is None else length
    if n < 126: h = struct.pack("!BB", b0, (0x80 if mask else 0) | n)
    elif n < 65536: h = struct.pack("!BBH", b0, (0x80 if mask else 0) | 126, n)
    else: h = struct.pack("!BBQ", b0, (0x80 if mask else 0) | 127, n)
    if not mask: return h + payload
    k = os.urandom(4)
    return h + k + bytes(c ^ k[i & 3] for i, c in enumerate(payload))

class Reader:
    def __init__(self, s, rest): self.s, self.buf = s, rest
    def need(self, n):
        while len(self.buf) < n:
            d = self.s.recv(65536)
            if not d: raise EOFError
            self.buf += d
    def next(self):
        self.need(2); b0, b1 = self.buf[0], self.buf[1]; n = b1 & 0x7F; h = 2
        if n == 126: self.need(4); n = struct.unpack("!H", self.buf[2:4])[0]; h = 4
        elif n == 127: self.need(10); n = struct.unpack("!Q", self.buf[2:10])[0]; h = 10
        self.need(h + n); p = self.buf[h:h + n]; self.buf = self.buf[h + n:]
        return b0 & 0x0F, p, bool(b0 & 0x80)

def expect_close(r, codes):
    """server must send close with one of codes (None: any close or TCP close) then close TCP"""
    try:
        while True:
            op, p, _ = r.next()
            if op == 8:
                code = struct.unpack("!H", p[:2])[0] if len(p) >= 2 else 1005
                if codes and code not in codes: return False, f"close code {code}"
                return True, f"close {code}"
            if op in (1, 2): continue
    except (EOFError, ConnectionResetError, socket.timeout) as e:
        # RFC 6455 7.1.7 "fail the WebSocket connection" may drop TCP without
        # a close frame; Autobahn accepts that. STRICT mode requires the code.
        return (codes is None or (not STRICT and not isinstance(e, socket.timeout))), f"tcp {type(e).__name__}"

def case(name, fn):
    try: ok, d = fn()
    except Exception as e: ok, d = False, repr(e)
    res.append((name, ok)); print(f"[{'PASS' if ok else 'FAIL'}] {name} {d}")

def echo_case(frames, want):
    def f():
        s, rest = conn(); r = Reader(s, rest)
        for fr in frames: s.sendall(fr)
        got = []
        for w in want:
            op, p, _ = r.next()
            while op == 10 and w[0] != 10: op, p, _ = r.next()
            got.append((op, p))
        s.close()
        return got == want, ""
    return f

def fail_case(frames, codes, pre=None):
    def f():
        s, rest = conn(); r = Reader(s, rest)
        for fr in frames: s.sendall(fr)
        if pre:
            for w in pre:
                op, p, _ = r.next()
                if (op, p) != w: return False, f"pre {op}"
        ok, d = expect_close(r, codes); s.close(); return ok, d
    return f

P = 1002
# 1.x framing / echo
for n in (0, 125, 126, 127, 128, 65535, 65536, 1 << 20):
    pl = os.urandom(n); case(f"1 binary echo {n}B", echo_case([frame(2, pl)], [(2, pl)]))
case("1 text echo", echo_case([frame(1, b"Hello")], [(1, b"Hello")]))
# 2.x ping/pong
case("2.1 ping -> pong", echo_case([frame(9, b"hi")], [(10, b"hi")]))
case("2.2 ping 125B", echo_case([frame(9, b"x" * 125)], [(10, b"x" * 125)]))
case("2.5 ping 126B -> fail", fail_case([frame(9, b"x" * 126)], {P}))
case("2.7 unsolicited pong ignored", echo_case([frame(10, b"p"), frame(1, b"a")], [(1, b"a")]))
case("2.10 10 pings -> 10 pongs", echo_case([frame(9, bytes([i])) for i in range(10)], [(10, bytes([i])) for i in range(10)]))
# 3.x reserved bits
for rsv in (1, 2, 4, 7): case(f"3 RSV={rsv} -> 1002", fail_case([frame(1, b"x", rsv=rsv)], {P}))
case("3.x unmasked client frame -> 1002", fail_case([frame(1, b"x", mask=False)], {P}))
# 4.x opcodes
for op in (3, 4, 5, 6, 7, 11, 12, 15): case(f"4 opcode {op} -> 1002", fail_case([frame(op, b"x")], {P}))
# 5.x fragmentation
case("5.1 fragmented ping -> fail", fail_case([frame(9, b"a", fin=False), frame(0, b"b")], {P}))
case("5.3 text in 2 frags", echo_case([frame(1, b"frag", fin=False), frame(0, b"ment")], [(1, b"fragment")]))
case("5.6 ping between frags", echo_case([frame(1, b"ab", fin=False), frame(9, b"P"), frame(0, b"cd")], [(10, b"P"), (1, b"abcd")]))
case("5.9 continuation without start -> fail", fail_case([frame(0, b"x")], {P}))
case("5.15 new msg while fragmented -> fail", fail_case([frame(1, b"a", fin=False), frame(1, b"b")], {P}))
case("5.19 many frags + pings", echo_case([frame(1, b"a", fin=False)] + [f for i in range(10) for f in (frame(0, b"b", fin=False), frame(9, b"z"))] + [frame(0, b"c")],
                                         [(10, b"z")] * 10 + [(1, b"a" + b"b" * 10 + b"c")]))
# 6.x UTF-8
good = ["κόσμε", "\U0010ffff", "\ud7ff", "\ue000", "\ufffd", "€" * 1000]
for g in good: case(f"6 valid utf8 {g[:3]!r}", echo_case([frame(1, g.encode("utf-8", "surrogatepass"))], [(1, g.encode("utf-8", "surrogatepass"))]))
bad = [b"\xff", b"\xc0\xaf", b"\xe0\x80\xaf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5\xed\xa0\x80edited", b"\xf8\x88\x80\x80\x80", b"\xc2", b"abc\xe2\x82"]
for i, b in enumerate(bad): case(f"6 invalid utf8 #{i} -> 1007", fail_case([frame(1, b)], {1007}))
case("6 invalid utf8 split across frags -> 1007", fail_case([frame(1, b"\xce", fin=False), frame(0, b"\xba\xff")], {1007}))
case("6 valid utf8 split mid-codepoint", echo_case([frame(1, b"\xce", fin=False), frame(0, b"\xba")], [(1, b"\xce\xba")]))
# 7.x close
def close_echo(payload, codes):
    def f():
        s, rest = conn(); r = Reader(s, rest); s.sendall(frame(8, payload)); ok, d = expect_close(r, codes); s.close(); return ok, d
    return f
case("7.1 close no payload", close_echo(b"", {1000, 1005}))
case("7.3 close 1-byte payload -> 1002", close_echo(b"\x03", {P}))
case("7.5 close invalid utf8 reason -> 1007", close_echo(struct.pack("!H", 1000) + b"\xff", {1007}))
for c in (1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 3000, 3999, 4000, 4999):
    case(f"7.7 close code {c} echoed", close_echo(struct.pack("!H", c), {c}))
for c in (0, 999, 1004, 1005, 1006, 1012, 1016, 1100, 2000, 2999, 5000, 65535):
    case(f"7.9 invalid close code {c} -> 1002", close_echo(struct.pack("!H", c), {P}))
case("7.x data after close ignored", fail_case([frame(8, struct.pack("!H", 1000)), frame(1, b"late")], {1000}))
# 9.x-ish large / limits
case("9 4MB fragmented in 64KB frames", echo_case([frame(1 if i == 0 else 0, b"a" * 65536, fin=(i == 63)) for i in range(64)], [(1, b"a" * (64 * 65536))]))
ok = sum(1 for _, c in res if c)
print(f"{ok}/{len(res)} passed ({'strict' if STRICT else 'lenient: TCP drop accepted as failing the connection'})")
sys.exit(0 if ok == len(res) else 1)

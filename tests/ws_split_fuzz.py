"""Randomized framing stress test for the ngws receive path (raw sockets).
Sends random mixes of whole and fragmented TEXT/BINARY messages (0 B .. 300 KB)
and interleaved PINGs, written in random chunk sizes (1 B .. 200 KB) so frame
headers, masks and payloads are split at arbitrary offsets; checks every echo
and PONG byte for byte. Run against an echo server:
    python tests/ws_split_fuzz.py [port] [rounds] [seed]"""
import os, random, socket, struct, sys
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9001
ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 200
rnd = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 1)

def frame(op, payload, fin=True):
    n = len(payload); b0 = (0x80 if fin else 0) | op
    if n < 126: h = struct.pack("!BB", b0, 0x80 | n)
    elif n < 65536: h = struct.pack("!BBH", b0, 0x80 | 126, n)
    else: h = struct.pack("!BBQ", b0, 0x80 | 127, n)
    k = os.urandom(4)
    m = (k * (n // 4 + 1))[:n]
    return h + k + (int.from_bytes(payload, "little") ^ int.from_bytes(m, "little")).to_bytes(n, "little")

def conn():
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf: buf += s.recv(4096)
    return s, buf.split(b"\r\n\r\n", 1)[1]

class R:
    def __init__(s, sock, rest): s.s, s.b = sock, rest
    def need(s, n):
        while len(s.b) < n:
            d = s.s.recv(1 << 20)
            if not d: raise EOFError("server closed")
            s.b += d
    def frame(s):
        s.need(2); op = s.b[0] & 15; n = s.b[1] & 127; h = 2
        if n == 126: s.need(4); n = struct.unpack("!H", s.b[2:4])[0]; h = 4
        elif n == 127: s.need(10); n = struct.unpack("!Q", s.b[2:10])[0]; h = 10
        s.need(h + n); p = s.b[h:h + n]; s.b = s.b[h + n:]; return op, p

def size():
    r = rnd.random()
    return rnd.randint(0, 125) if r < .4 else rnd.randint(126, 70000) if r < .8 else rnd.randint(65536, 300000)

def payload(op, n):
    return bytes(rnd.choice(b"abcdefghij") for _ in range(min(n, 64))) * (n // 64 + 1) if op == 1 else os.urandom(n)

sock, rest = conn(); rd = R(sock, rest); total = 0
for rnd_i in range(ROUNDS):
    wire = b""; expect = []
    for _ in range(rnd.randint(1, 6)):
        op = rnd.choice((1, 2)); p = payload(op, size())[:size()]
        if rnd.random() < 0.3 and len(p) > 2:   # fragmented, with a ping in between
            cuts = sorted(rnd.sample(range(1, len(p)), min(len(p) - 1, rnd.randint(1, 4))))
            parts = [p[a:b] for a, b in zip([0] + cuts, cuts + [len(p)])]
            for i, part in enumerate(parts):
                wire += frame(op if i == 0 else 0, part, fin=i == len(parts) - 1)
                if i == 0 and rnd.random() < .5:
                    pp = os.urandom(rnd.randint(0, 125)); wire += frame(9, pp); expect.append((10, pp))
        else: wire += frame(op, p)
        expect.append((op, p))
    off = 0
    while off < len(wire):   # random chunking
        k = rnd.choice((1, 2, 3, 7, 13, rnd.randint(1, 4096), rnd.randint(1, 200000)))
        sock.sendall(wire[off:off + k]); off += k
    for op, p in expect:
        got = rd.frame()
        assert got == (op, p), "round %d: expected op %d len %d, got op %d len %d" % (rnd_i, op, len(p), got[0], len(got[1]))
        total += 1
print("ws_split_fuzz: %d messages over %d rounds OK" % (total, ROUNDS))

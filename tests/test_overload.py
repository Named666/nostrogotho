#!/usr/bin/env python3
"""Overload / slow-reader regression tests. Each case starts its own relay
(RELAY_BIN, default build/main) with a small budget config.

A per-connection backlog: a non-reading subscriber is closed, a fast one gets
  every event, the publisher every OK; a REQ reply is capped at half the
  per-connection budget and still ends with EOSE.
B process-wide budget: four non-reading subscribers are all closed by the
  aggregate cap (closed_total_limit), the relay keeps serving.
C slow-reader admission: a subscriber with a large backlog gets its REQ and
  EVENT answered CLOSED / OK false "error: ..." (queued behind the backlog).
D per-connection pending limit: 300 pipelined REQs in one write are each
  answered exactly once, EOSE or CLOSED "error: relay overloaded".
E bounded writer queue: 300 pipelined EVENTs each get one OK; overflow is
  OK false "error: relay overloaded" and such an event can be resent.
F worker queue budget: a message larger than the budget is answered by the
  I/O thread (OK false "error: relay overloaded").
"""
import hashlib, json, os, pathlib, signal, socket, struct, subprocess, sys, tempfile, threading, time
from coincurve import PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = os.environ.get("RELAY_BIN", str(ROOT / "build/main"))
SK = PrivateKey()
PK = SK.public_key.format(compressed=True)[1:].hex()
results = []

def check(name, cond, detail=""):
    results.append(bool(cond)); print(f"[{'PASS' if cond else 'FAIL'}] {name} {detail}", flush=True)

def mk(content, kind=1, tags=None, ca=None):
    tags = tags or []; ca = ca or int(time.time())
    ser = json.dumps([0, PK, ca, kind, tags, content], separators=(",", ":"), ensure_ascii=False)
    eid = hashlib.sha256(ser.encode()).hexdigest()
    return {"id": eid, "pubkey": PK, "created_at": ca, "kind": kind, "tags": tags,
            "content": content, "sig": SK.sign_schnorr(bytes.fromhex(eid)).hex()}

def frame(text):
    b = text.encode(); m = os.urandom(4); n = len(b)
    h = bytes([0x81]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n) if n < 65536 else bytes([0x80 | 127]) + struct.pack(">Q", n))
    return h + m + bytes(c ^ m[i & 3] for i, c in enumerate(b))

class WS:
    def __init__(self, port, rcvbuf=None):
        s = socket.socket()
        if rcvbuf: s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        s.connect(("127.0.0.1", port)); s.settimeout(10)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d: raise IOError("closed in handshake")
            buf += d
        self.s, self.buf, self.closed, self.nbytes, self.pos = s, buf.split(b"\r\n\r\n", 1)[1], False, 0, 0
    def send(self, *msgs): self.s.sendall(b"".join(frame(json.dumps(m)) for m in msgs))
    def _fill(self, timeout):
        self.s.settimeout(timeout)
        try: d = self.s.recv(1 << 20)
        except (ConnectionResetError, BrokenPipeError): d = b""
        if not d: self.closed = True; return False
        self.nbytes += len(d); self.buf += d; return True
    def recv(self, timeout=10):
        """Next text message (parsed) or None on close/timeout."""
        while True:
            b, i = self.buf, self.pos
            if len(b) - i >= 2:
                n = b[i + 1] & 127; o = 2
                if n == 126: n = struct.unpack(">H", b[i + 2:i + 4])[0] if len(b) - i >= 4 else -1; o = 4
                elif n == 127: n = struct.unpack(">Q", b[i + 2:i + 10])[0] if len(b) - i >= 10 else -1; o = 10
                if n >= 0 and len(b) - i >= o + n:
                    op = b[i] & 15; payload = b[i + o:i + o + n]; self.pos = i + o + n
                    if self.pos > (1 << 20): self.buf = b[self.pos:]; self.pos = 0
                    if op == 8: self.closed = True; return None
                    if op == 1:
                        m = json.loads(payload)
                        if m and m[0] == "AUTH": continue   # NIP-42 challenge on connect
                        return m
                    continue
            try:
                if not self._fill(timeout): return None
            except socket.timeout: return None
    def close(self):
        try: self.s.close()
        except OSError: pass

class Relay:
    def __init__(self, conf):
        self.td = tempfile.TemporaryDirectory(prefix="ng-overload-")
        with socket.socket() as s: s.bind(("127.0.0.1", 0)); self.port = s.getsockname()[1]
        pathlib.Path(self.td.name, "r.conf").write_text(conf)
        self.err = open(pathlib.Path(self.td.name, "err.log"), "w+")
        env = dict(os.environ, NG_IO_THREADS="2", NG_WORKERS="2")
        self.p = subprocess.Popen([BIN, "--port", str(self.port), "--db", self.td.name + "/t.sqlite",
                                   "--config", self.td.name + "/r.conf"], stdout=subprocess.DEVNULL, stderr=self.err, env=env)
        for _ in range(200):
            try: socket.create_connection(("127.0.0.1", self.port), timeout=.1).close(); return
            except OSError: time.sleep(.02)
        raise RuntimeError("relay did not start")
    def stop(self):
        alive = self.p.poll() is None
        if alive: self.p.send_signal(signal.SIGINT)
        try: self.p.wait(timeout=20)
        except subprocess.TimeoutExpired: self.p.kill(); self.p.wait()
        self.err.seek(0); log = self.err.read(); self.err.close(); self.td.cleanup()
        st = {}
        for line in log.splitlines():
            if line.startswith("overload:"):
                st = {k: int(v) for k, v in (t.split("=") for t in line.split()[1:])}
        return alive, st

def publish(ws, events, window=50):
    oks = {}
    for i in range(0, len(events), window):
        chunk = events[i:i + window]; ws.send(*[["EVENT", e] for e in chunk])
        while sum(1 for e in chunk if e["id"] in oks) < len(chunk):
            m = ws.recv()
            if m is None: return oks
            if m[0] == "OK": oks[m[1]] = (m[2], m[3])
    return oks

def drain(ws, timeout=3):
    """Read until close/timeout. Returns (closed, bytes)."""
    end = time.time() + 30
    while time.time() < end and not ws.closed:
        try:
            if not ws._fill(timeout): break
        except socket.timeout: break
    return ws.closed, ws.nbytes

class Reader(threading.Thread):
    """Reads a subscriber continuously (a fast client), counting EVENTs."""
    def __init__(self, ws):
        super().__init__(daemon=True); self.ws, self.events, self.stop = ws, 0, False; self.start()
    def run(self):
        while not self.stop:
            m = self.ws.recv(0.5)
            if m is None:
                if self.ws.closed: return
                continue
            if m[0] == "EVENT": self.events += 1
    def wait_for(self, n, timeout=20):
        end = time.time() + timeout
        while self.events < n and time.time() < end and not self.ws.closed: time.sleep(.05)
        return self.events

def subscribe(ws, sub="s"):
    ws.send(["REQ", sub, {"kinds": [1], "limit": 0}])

def wait_eose(ws, sub="s"):
    while True:
        m = ws.recv()
        if m is None or (m[0] == "EOSE" and m[1] == sub): return m

N_BIG, BODY = 1500, "x" * 8000
BIG = [mk(BODY + str(i)) for i in range(N_BIG)]

# ---------------------------------------------------------------- A ----
r = Relay("conn_outbound_max = 1M\ntotal_outbound_max = 1G\n")
slow = WS(r.port, rcvbuf=4096); subscribe(slow, "slow")
fast = WS(r.port); subscribe(fast, "fast"); wait_eose(fast, "fast"); fr = Reader(fast)
pub = WS(r.port)
time.sleep(.3)
oks = publish(pub, BIG)
got = fr.wait_for(N_BIG)
check("A publisher got every OK true", len(oks) == N_BIG and all(v[0] for v in oks.values()), f"{len(oks)}/{N_BIG}")
check("A fast subscriber got every event", got == N_BIG, f"{got}/{N_BIG}")
closed, nb = drain(slow)
check("A slow reader closed by the relay", closed, f"received {nb} of ~{N_BIG*8000} bytes")
check("A slow reader received only a fraction", nb < N_BIG * 8000 // 2, f"{nb}")
probe = WS(r.port); probe.send(["REQ", "p", {"kinds": [1], "limit": 500}]); n = 0
while True:
    m = probe.recv(5)
    if m is None or m[0] != "EVENT": break
    n += 1
check("A relay still serves REQ, reply capped by the byte budget", m and m[0] == "EOSE" and 0 < n < 500 and n * 8000 <= 512 * 1024, f"{n} stored events then {m and m[0]}")
alive, st = r.stop()
check("A relay alive, closed_conn_limit counted", alive and st.get("closed_conn_limit", 0) >= 1, str(st))

# ---------------------------------------------------------------- B ----
r = Relay("conn_outbound_max = 64M\ntotal_outbound_max = 1M\n")
slows = [WS(r.port, rcvbuf=4096) for _ in range(4)]
for i, s in enumerate(slows): subscribe(s, f"slow{i}")
fast = WS(r.port); subscribe(fast, "fast"); wait_eose(fast, "fast"); fr = Reader(fast)
pub = WS(r.port); time.sleep(.3)
oks = publish(pub, [mk(BODY + "b" + str(i)) for i in range(N_BIG)], window=20)
rejected = sum(1 for v in oks.values() if not v[0])
got = fr.wait_for(N_BIG - rejected)
states = [drain(s, 2) for s in slows]
check("B every non-reading subscriber closed", all(c for c, _ in states), str(states))
check("B every EVENT answered", len(oks) == N_BIG, f"{len(oks)} ({rejected} rejected under budget)")
check("B fast subscriber got every accepted event", got == N_BIG - rejected, f"{got}/{N_BIG - rejected}")
probe = WS(r.port); subscribe(probe, "p"); check("B relay recovered, REQ served", (wait_eose(probe, "p") or [None])[0] == "EOSE")
alive, st = r.stop()
check("B closed_total_limit counted", alive and st.get("closed_total_limit", 0) >= 1, str(st))

# ---------------------------------------------------------------- C ----
N_C = 2600   # ~22 MB: the kernel absorbs up to tcp_wmem[2] (4 MB here), the rest is backlog
r = Relay("conn_outbound_max = 32M\ntotal_outbound_max = 1G\n")
slow = WS(r.port, rcvbuf=4096); subscribe(slow, "slow")
pub = WS(r.port); time.sleep(.3)
oks = publish(pub, [mk(BODY + "c" + str(i)) for i in range(N_C)])
time.sleep(.3)
ev = mk("from a slow reader")
slow.send(["REQ", "probe", {"kinds": [1], "limit": 1}], ["EVENT", ev])
closed_msg = ok_msg = None; events = 0
while closed_msg is None or ok_msg is None:
    m = slow.recv(5)
    if m is None: break
    if m[0] == "EVENT": events += 1
    elif m[0] == "CLOSED" and m[1] == "probe": closed_msg = m
    elif m[0] == "OK" and m[1] == ev["id"]: ok_msg = m
check("C slow reader's REQ answered CLOSED error:", closed_msg is not None and closed_msg[2].startswith("error:"), str(closed_msg))
check("C slow reader's EVENT answered OK false error:", ok_msg is not None and ok_msg[2] is False and ok_msg[3].startswith("error:"), str(ok_msg))
check("C slow reader kept (under per-connection limit)", not slow.closed and events == N_C, f"events={events}")
alive, st = r.stop()
check("C admission rejections counted", alive and st.get("shed_admission", 0) >= 2, str(st))

# ---------------------------------------------------------------- D ----
r = Relay("conn_pending_max = 8\n")
c = WS(r.port); time.sleep(.2)
c.send(*[["REQ", f"q{i}", {"kinds": [7], "limit": 1}] for i in range(300)])
ans = {}
while len(ans) < 300:
    m = c.recv(5)
    if m is None: break
    if m[0] in ("EOSE", "CLOSED"):
        check_dup = m[1] in ans
        ans[m[1]] = m
        if check_dup: break
shed = [m for m in ans.values() if m[0] == "CLOSED"]
check("D every REQ answered exactly once", len(ans) == 300 and not (c.recv(0.5)), f"{len(ans)}")
check("D overflow shed inline with CLOSED error:", len(shed) > 0 and all(m[2] == "error: relay overloaded, try again later" for m in shed), f"{len(shed)} shed")
alive, st = r.stop()
check("D relay alive, shed_inline counted", alive and st.get("shed_inline", 0) == len(shed), str(st))

# ---------------------------------------------------------------- E ----
r = Relay("writer_queue_max = 2\n")
c = WS(r.port); time.sleep(.2)
evs = [mk(f"writer queue {i}") for i in range(300)]
c.send(*[["EVENT", e] for e in evs])
oks = {}
while len(oks) < 300:
    m = c.recv(5)
    if m is None: break
    if m[0] == "OK": oks[m[1]] = m
rej = [m for m in oks.values() if m[2] is False]
check("E every EVENT answered once", len(oks) == 300, f"{len(oks)}")
check("E writer overflow is OK false error:", len(rej) > 0 and all(m[3].startswith("error: relay overloaded") for m in rej), f"{len(rej)} rejected")
if rej:
    e = next(x for x in evs if x["id"] == rej[0][1]); time.sleep(.3)
    c.send(["EVENT", e]); m = c.recv(5)
    check("E rejected event accepted on retry", m and m[0] == "OK" and m[2] is True, str(m))
alive, st = r.stop()
check("E relay alive", alive, str(st))

# ---------------------------------------------------------------- F ----
r = Relay("worker_queue_max = 64K\n")
c = WS(r.port); time.sleep(.2)
e = mk("y" * 100000); c.send(["EVENT", e]); m = c.recv(5)
check("F oversize-for-budget message shed by the I/O thread", m and m[0] == "OK" and m[1] == e["id"] and m[2] is False and m[3].startswith("error: relay overloaded"), str(m)[:120])
c.send(["REQ", "ok", {"kinds": [1], "limit": 1}]); m = c.recv(5)
check("F small messages still processed", m and m[0] == "EOSE", str(m))
alive, st = r.stop()
check("F relay alive", alive, str(st))

print(f"{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)

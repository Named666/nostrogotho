"""Shared helpers for the relay functional tests: a minimal WebSocket client,
signed event construction (coincurve) and relay process management."""
import hashlib, json, os, pathlib, signal, socket, struct, subprocess, tempfile, time
from coincurve import PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = os.environ.get("RELAY_BIN", str(ROOT / "build/main"))
results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(f"[{'PASS' if cond else 'FAIL'}] {name} {detail}", flush=True)


def summary():
    print(f"{sum(results)}/{len(results)} passed")
    return 0 if all(results) else 1


class Key:
    def __init__(self, sk=None):
        self.sk = sk or PrivateKey()
        self.pk = self.sk.public_key.format(compressed=True)[1:].hex()

    def ev(self, content="", kind=1, tags=None, ca=None):
        tags = tags or []
        ca = int(time.time()) if ca is None else ca
        ser = json.dumps([0, self.pk, ca, kind, tags, content], separators=(",", ":"), ensure_ascii=False)
        eid = hashlib.sha256(ser.encode()).hexdigest()
        return {"id": eid, "pubkey": self.pk, "created_at": ca, "kind": kind, "tags": tags,
                "content": content, "sig": self.sk.sign_schnorr(bytes.fromhex(eid)).hex()}


def frame(text):
    b = text.encode(); m = os.urandom(4); n = len(b)
    if n < 126: h = bytes([0x81, 0x80 | n])
    elif n < 65536: h = bytes([0x81, 0x80 | 126]) + struct.pack(">H", n)
    else: h = bytes([0x81, 0x80 | 127]) + struct.pack(">Q", n)
    return h + m + bytes(c ^ m[i & 3] for i, c in enumerate(b))


class WS:
    def __init__(self, port, host="127.0.0.1", headers=b""):
        s = socket.socket(); s.connect((host, port)); s.settimeout(10)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" + headers +
                  b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d: raise IOError("closed in handshake")
            buf += d
        self.s, self.buf, self.closed = s, buf.split(b"\r\n\r\n", 1)[1], False
        self.challenge = None

    def send(self, *msgs): self.s.sendall(b"".join(frame(json.dumps(m)) for m in msgs))
    def send_raw(self, text): self.s.sendall(frame(text))

    def recv(self, timeout=5, keep_auth=False):
        """Next text message (parsed), or None on close/timeout. AUTH challenges
        are remembered in self.challenge and skipped unless keep_auth."""
        deadline = time.monotonic() + timeout
        while True:
            b = self.buf
            if len(b) >= 2:
                n = b[1] & 127; o = 2
                if n == 126: n = struct.unpack(">H", b[2:4])[0] if len(b) >= 4 else -1; o = 4
                elif n == 127: n = struct.unpack(">Q", b[2:10])[0] if len(b) >= 10 else -1; o = 10
                if n >= 0 and len(b) >= o + n:
                    op = b[0] & 15; payload = b[o:o + n]; self.buf = b[o + n:]
                    if op == 8: self.closed = True; return None
                    if op == 1:
                        m = json.loads(payload)
                        if m and m[0] == "AUTH":
                            self.challenge = m[1]
                            if not keep_auth: continue
                        return m
                    continue
            left = deadline - time.monotonic()
            if left <= 0: return None
            self.s.settimeout(left)
            try: d = self.s.recv(1 << 20)
            except socket.timeout: return None
            except OSError: d = b""
            if not d: self.closed = True; return None
            self.buf += d

    def publish(self, ev, timeout=5):
        """EVENT -> the matching OK (or NOTICE) message."""
        self.send(["EVENT", ev])
        while True:
            m = self.recv(timeout)
            if m is None or m[0] == "NOTICE" or (m[0] == "OK" and m[1] == ev["id"]): return m

    def req(self, sub, *filters, verb="REQ", timeout=5):
        """REQ/COUNT -> (events, terminal message: EOSE / CLOSED / COUNT / None)."""
        self.send([verb, sub, *filters]); evs = []
        while True:
            m = self.recv(timeout)
            if m is None: return evs, None
            if m[0] == "EVENT" and m[1] == sub: evs.append(m[2]); continue
            if m[0] in ("EOSE", "CLOSED", "COUNT") and m[1] == sub: return evs, m
            if m[0] == "NOTICE": return evs, m

    def auth(self, key, relay_url, timeout=5):
        """Answer the last AUTH challenge as key -> the OK message."""
        t0 = time.monotonic()
        while self.challenge is None and time.monotonic() - t0 < timeout:
            m = self.recv(0.2, keep_auth=True)
        ev = key.ev("", 22242, [["relay", relay_url], ["challenge", self.challenge or ""]])
        self.send(["AUTH", ev])
        while True:
            m = self.recv(timeout)
            if m is None or (m[0] == "OK" and m[1] == ev["id"]): return m

    def close(self):
        try: self.s.close()
        except OSError: pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); return s.getsockname()[1]


class Relay:
    """build/main on a free port with a temp DB and an optional config text."""
    def __init__(self, conf="", env=None, db=None, port=None):
        self.dir = tempfile.mkdtemp(prefix="ngtest-")
        self.port = port or free_port()
        self.db = db or os.path.join(self.dir, "t.sqlite")
        self.conf = os.path.join(self.dir, "nostrogotho.conf")
        open(self.conf, "w").write(conf)
        self.url = f"ws://127.0.0.1:{self.port}"
        self.env = dict(os.environ, **(env or {}))
        self.start()

    def start(self):
        self.log = open(os.path.join(self.dir, "relay.log"), "ab")
        self.p = subprocess.Popen([BIN, "--port", str(self.port), "--db", self.db, "--config", self.conf],
                                  cwd=self.dir, env=self.env, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 10
        while True:
            if self.p.poll() is not None: raise RuntimeError("relay exited: " + self.logtext())
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=.1): break
            except OSError:
                if time.monotonic() > deadline: raise RuntimeError("relay did not listen")
                time.sleep(.02)

    def logtext(self):
        try: return open(os.path.join(self.dir, "relay.log"), errors="replace").read()
        except OSError: return ""

    def stop(self, sig=signal.SIGINT):
        if self.p.poll() is None:
            self.p.send_signal(sig)
            try: self.p.wait(timeout=20)
            except subprocess.TimeoutExpired: self.p.kill(); self.p.wait()
        self.log.close()

    def http(self, path="/", headers=None, method="GET", body=b""):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        h = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
        s.sendall(f"{method} {path} HTTP/1.1\r\nHost: x\r\n{h}Content-Length: {len(body)}\r\n\r\n".encode() + body)
        data = b""
        while True:
            d = s.recv(65536)
            if not d: break
            data += d
        s.close()
        head, _, payload = data.partition(b"\r\n\r\n")
        return head.decode(errors="replace"), payload

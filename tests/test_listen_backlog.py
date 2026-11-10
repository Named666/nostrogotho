#!/usr/bin/env python3
"""listen_backlog config: the backlog the kernel reports for the relay's
listening sockets (ss Send-Q) must be the configured value, the kernel cap
(net.core.somaxconn) by default, and capped at somaxconn when larger."""
import os, pathlib, signal, socket, subprocess, sys, tempfile, time
ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = os.environ.get("RELAY_BIN") or str(ROOT / "build/main")
SOMAX = int(open("/proc/sys/net/core/somaxconn").read())
ok = []

def backlogs(conf):
    with tempfile.TemporaryDirectory(prefix="ng-backlog-") as td:
        pathlib.Path(td, "r.conf").write_text(conf)
        with socket.socket() as s: s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
        p = subprocess.Popen([BIN, "--port", str(port), "--db", td + "/t.sqlite", "--config", td + "/r.conf"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=dict(os.environ, NG_IO_THREADS="3"))
        try:
            for _ in range(200):
                try: socket.create_connection(("127.0.0.1", port), timeout=.1).close(); break
                except OSError: time.sleep(.02)
            out = subprocess.run(["ss", "-Hltn", f"sport = :{port}"], capture_output=True, text=True).stdout
            return [int(l.split()[2]) for l in out.splitlines() if l.strip()]
        finally:
            p.send_signal(signal.SIGINT); p.wait(timeout=20)

for conf, want in [("", SOMAX), ("listen_backlog = auto\n", SOMAX), ("listen_backlog = 1234\n", min(1234, SOMAX)),
                   ("listen_backlog = 1000000\n", SOMAX)]:
    got = backlogs(conf)
    good = len(got) == 3 and all(b == want for b in got)   # one SO_REUSEPORT socket per loop
    ok.append(good); print(f"[{'PASS' if good else 'FAIL'}] {conf.strip() or '(default)'} -> {got} want {want}")
print(f"{sum(ok)}/{len(ok)} passed"); sys.exit(0 if all(ok) else 1)

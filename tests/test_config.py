#!/usr/bin/env python3
"""Runtime config startup regression tests (no third-party Python packages)."""
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time

BINARY = str(Path(__file__).resolve().parents[1] / "build/main")


def check(text, valid, explicit=True):
    with tempfile.TemporaryDirectory(prefix="ng-config-") as root:
        config = Path(root) / "nostrogotho.conf"
        if text is not None:
            config.write_text(text)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        args = [BINARY, "--port", str(port), "--db", str(Path(root) / "test.sqlite")]
        if explicit:
            args += ["--config", str(config)]
        env = dict(os.environ, NG_SYNC="NORMAL")  # obsolete override must not matter
        proc = subprocess.Popen(args, cwd=root, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        try:
            if valid:
                deadline = time.monotonic() + 10
                while True:
                    assert proc.poll() is None, proc.communicate()[1].decode()
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.1):
                            break
                    except OSError:
                        assert time.monotonic() < deadline, "relay failed to listen"
                        time.sleep(.02)
                proc.send_signal(signal.SIGINT)
                _, err = proc.communicate(timeout=10)
                assert proc.returncode == 0, err.decode()
            else:
                _, err = proc.communicate(timeout=10)
                assert proc.returncode != 0, "invalid config was accepted"
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()


for text, valid, explicit in [
    (None, True, False),  # absent optional file -> FULL default
    ("", True, True),
    ("db_sync=full\n", True, True),
    ("  db_sync = normal  # performance opt-in\n", True, True),
    ("db_sync=full", True, False),  # final line without newline
    (None, False, True),
    ("db_sync=off\n", False, True),
    ("db_sync=FULL\n", False, True),
    ("typo=normal\n", False, True),
    ("db_sync full\n", False, True),
    ("db_sync=" + "x" * 300, False, True),
]:
    check(text, valid, explicit)
print("PASS: 11 runtime config startup cases")

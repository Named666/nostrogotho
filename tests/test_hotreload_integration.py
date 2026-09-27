"""Linux integration test for module replacement without dropping a socket.

Run after the Linux builder has produced build/nob_configed and build/main:
    python tests/test_hotreload_integration.py

The test starts a hot relay, connects a WebSocket, and publishes two actual
module builds while the same socket remains connected. Each publication must
produce a new loaded generation and the socket must still complete REQ/EOSE.
"""
import asyncio
import json
import os
import pathlib
import socket
import subprocess
import time

import websockets

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
FILTER = {"ids": ["ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"]}


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def loaded_generations(pid):
    files = set(BUILD.glob(f"nhr_{pid}_*.so"))
    if files:
        return files
    # If generation-file cleanup is enabled, use the relay process's image
    # mapping count as the signal that a distinct image is active.
    maps = pathlib.Path(f"/proc/{pid}/maps")
    if maps.exists():
        return {line.split()[-1] for line in maps.read_text().splitlines()
                if "nhr_" in line and line.endswith(".so")}
    return set()


async def wait_for_eose(ws, subscription_id):
    while True:
        message = await asyncio.wait_for(ws.recv(), timeout=20)
        response = json.loads(message)
        if response[0] == "EOSE" and response[1] == subscription_id:
            return


async def verify_socket(uri, process, generations):
    async with websockets.connect(uri, open_timeout=10) as ws:
        await ws.send(json.dumps(["REQ", "before", FILTER]))
        await wait_for_eose(ws, "before")
        for iteration in range(2):
            subprocess.run([str(BUILD / "nob_configed"), "-module-only"],
                           cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                current = loaded_generations(process.pid)
                if current and current != generations:
                    generations = current
                    break
                await asyncio.sleep(0.1)
            else:
                raise AssertionError("host did not load a new module generation")

            subscription_id = f"after-{iteration}"
            await ws.send(json.dumps(["REQ", subscription_id, FILTER]))
            await wait_for_eose(ws, subscription_id)
        print("PASS: two module publications preserved the WebSocket and query path")


def main():
    if os.name == "nt":
        raise SystemExit("This integration test currently requires the Linux/WSL builder")
    port = free_port()
    relay = subprocess.Popen(
        [str(BUILD / "main"), "--hot-reload", "--module",
         str(BUILD / "nostrogotho.so"), "-port", str(port)],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        uri = f"ws://127.0.0.1:{port}"
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                if relay.poll() is not None:
                    raise AssertionError(f"relay exited early: {relay.returncode}")
                time.sleep(0.1)
        else:
            raise AssertionError("relay did not open its listener")

        generations = loaded_generations(relay.pid)
        asyncio.run(verify_socket(uri, relay, generations))
    finally:
        relay.terminate()
        try:
            relay.wait(timeout=5)
        except subprocess.TimeoutExpired:
            relay.kill()
            relay.wait()


if __name__ == "__main__":
    main()
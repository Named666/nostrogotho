"""
NIP-13 PoW acceptance test (difficulty 4).

Starts the relay with MIN_POW_DIFFICULTY=4, then:
  1. Publishes a kind-1 note mined to difficulty >= 4 (with a committed
     ["nonce", "<value>", "4"] tag)  -> expect OK true.
  2. Publishes a kind-1 note with no PoW at all -> expect OK false with a
     "pow:" rejection reason.

Usage: python test_nip13.py
Assumes the relay binary is at build/main(.exe) and websockets + pynacl
are installed.
"""

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import time

import websockets
from coincurve import PrivateKey

PORT = 7449
URI = f"ws://127.0.0.1:{PORT}"
DIFFICULTY = 20


def leading_zero_bits(hex_str: str) -> int:
    count = 0
    for ch in hex_str:
        nibble = int(ch, 16)
        if nibble == 0:
            count += 4
        else:
            count += 4 - nibble.bit_length()
            break
    return count


def pow_proof(event_id: str, difficulty: int) -> str:
    """Human-checkable proof: the id's binary form and its leading zero bits.
    The PoW requirement is met when leading zero bits >= difficulty."""
    bits = bin(int(event_id, 16))[2:].zfill(256)
    zeros = leading_zero_bits(event_id)
    verdict = ">=" if zeros >= difficulty else "<"
    return f"id has {zeros} leading zero bits ({verdict} target {difficulty}): {bits[:zeros]}...{bits[-8:]}"


def serialize_event(pubkey: str, created_at: int, kind: int, tags, content: str) -> str:
    return json.dumps(
        [0, pubkey, created_at, kind, tags, content],
        separators=(",", ":"), ensure_ascii=False,
    )


def mine_event(sk: PrivateKey, content: str, difficulty: int, commit_target: bool):
    """Mine a kind-1 note until its id has >= difficulty leading zero bits."""
    # Nostr pubkey = 32-byte x-coordinate: compressed encoding minus the
    # 1-byte 0x02/0x03 prefix.
    pubkey = sk.public_key.format(compressed=True)[1:].hex()
    created_at = int(time.time())
    nonce = 0
    while True:
        tags = [["nonce", str(nonce), str(difficulty)]] if commit_target else []
        serialized = serialize_event(pubkey, created_at, 1, tags, content)
        event_id = hashlib.sha256(serialized.encode()).hexdigest()
        if leading_zero_bits(event_id) >= difficulty:
            sig = sk.sign_schnorr(bytes.fromhex(event_id)).hex()
            return {
                "id": event_id, "pubkey": pubkey, "created_at": created_at,
                "kind": 1, "tags": tags, "content": content, "sig": sig,
                "_nonce": nonce,
            }
        nonce += 1


async def recv_ok(ws, sub_id: str, timeout=5):
    """Wait for the OK message matching sub_id."""
    while True:
        msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
        parsed = json.loads(msg)
        if parsed[0] == "OK" and parsed[1] == sub_id:
            return parsed


async def run_tests():
    results = []
    async with websockets.connect(URI, open_timeout=10) as ws:
        sk = PrivateKey()

        # --- Test 1: mined note (difficulty 4, committed target) -> accepted
        mined = mine_event(sk, "hello from the NIP-13 test (mined)", DIFFICULTY, True)
        bits = leading_zero_bits(mined["id"])
        print(f"[test 1] mined id={mined['id']} ({bits} zero bits, target {DIFFICULTY})")
        await ws.send(json.dumps(["EVENT", mined], separators=(",", ":")))
        ok = await recv_ok(ws, mined["id"])
        passed = ok[2] is True and leading_zero_bits(mined["id"]) >= DIFFICULTY
        print(f"[test 1] {'PASS' if passed else 'FAIL'} (nonce {mined['_nonce']}): relay said {ok}")
        print(f"[test 1] proof: {pow_proof(mined['id'], DIFFICULTY)}")
        results.append(("mined note accepted", passed))

        # --- Test 2: unmined note -> rejected with pow: reason
        plain = mine_event(sk, "no work done here", 0, False)  # difficulty 0 = no mining
        print(f"[test 2] plain id={plain['id']} ({leading_zero_bits(plain['id'])} zero bits)")
        await ws.send(json.dumps(["EVENT", plain], separators=(",", ":")))
        ok = await recv_ok(ws, plain["id"])
        passed = ok[2] is False and "pow" in ok[3].lower() and leading_zero_bits(plain["id"]) < DIFFICULTY
        print(f"[test 2] {'PASS' if passed else 'FAIL'} (nonce {plain['_nonce']}): relay said {ok}")
        print(f"[test 2] proof: {pow_proof(plain['id'], DIFFICULTY)} (below target, so rejection is correct)")
        results.append(("unmined note rejected with pow reason", passed))

    return results


def main():
    exe = os.path.join("build", "main.exe" if os.name == "nt" else "main")
    if not os.path.exists(exe):
        print(f"Relay binary not found: {exe} — build it first (run .\\nob.exe)")
        sys.exit(1)

    env = dict(os.environ, MIN_POW_DIFFICULTY=str(DIFFICULTY))
    proc = subprocess.Popen([exe, "-port", str(PORT)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)  # let the relay bind
        results = asyncio.run(run_tests())
    finally:
        proc.terminate()

    failed = [name for name, passed in results if not passed]
    print()
    if failed:
        print(f"FAILED: {failed}")
        sys.exit(1)
    print("ALL TESTS PASSED")


if __name__ == "__main__":
    main()

"""Keep one WebSocket connected across module publication/reload.

Run against the Linux hot host on port 7456, then rebuild/publish the module
while the script is in its 20-second wait window.
"""
import asyncio
import argparse
import json
import websockets

FILTER = {"ids": ["ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"]}

async def wait_for_eose(ws, subscription_id):
    while True:
        message = await asyncio.wait_for(ws.recv(), 10)
        parsed = json.loads(message)
        if parsed[0] == "EOSE" and parsed[1] == subscription_id:
            return

async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri", default="ws://127.0.0.1:7456",
                        help="hot relay WebSocket URI")
    args = parser.parse_args()
    async with websockets.connect(args.uri, open_timeout=10) as ws:
        await ws.send(json.dumps(["REQ", "before-reload", FILTER]))
        await wait_for_eose(ws, "before-reload")
        print("READY: trigger a module rebuild now", flush=True)
        await asyncio.sleep(20)
        await ws.send(json.dumps(["REQ", "after-reload", FILTER]))
        await wait_for_eose(ws, "after-reload")
        print("PASS: same WebSocket completed REQ/EOSE before and after reload", flush=True)

asyncio.run(main())

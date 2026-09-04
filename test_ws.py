import asyncio
import websockets

async def main():
    uri = "ws://127.0.0.1:7447"
    print(f"Connecting to {uri} ...")
    try:
        async with websockets.connect(uri, open_timeout=10) as ws:
            print("CONNECTED!")
            # Send a NIP-01 REQ
            await ws.send('["REQ","test",{"kinds":[1]}]')
            print("Sent REQ")
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=5)
                print(f"Received: {msg}")
            except asyncio.TimeoutError:
                print("No response within 5s (but connection is alive)")
    except Exception as e:
        print(f"FAILED: {type(e).__name__}: {e}")

asyncio.run(main())
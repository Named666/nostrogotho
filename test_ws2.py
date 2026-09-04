import asyncio
import websockets

async def recv_all(ws, timeout=2):
    msgs = []
    while True:
        try:
            msgs.append(await asyncio.wait_for(ws.recv(), timeout=timeout))
        except asyncio.TimeoutError:


            break
    return msgs

async def main():
    uri = "ws://127.0.0.1:7447"
    print(f"=== Connecting to {uri} ===")
    async with websockets.connect(uri, open_timeout=10) as ws:

        msgs = await recv_all(ws)
        print(f"[on open] received {len(msgs)} msgs: {msgs}")

        await ws.send('["REQ","test",{"kinds":[1]}]')
        msgs = await recv_all(ws)
        print(f"[after REQ] received {len(msgs)} msgs: {msgs}")

        dummy = '["REQ","_",{"ids":["' + 'a'*64 + '"],"limit":1}]'
        await ws.send(dummy)
        msgs = await recv_all(ws)
        print(f"[after dummy REQ ping] received {len(msgs)} msgs: {msgs}")

        await ws.send('["COUNT","cnt",{"kinds":[1]}]')
        msgs = await recv_all(ws)
        print(f"[after COUNT] received {len(msgs)} msgs: {msgs}")

asyncio.run(main())
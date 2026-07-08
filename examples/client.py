from __future__ import annotations

import asyncio

from _demo_util import (
    client_ssl_context,
    ensure_demo_certificate,
    load_or_create_identity,
)
from securews import connect
from securews.identity import KnownPeers

HOST = "localhost"
PORT = 8765


async def main() -> None:
    ensure_demo_certificate()
    identity = load_or_create_identity("examples/client_identity.hex")
    print(f"[client] identity fingerprint: {identity.fingerprint}")

    known = KnownPeers.load("examples/client_known_servers.json")

    conn = await connect(
        f"wss://{HOST}:{PORT}",
        identity=identity,
        ssl_context=client_ssl_context(),
        known_peers=known,
        peer_label="server",
    )
    known.save("examples/client_known_servers.json")

    print(f"[client] connected; server fingerprint={conn.remote_fingerprint}")
    print(f"[client] SAFETY NUMBER: {conn.safety_number()}")
    print("[client] ^ verify this matches the server's safety number.\n")

    try:
        for text in [b"hello", b"end-to-end encrypted", b"over WSS"]:
            await conn.send(text)
            reply = await conn.recv()
            print(f"[client] sent {text!r} -> echoed {reply!r}")
    finally:
        await conn.close()
        print("[client] closed")


if __name__ == "__main__":
    asyncio.run(main())

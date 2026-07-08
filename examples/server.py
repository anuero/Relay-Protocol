from __future__ import annotations

import asyncio

from _demo_util import (
    ensure_demo_certificate,
    load_or_create_identity,
    server_ssl_context,
)
from securews import serve

HOST = "127.0.0.1"
PORT = 8765


async def echo(conn) -> None:
    print(f"[server] client connected; fingerprint={conn.remote_fingerprint}")
    print(f"[server] SAFETY NUMBER: {conn.safety_number()}")
    async for message in conn:
        print(f"[server] recv: {message!r}")
        await conn.send(message)
    print("[server] client disconnected")


async def main() -> None:
    ensure_demo_certificate()
    identity = load_or_create_identity("examples/server_identity.hex")
    print(f"[server] identity fingerprint: {identity.fingerprint}")

    server = await serve(echo, HOST, PORT, identity=identity, ssl_context=server_ssl_context())
    print(f"[server] listening on wss://localhost:{PORT} (Ctrl+C to stop)")
    await server.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[server] shutting down")

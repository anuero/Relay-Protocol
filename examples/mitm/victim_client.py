from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _demo_util import (
    client_ssl_context,
    ensure_demo_certificate,
    load_or_create_identity,
)
from securews import connect
from securews.errors import IdentityError
from securews.identity import KnownPeers

PIN_STORE = "examples/mitm/victim_pins.json"


async def main(url: str, pin: bool, require: bool) -> None:
    ensure_demo_certificate()
    me = load_or_create_identity("examples/mitm/victim_identity.hex")

    use_store = pin or require
    known = KnownPeers.load(PIN_STORE) if use_store else None
    mode = "FAIL-CLOSED (require pin)" if require else "TOFU pin" if pin else "no authentication"
    print(f"[victim] mode: {mode}")

    try:
        conn = await connect(
            url,
            identity=me,
            ssl_context=client_ssl_context(),
            known_peers=known,
            peer_label="server" if use_store else None,
            require_known_peer=require,
        )
    except IdentityError as exc:
        print(f"[victim] CONNECTION REFUSED: {exc}")
        print("[victim] -> the peer was not authenticated; nothing was sent. OK")
        return

    if use_store and known is not None:
        known.save(PIN_STORE)

    print(f"[victim] connected to {url}")
    print(f"[victim] server fingerprint: {conn.remote_fingerprint}")
    print(f"[victim] SAFETY NUMBER    : {conn.safety_number()}")
    print("[victim] ^ compare with the REAL server's safety number; mismatch == MITM.\n")

    try:
        for text in [b"hi", b"my password is hunter2", b"please transfer $100"]:
            await conn.send(text)
            reply = await conn.recv()
            print(f"[victim] sent {text!r} -> echoed {reply!r}")
    finally:
        await conn.close()
        print("[victim] closed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MITM-lab victim client")
    parser.add_argument("--url", default="wss://localhost:8770", help="target (default: the MITM)")
    parser.add_argument("--pin", action="store_true", help="TOFU key pinning")
    parser.add_argument(
        "--require-pin",
        dest="require",
        action="store_true",
        help="fail closed: refuse any peer that is not already pinned",
    )
    args = parser.parse_args()
    asyncio.run(main(args.url, args.pin, args.require))

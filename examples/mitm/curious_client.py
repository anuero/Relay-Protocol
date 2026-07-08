from __future__ import annotations

import argparse
import asyncio
import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _demo_util import ensure_demo_certificate, load_or_create_identity
from securews import connect


def insecure_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def main(url: str) -> None:
    ensure_demo_certificate()
    me = load_or_create_identity("examples/mitm/curious_client_identity.hex")
    conn = await connect(url, identity=me, ssl_context=insecure_ctx())
    print(f"[curious-client] connected via intermediary to {url}")
    print(f"[curious-client] server fingerprint: {conn.remote_fingerprint}")
    print(f"[curious-client] SAFETY NUMBER    : {conn.safety_number()}")
    try:
        for text in [b"secret message one", b"secret message two"]:
            await conn.send(text)
            reply = await conn.recv()
            print(f"[curious-client] sent {text!r} -> echoed {reply!r}")
    finally:
        await conn.close()
    print("\n[curious-client] Now open mitmweb: the WebSocket frames are ciphertext,")
    print("[curious-client] NOT the plaintext above. TLS was broken; Noise held.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="curious-intermediary demo client")
    parser.add_argument("--url", default="wss://localhost:8080", help="intermediary URL")
    args = parser.parse_args()
    asyncio.run(main(args.url))

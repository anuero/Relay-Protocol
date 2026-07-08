from __future__ import annotations

from enum import IntEnum
from typing import Final

PROTOCOL_NAME: Final[str] = "secure-websocket-sdk"


PROTOCOL_VERSION: Final[int] = 1


NOISE_PROTOCOL_NAME: Final[str] = "Noise_XX_25519_ChaChaPoly_SHA256"


X25519_KEY_LEN: Final[int] = 32


AEAD_TAG_LEN: Final[int] = 16


HANDSHAKE_HASH_LEN: Final[int] = 32


class MessageType(IntEnum):
    HANDSHAKE = 1
    TRANSPORT = 2
    REKEY = 3
    CLOSE = 4


def build_prologue(
    *,
    protocol_name: str = PROTOCOL_NAME,
    version: int = PROTOCOL_VERSION,
    noise_name: str = NOISE_PROTOCOL_NAME,
) -> bytes:
    return f"{protocol_name}/{version};suite={noise_name}".encode("ascii")

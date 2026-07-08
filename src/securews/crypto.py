from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from .protocol import HANDSHAKE_HASH_LEN, X25519_KEY_LEN

_SAFETY_NUMBER_DIGITS = 60
_SAFETY_NUMBER_GROUP = 5
_SAFETY_DOMAIN = b"secure-websocket-sdk/safety-number/v1"
_FINGERPRINT_DOMAIN = b"secure-websocket-sdk/key-fingerprint/v1"


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    private = X25519PrivateKey.generate()
    return x25519_private_to_raw(private), x25519_public_raw(private)


def x25519_private_to_raw(private: X25519PrivateKey) -> bytes:
    return private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def x25519_public_raw(private: X25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def load_x25519_private(raw: bytes) -> X25519PrivateKey:
    if len(raw) != X25519_KEY_LEN:
        raise ValueError(f"X25519 private key must be {X25519_KEY_LEN} bytes, got {len(raw)}")
    return X25519PrivateKey.from_private_bytes(raw)


def public_from_private_raw(raw: bytes) -> bytes:
    return x25519_public_raw(load_x25519_private(raw))


def validate_public_key(raw: bytes) -> None:
    if len(raw) != X25519_KEY_LEN:
        raise ValueError(f"X25519 public key must be {X25519_KEY_LEN} bytes, got {len(raw)}")

    X25519PublicKey.from_public_bytes(raw)


def secure_zero(buffer: bytearray) -> None:
    if not isinstance(buffer, bytearray):
        raise TypeError("secure_zero requires a mutable bytearray")
    for i in range(len(buffer)):
        buffer[i] = 0


class SecretBytes:
    __slots__ = ("_buf",)

    def __init__(self, data: bytes | bytearray | memoryview) -> None:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("SecretBytes requires bytes-like input")
        self._buf = bytearray(data)

    def __bytes__(self) -> bytes:
        return bytes(self._buf)

    def __len__(self) -> int:
        return len(self._buf)

    def wipe(self) -> None:
        secure_zero(self._buf)

    def __enter__(self) -> SecretBytes:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.wipe()

    def __repr__(self) -> str:
        return f"SecretBytes(len={len(self._buf)})"


def constant_time_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def safety_number(handshake_hash: bytes) -> str:
    if len(handshake_hash) != HANDSHAKE_HASH_LEN:
        raise ValueError(
            f"handshake hash must be {HANDSHAKE_HASH_LEN} bytes, got {len(handshake_hash)}"
        )
    digest = hashlib.sha256(_SAFETY_DOMAIN + handshake_hash).digest()
    value = int.from_bytes(digest, "big") % (10**_SAFETY_NUMBER_DIGITS)
    digits = str(value).zfill(_SAFETY_NUMBER_DIGITS)
    groups = [
        digits[i : i + _SAFETY_NUMBER_GROUP]
        for i in range(0, _SAFETY_NUMBER_DIGITS, _SAFETY_NUMBER_GROUP)
    ]
    return " ".join(groups)


def key_fingerprint(public_key: bytes) -> str:
    validate_public_key(public_key)
    digest = hashlib.sha256(_FINGERPRINT_DOMAIN + public_key).digest()[:8]
    return ":".join(f"{b:02x}" for b in digest)

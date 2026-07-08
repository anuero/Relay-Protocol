from __future__ import annotations

import json
from pathlib import Path

from .crypto import (
    SecretBytes,
    constant_time_equal,
    generate_x25519_keypair,
    key_fingerprint,
    public_from_private_raw,
    safety_number,
    validate_public_key,
)
from .errors import IdentityError

__all__ = [
    "StaticIdentity",
    "KnownPeers",
    "safety_number",
    "key_fingerprint",
]


class StaticIdentity:
    __slots__ = ("_private", "_public")

    def __init__(self, private: bytes, public: bytes) -> None:
        self._private = SecretBytes(private)
        self._public = bytes(public)

    @classmethod
    def generate(cls) -> StaticIdentity:
        private, public = generate_x25519_keypair()
        return cls(private=private, public=public)

    @classmethod
    def from_private(cls, private: bytes) -> StaticIdentity:
        return cls(private=private, public=public_from_private_raw(private))

    @property
    def private(self) -> bytes:
        return bytes(self._private)

    @property
    def public(self) -> bytes:
        return self._public

    @property
    def fingerprint(self) -> str:
        return key_fingerprint(self._public)

    def wipe(self) -> None:
        self._private.wipe()

    def __enter__(self) -> StaticIdentity:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.wipe()

    def __repr__(self) -> str:
        return f"StaticIdentity(public_fingerprint={self.fingerprint!r})"


class KnownPeers:
    def __init__(self, pins: dict[str, bytes] | None = None) -> None:
        self._pins: dict[str, bytes] = dict(pins or {})

    def pinned(self, label: str) -> bytes | None:
        return self._pins.get(label)

    def is_known(self, label: str) -> bool:
        return label in self._pins

    def pin(self, label: str, public_key: bytes) -> None:
        validate_public_key(public_key)
        self._pins[label] = bytes(public_key)

    def verify(self, label: str, public_key: bytes) -> None:
        validate_public_key(public_key)
        pinned = self._pins.get(label)
        if pinned is None:
            raise IdentityError(f"no pinned key for peer {label!r}")
        if not constant_time_equal(pinned, public_key):
            raise IdentityError(
                f"static key mismatch for peer {label!r}: "
                f"pinned {key_fingerprint(pinned)}, got {key_fingerprint(public_key)}"
            )

    def trust_or_verify(self, label: str, public_key: bytes) -> bool:
        if self.is_known(label):
            self.verify(label, public_key)
            return False
        self.pin(label, public_key)
        return True

    def to_dict(self) -> dict[str, str]:
        return {label: key.hex() for label, key in self._pins.items()}

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> KnownPeers:
        pins = {label: bytes.fromhex(hexkey) for label, hexkey in data.items()}
        for key in pins.values():
            validate_public_key(key)
        return cls(pins)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), "utf-8")

    @classmethod
    def load(cls, path: str | Path) -> KnownPeers:
        p = Path(path)
        if not p.exists():
            return cls()
        return cls.from_dict(json.loads(p.read_text("utf-8")))

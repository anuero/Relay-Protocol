from __future__ import annotations

import json
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .crypto import constant_time_equal, validate_public_key
from .errors import IdentityError

CERT_VERSION = 1
ED25519_KEY_LEN = 32
ED25519_SIG_LEN = 64


def _canonical(subject: str, public_key: bytes, not_after: int, issuer: bytes) -> bytes:
    return (
        f"securews-cert/v{CERT_VERSION}\n{subject}\n{public_key.hex()}\n{not_after}\n{issuer.hex()}"
    ).encode()


@dataclass(frozen=True, slots=True)
class IdentityCertificate:
    subject: str
    public_key: bytes
    not_after: int
    issuer: bytes
    signature: bytes

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "v": CERT_VERSION,
                "sub": self.subject,
                "key": self.public_key.hex(),
                "exp": self.not_after,
                "iss": self.issuer.hex(),
                "sig": self.signature.hex(),
            },
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> IdentityCertificate:
        try:
            fields = json.loads(data)
            if fields.get("v") != CERT_VERSION:
                raise IdentityError(f"unsupported certificate version: {fields.get('v')!r}")
            cert = cls(
                subject=str(fields["sub"]),
                public_key=bytes.fromhex(fields["key"]),
                not_after=int(fields["exp"]),
                issuer=bytes.fromhex(fields["iss"]),
                signature=bytes.fromhex(fields["sig"]),
            )
        except IdentityError:
            raise
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise IdentityError(f"malformed identity certificate: {exc}") from exc
        return cert

    def verify(
        self,
        trusted_issuer: bytes,
        *,
        now: float | None = None,
        revocation: RevocationList | None = None,
    ) -> None:
        validate_public_key(self.public_key)
        if len(self.issuer) != ED25519_KEY_LEN or not constant_time_equal(
            self.issuer, trusted_issuer
        ):
            raise IdentityError("certificate issued by an untrusted authority")
        if len(self.signature) != ED25519_SIG_LEN:
            raise IdentityError("certificate signature has the wrong length")
        if self.not_after <= 0:
            raise IdentityError("identity certificate has no valid expiry")
        current = time.time() if now is None else now
        if current > self.not_after:
            raise IdentityError("identity certificate has expired")
        message = _canonical(self.subject, self.public_key, self.not_after, self.issuer)
        try:
            Ed25519PublicKey.from_public_bytes(self.issuer).verify(self.signature, message)
        except InvalidSignature as exc:
            raise IdentityError("invalid certificate signature") from exc
        if revocation is not None and revocation.is_revoked(self):
            raise IdentityError("identity certificate has been revoked")


class CertificateAuthority:
    __slots__ = ("_signing_key",)

    def __init__(self, private_key: bytes | None = None) -> None:
        if private_key is None:
            self._signing_key = Ed25519PrivateKey.generate()
        else:
            if len(private_key) != ED25519_KEY_LEN:
                raise ValueError("Ed25519 private key must be 32 bytes")
            self._signing_key = Ed25519PrivateKey.from_private_bytes(private_key)

    @property
    def public_key(self) -> bytes:
        return self._signing_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def private_key(self) -> bytes:
        return self._signing_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    def issue(
        self,
        subject: str,
        public_key: bytes,
        *,
        not_after: int | None = None,
        lifetime: timedelta | None = None,
    ) -> IdentityCertificate:
        validate_public_key(public_key)
        if not_after is not None and lifetime is not None:
            raise ValueError("issue() takes not_after= or lifetime=, not both")
        if lifetime is not None:
            if lifetime <= timedelta(0):
                raise ValueError("lifetime must be positive")
            expiry = int(time.time() + lifetime.total_seconds())
        elif not_after is not None:
            expiry = not_after
        else:
            raise ValueError(
                "issue() requires an expiry: pass not_after= (absolute Unix time) "
                "or lifetime= (a datetime.timedelta)"
            )
        if expiry <= 0:
            raise ValueError("not_after must be a positive Unix timestamp")
        issuer = self.public_key
        message = _canonical(subject, public_key, expiry, issuer)
        signature = self._signing_key.sign(message)
        return IdentityCertificate(
            subject=subject,
            public_key=bytes(public_key),
            not_after=expiry,
            issuer=issuer,
            signature=signature,
        )


class RevocationList:
    def __init__(
        self,
        revoked_keys: Iterable[bytes] = (),
        revoked_subjects: Iterable[str] = (),
    ) -> None:
        self._keys: set[bytes] = set()
        self._subjects: set[str] = set()
        for key in revoked_keys:
            self.revoke_key(key)
        for subject in revoked_subjects:
            self.revoke_subject(subject)

    def revoke_key(self, public_key: bytes) -> None:
        validate_public_key(public_key)
        self._keys.add(bytes(public_key))

    def revoke_subject(self, subject: str) -> None:
        self._subjects.add(str(subject))

    def is_revoked_key(self, public_key: bytes) -> bool:
        return bytes(public_key) in self._keys

    def is_revoked_subject(self, subject: str) -> bool:
        return subject in self._subjects

    def is_revoked(self, cert: IdentityCertificate) -> bool:
        return self.is_revoked_key(cert.public_key) or self.is_revoked_subject(cert.subject)

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "keys": sorted(key.hex() for key in self._keys),
            "subjects": sorted(self._subjects),
        }

    @classmethod
    def from_dict(cls, data: dict[str, list[str]]) -> RevocationList:
        return cls(
            revoked_keys=[bytes.fromhex(h) for h in data.get("keys", [])],
            revoked_subjects=list(data.get("subjects", [])),
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True), "utf-8")

    @classmethod
    def load(cls, path: str | Path) -> RevocationList:
        p = Path(path)
        if not p.exists():
            return cls()
        return cls.from_dict(json.loads(p.read_text("utf-8")))

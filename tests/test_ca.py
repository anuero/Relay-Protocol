from __future__ import annotations

import time
from datetime import timedelta

import pytest

from securews.ca import CertificateAuthority, IdentityCertificate
from securews.errors import IdentityError
from securews.identity import StaticIdentity


def test_issue_requires_an_expiry() -> None:
    ca = CertificateAuthority()
    with pytest.raises(ValueError):
        ca.issue("server", StaticIdentity.generate().public)


def test_issue_rejects_both_expiry_forms() -> None:
    ca = CertificateAuthority()
    with pytest.raises(ValueError):
        ca.issue(
            "server",
            StaticIdentity.generate().public,
            not_after=2_000_000_000,
            lifetime=timedelta(days=1),
        )


def test_issue_with_lifetime_sets_not_after() -> None:
    ca = CertificateAuthority()
    before = time.time()
    cert = ca.issue("server", StaticIdentity.generate().public, lifetime=timedelta(hours=1))
    assert before + 3599 <= cert.not_after <= time.time() + 3601
    cert.verify(ca.public_key)


def test_verify_rejects_certificate_without_expiry() -> None:
    ca = CertificateAuthority()
    cert = ca.issue("server", StaticIdentity.generate().public, not_after=2_000_000_000)
    eternal = IdentityCertificate(
        subject=cert.subject,
        public_key=cert.public_key,
        not_after=0,
        issuer=cert.issuer,
        signature=cert.signature,
    )
    with pytest.raises(IdentityError, match="expiry"):
        eternal.verify(ca.public_key, now=1)


def test_issue_and_verify() -> None:
    ca = CertificateAuthority()
    peer = StaticIdentity.generate()
    cert = ca.issue("server", peer.public, lifetime=timedelta(days=30))
    cert.verify(ca.public_key)


def test_ca_key_roundtrip() -> None:
    ca = CertificateAuthority()
    same = CertificateAuthority(ca.private_key)
    assert same.public_key == ca.public_key


def test_wrong_issuer_rejected() -> None:
    ca = CertificateAuthority()
    other = CertificateAuthority()
    cert = ca.issue("server", StaticIdentity.generate().public, lifetime=timedelta(days=30))
    with pytest.raises(IdentityError):
        cert.verify(other.public_key)


def test_tampered_subject_rejected() -> None:
    ca = CertificateAuthority()
    cert = ca.issue("server", StaticIdentity.generate().public, lifetime=timedelta(days=30))
    forged = IdentityCertificate(
        subject="admin",
        public_key=cert.public_key,
        not_after=cert.not_after,
        issuer=cert.issuer,
        signature=cert.signature,
    )
    with pytest.raises(IdentityError):
        forged.verify(ca.public_key)


def test_tampered_key_rejected() -> None:
    ca = CertificateAuthority()
    cert = ca.issue("server", StaticIdentity.generate().public, lifetime=timedelta(days=30))
    forged = IdentityCertificate(
        subject=cert.subject,
        public_key=StaticIdentity.generate().public,
        not_after=cert.not_after,
        issuer=cert.issuer,
        signature=cert.signature,
    )
    with pytest.raises(IdentityError):
        forged.verify(ca.public_key)


def test_expiry() -> None:
    ca = CertificateAuthority()
    cert = ca.issue("server", StaticIdentity.generate().public, not_after=1000)
    cert.verify(ca.public_key, now=999)
    with pytest.raises(IdentityError):
        cert.verify(ca.public_key, now=1001)


def test_serialization_roundtrip() -> None:
    ca = CertificateAuthority()
    cert = ca.issue("server", StaticIdentity.generate().public, not_after=42)
    restored = IdentityCertificate.from_bytes(cert.to_bytes())
    assert restored == cert
    restored.verify(ca.public_key, now=1)


def test_malformed_certificate_rejected() -> None:
    with pytest.raises(IdentityError):
        IdentityCertificate.from_bytes(b"not json at all")
    with pytest.raises(IdentityError):
        IdentityCertificate.from_bytes(b'{"v": 999}')


def test_ca_rejects_bad_private_key_length() -> None:
    with pytest.raises(ValueError):
        CertificateAuthority(b"\x00" * 16)

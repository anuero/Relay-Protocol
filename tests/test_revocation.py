from __future__ import annotations

from datetime import timedelta

import pytest

from securews.ca import CertificateAuthority, RevocationList
from securews.errors import IdentityError
from securews.identity import StaticIdentity


def test_revocation_by_key() -> None:
    peer = StaticIdentity.generate()
    rl = RevocationList()
    assert not rl.is_revoked_key(peer.public)
    rl.revoke_key(peer.public)
    assert rl.is_revoked_key(peer.public)


def test_revocation_by_subject() -> None:
    rl = RevocationList()
    assert not rl.is_revoked_subject("server")
    rl.revoke_subject("server")
    assert rl.is_revoked_subject("server")


def test_is_revoked_checks_key_and_subject() -> None:
    ca = CertificateAuthority()
    peer = StaticIdentity.generate()
    cert = ca.issue("server", peer.public, lifetime=timedelta(days=30))
    assert not RevocationList().is_revoked(cert)
    assert RevocationList(revoked_keys=[peer.public]).is_revoked(cert)
    assert RevocationList(revoked_subjects=["server"]).is_revoked(cert)


def test_verify_rejects_revoked_certificate() -> None:
    ca = CertificateAuthority()
    peer = StaticIdentity.generate()
    cert = ca.issue("server", peer.public, lifetime=timedelta(days=30))
    rl = RevocationList(revoked_keys=[peer.public])
    with pytest.raises(IdentityError, match="revoked"):
        cert.verify(ca.public_key, revocation=rl)


def test_verify_allows_unrevoked_certificate() -> None:
    ca = CertificateAuthority()
    peer = StaticIdentity.generate()
    cert = ca.issue("server", peer.public, lifetime=timedelta(days=30))
    other = StaticIdentity.generate()
    cert.verify(ca.public_key, revocation=RevocationList(revoked_keys=[other.public]))


def test_revoke_key_validates_length() -> None:
    with pytest.raises(ValueError):
        RevocationList().revoke_key(b"\x00" * 31)


def test_revocation_persistence(tmp_path) -> None:
    peer = StaticIdentity.generate()
    rl = RevocationList(revoked_keys=[peer.public], revoked_subjects=["old"])
    path = tmp_path / "revoked.json"
    rl.save(path)

    loaded = RevocationList.load(path)
    assert loaded.is_revoked_key(peer.public)
    assert loaded.is_revoked_subject("old")


def test_revocation_load_missing_file_is_empty(tmp_path) -> None:
    rl = RevocationList.load(tmp_path / "nope.json")
    assert not rl.is_revoked_subject("anything")

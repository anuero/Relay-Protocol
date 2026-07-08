from __future__ import annotations

import pytest

from securews.crypto import safety_number
from securews.errors import IdentityError
from securews.identity import KnownPeers, StaticIdentity

from .conftest import run_handshake


def test_identity_generate_and_derive() -> None:
    ident = StaticIdentity.generate()
    assert len(ident.private) == 32
    assert len(ident.public) == 32

    assert StaticIdentity.from_private(ident.private).public == ident.public


def test_identity_repr_hides_private_key() -> None:
    ident = StaticIdentity.generate()
    text = repr(ident)
    assert ident.private.hex() not in text
    assert "fingerprint" in text


def test_identity_wipe_zeros_private_key() -> None:
    ident = StaticIdentity.generate()
    public = ident.public
    ident.wipe()
    assert ident.private == bytes(32)
    assert ident.public == public


def test_identity_context_manager_wipes_private_key() -> None:
    with StaticIdentity.generate() as ident:
        assert ident.private != bytes(32)
    assert ident.private == bytes(32)


def test_tofu_pin_then_verify() -> None:
    peers = KnownPeers()
    server = StaticIdentity.generate()

    assert peers.trust_or_verify("server", server.public) is True

    assert peers.trust_or_verify("server", server.public) is False


def test_tofu_mismatch_raises() -> None:
    peers = KnownPeers()
    server = StaticIdentity.generate()
    attacker = StaticIdentity.generate()
    peers.trust_or_verify("server", server.public)
    with pytest.raises(IdentityError):
        peers.trust_or_verify("server", attacker.public)


def test_verify_unknown_peer_raises() -> None:
    with pytest.raises(IdentityError):
        KnownPeers().verify("nobody", StaticIdentity.generate().public)


def test_known_peers_persistence(tmp_path) -> None:
    path = tmp_path / "peers.json"
    server = StaticIdentity.generate()
    peers = KnownPeers()
    peers.pin("server", server.public)
    peers.save(path)

    loaded = KnownPeers.load(path)
    assert loaded.is_known("server")
    loaded.verify("server", server.public)


def test_load_missing_file_is_empty(tmp_path) -> None:
    peers = KnownPeers.load(tmp_path / "does-not-exist.json")
    assert not peers.is_known("anything")


def test_safety_numbers_match_between_honest_peers() -> None:
    client = StaticIdentity.generate()
    server = StaticIdentity.generate()
    cr, sr = run_handshake(client, server)
    assert safety_number(cr.handshake_hash) == safety_number(sr.handshake_hash)


def test_safety_number_format() -> None:
    client = StaticIdentity.generate()
    server = StaticIdentity.generate()
    cr, _ = run_handshake(client, server)
    number = safety_number(cr.handshake_hash)
    groups = number.split(" ")
    assert len(groups) == 12
    assert all(len(g) == 5 and g.isdigit() for g in groups)


def test_different_sessions_have_different_safety_numbers() -> None:
    client = StaticIdentity.generate()
    server = StaticIdentity.generate()
    cr1, _ = run_handshake(client, server)
    cr2, _ = run_handshake(client, server)
    assert safety_number(cr1.handshake_hash) != safety_number(cr2.handshake_hash)


def test_fingerprint_is_stable_and_safe() -> None:
    ident = StaticIdentity.generate()
    fp1 = ident.fingerprint
    fp2 = StaticIdentity.from_private(ident.private).fingerprint
    assert fp1 == fp2

    assert ident.public.hex() not in fp1
    assert fp1.count(":") == 7

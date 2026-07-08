from __future__ import annotations

import pytest

from securews.errors import HandshakeError
from securews.handshake import NoiseXXHandshake
from securews.identity import StaticIdentity
from securews.protocol import build_prologue

from .conftest import run_handshake


def test_successful_mutual_handshake() -> None:
    client = StaticIdentity.generate()
    server = StaticIdentity.generate()
    cr, sr = run_handshake(client, server)

    assert cr.handshake_hash == sr.handshake_hash

    assert cr.remote_static == server.public
    assert sr.remote_static == client.public
    assert cr.is_initiator is True
    assert sr.is_initiator is False


def test_prologue_mismatch_is_rejected() -> None:
    client = StaticIdentity.generate()
    server = StaticIdentity.generate()
    with pytest.raises(HandshakeError):
        run_handshake(
            client,
            server,
            client_prologue=build_prologue(version=1),
            server_prologue=build_prologue(version=2),
        )


def test_tampered_handshake_message_rejected() -> None:
    client = StaticIdentity.generate()
    server = StaticIdentity.generate()
    ini = NoiseXXHandshake(initiator=True, static_private=client.private)
    res = NoiseXXHandshake(initiator=False, static_private=server.private)

    m1 = ini.write_message()
    res.read_message(m1)
    m2 = bytearray(res.write_message())
    m2[-1] ^= 0x01
    with pytest.raises(HandshakeError):
        ini.read_message(bytes(m2))


def test_result_before_completion_raises() -> None:
    client = StaticIdentity.generate()
    ini = NoiseXXHandshake(initiator=True, static_private=client.private)
    with pytest.raises(HandshakeError):
        ini.result()


def test_next_is_write_alternation() -> None:
    client = StaticIdentity.generate()
    server = StaticIdentity.generate()
    ini = NoiseXXHandshake(initiator=True, static_private=client.private)
    res = NoiseXXHandshake(initiator=False, static_private=server.private)

    assert ini.next_is_write() is True
    assert res.next_is_write() is False

from __future__ import annotations

import pytest

from securews.errors import (
    ChannelClosedError,
    DecryptionError,
    ProtocolError,
    ReplayError,
)
from securews.framing import MAX_PLAINTEXT

from .conftest import ChannelPair, make_channel_pair


def test_bidirectional_roundtrip(channel_pair: ChannelPair) -> None:
    assert channel_pair.client_to_server(b"ping") == b"ping"
    assert channel_pair.server_to_client(b"pong") == b"pong"


def test_many_messages_keep_sequence(channel_pair: ChannelPair) -> None:
    for i in range(500):
        assert channel_pair.client_to_server(f"m{i}".encode()) == f"m{i}".encode()


def test_ciphertext_differs_from_plaintext(channel_pair: ChannelPair) -> None:
    frame = channel_pair.client.encrypt(b"topsecret")[0]
    assert b"topsecret" not in frame


def test_tampered_ciphertext_rejected(channel_pair: ChannelPair) -> None:
    frame = bytearray(channel_pair.client.encrypt(b"secret")[0])
    frame[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        channel_pair.server.decrypt(bytes(frame))


def test_tampered_header_seq_rejected(channel_pair: ChannelPair) -> None:

    frame = bytearray(channel_pair.client.encrypt(b"secret")[0])
    frame[2] ^= 0x01
    with pytest.raises((DecryptionError, ReplayError, ProtocolError)):
        channel_pair.server.decrypt(bytes(frame))


def test_truncated_frame_rejected(channel_pair: ChannelPair) -> None:
    frame = channel_pair.client.encrypt(b"secret")[0]
    with pytest.raises(DecryptionError.__mro__[1]):
        channel_pair.server.decrypt(frame[:-1])


def test_replayed_frame_rejected(channel_pair: ChannelPair) -> None:
    frame = channel_pair.client.encrypt(b"once")[0]
    assert channel_pair.server.decrypt(frame) == b"once"
    with pytest.raises(ReplayError):
        channel_pair.server.decrypt(frame)


def test_message_too_large_rejected(channel_pair: ChannelPair) -> None:
    with pytest.raises(ProtocolError):
        channel_pair.client.encrypt(b"\x00" * (MAX_PLAINTEXT + 1))


def test_max_size_message_ok(channel_pair: ChannelPair) -> None:
    payload = b"\x7f" * MAX_PLAINTEXT
    assert channel_pair.client_to_server(payload) == payload


def test_close_marks_both_sides(channel_pair: ChannelPair) -> None:
    close = channel_pair.client.close_frame()
    assert channel_pair.client.is_closed
    with pytest.raises(ChannelClosedError):
        channel_pair.server.decrypt(close)
    assert channel_pair.server.is_closed


def test_send_after_close_rejected(channel_pair: ChannelPair) -> None:
    channel_pair.client.close_frame()
    with pytest.raises(ChannelClosedError):
        channel_pair.client.encrypt(b"too late")


def test_empty_message_roundtrip(channel_pair: ChannelPair) -> None:
    assert channel_pair.client_to_server(b"") == b""


def test_cross_channel_confidentiality() -> None:
    a = make_channel_pair()
    b = make_channel_pair()
    frame = a.client.encrypt(b"for-a-only")[0]
    with pytest.raises(DecryptionError):
        b.server.decrypt(frame)

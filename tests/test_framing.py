from __future__ import annotations

import pytest

from securews.errors import FrameError, ProtocolError
from securews.framing import (
    FRAME_VERSION,
    HEADER_LEN,
    MAX_PAYLOAD,
    Frame,
    MessageType,
    decode,
    encode,
    pack_header,
)


def test_roundtrip_all_message_types() -> None:
    for mtype in MessageType:
        payload = b"x" * 10
        wire = encode(mtype, 42, payload)
        frame = decode(wire)
        assert frame.msg_type is mtype
        assert frame.seq == 42
        assert frame.payload == payload


def test_empty_payload_roundtrip() -> None:
    frame = decode(encode(MessageType.CLOSE, 0, b""))
    assert frame.payload == b""
    assert frame.seq == 0


def test_max_payload_roundtrip() -> None:
    payload = b"\xab" * MAX_PAYLOAD
    frame = decode(encode(MessageType.TRANSPORT, 1, payload))
    assert frame.payload == payload


def test_header_is_deterministic_and_used_as_aad() -> None:

    frame = Frame(MessageType.TRANSPORT, 7, b"hello")
    assert frame.header() == pack_header(MessageType.TRANSPORT, 7, len(b"hello"))


def test_reject_short_buffer() -> None:
    with pytest.raises(FrameError):
        decode(b"\x01\x02\x03")


def test_reject_unknown_version() -> None:
    wire = bytearray(encode(MessageType.TRANSPORT, 0, b"hi"))
    wire[0] = FRAME_VERSION + 7
    with pytest.raises(ProtocolError):
        decode(bytes(wire))


def test_reject_unknown_message_type() -> None:
    wire = bytearray(encode(MessageType.TRANSPORT, 0, b"hi"))
    wire[1] = 200
    with pytest.raises(ProtocolError):
        decode(bytes(wire))


def test_reject_length_greater_than_body() -> None:

    wire = pack_header(MessageType.TRANSPORT, 0, 100) + b"short"
    with pytest.raises(FrameError):
        decode(wire)


def test_reject_trailing_bytes() -> None:
    wire = encode(MessageType.TRANSPORT, 0, b"hi") + b"EXTRA"
    with pytest.raises(FrameError):
        decode(wire)


def test_reject_length_over_max() -> None:

    import struct

    header = struct.pack(">BBQI", FRAME_VERSION, int(MessageType.TRANSPORT), 0, MAX_PAYLOAD + 1)
    with pytest.raises(FrameError):
        decode(header + b"\x00")


def test_pack_header_rejects_bad_fields() -> None:
    with pytest.raises(ProtocolError):
        pack_header(MessageType.TRANSPORT, -1, 0)
    with pytest.raises(FrameError):
        pack_header(MessageType.TRANSPORT, 0, MAX_PAYLOAD + 1)


def test_frame_rejects_oversized_payload() -> None:
    with pytest.raises(FrameError):
        Frame(MessageType.TRANSPORT, 0, b"\x00" * (MAX_PAYLOAD + 1))


def test_header_len_constant() -> None:
    assert HEADER_LEN == 14
    assert len(pack_header(MessageType.TRANSPORT, 0, 0)) == HEADER_LEN

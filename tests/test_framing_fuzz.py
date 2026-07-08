from __future__ import annotations

import contextlib

from hypothesis import given, settings
from hypothesis import strategies as st

from securews.errors import SecureWebSocketError
from securews.framing import MAX_PAYLOAD, MessageType, decode, encode


@settings(max_examples=2000)
@given(st.binary(min_size=0, max_size=256))
def test_decode_never_crashes_on_arbitrary_bytes(data: bytes) -> None:
    with contextlib.suppress(SecureWebSocketError):
        decode(data)


@settings(max_examples=1000)
@given(
    st.sampled_from(list(MessageType)),
    st.integers(min_value=0, max_value=(1 << 64) - 1),
    st.binary(min_size=0, max_size=512),
)
def test_encode_decode_roundtrip(mtype: MessageType, seq: int, payload: bytes) -> None:
    frame = decode(encode(mtype, seq, payload))
    assert frame.msg_type is mtype
    assert frame.seq == seq
    assert frame.payload == payload


@settings(max_examples=500)
@given(st.integers(min_value=MAX_PAYLOAD + 1, max_value=(1 << 32) - 1))
def test_hostile_length_field_is_rejected_without_allocation(bogus_length: int) -> None:
    import struct

    header = struct.pack(">BBQI", 1, int(MessageType.TRANSPORT), 0, bogus_length)

    try:
        decode(header + b"\x00")
        raise AssertionError("expected rejection")
    except SecureWebSocketError:
        pass


@settings(max_examples=500)
@given(st.binary(min_size=14, max_size=64), st.integers(min_value=1, max_value=32))
def test_truncated_frames_rejected(full: bytes, cut: int) -> None:
    truncated = full[: max(0, len(full) - cut)]
    with contextlib.suppress(SecureWebSocketError):
        decode(truncated)

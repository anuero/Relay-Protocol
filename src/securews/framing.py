from __future__ import annotations

import struct
from dataclasses import dataclass

from .errors import FrameError, ProtocolError
from .protocol import AEAD_TAG_LEN, PROTOCOL_VERSION, MessageType

FRAME_VERSION: int = PROTOCOL_VERSION


_HEADER = struct.Struct(">BBQI")
HEADER_LEN: int = _HEADER.size


MAX_PAYLOAD: int = 65535


MAX_PLAINTEXT: int = MAX_PAYLOAD - AEAD_TAG_LEN


MAX_SEQ: int = (1 << 64) - 1


@dataclass(frozen=True, slots=True)
class Frame:
    msg_type: MessageType
    seq: int
    payload: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.msg_type, MessageType):
            raise ProtocolError(f"unknown message type: {self.msg_type!r}")
        if not (0 <= self.seq <= MAX_SEQ):
            raise ProtocolError(f"seq out of range: {self.seq}")
        if len(self.payload) > MAX_PAYLOAD:
            raise FrameError(f"payload too large: {len(self.payload)} > {MAX_PAYLOAD}")

    def header(self) -> bytes:
        return pack_header(self.msg_type, self.seq, len(self.payload))

    def encode(self) -> bytes:
        return self.header() + self.payload


def pack_header(msg_type: MessageType, seq: int, length: int) -> bytes:
    if not isinstance(msg_type, MessageType):
        raise ProtocolError(f"unknown message type: {msg_type!r}")
    if not (0 <= seq <= MAX_SEQ):
        raise ProtocolError(f"seq out of range: {seq}")
    if not (0 <= length <= MAX_PAYLOAD):
        raise FrameError(f"length out of range: {length}")
    return _HEADER.pack(FRAME_VERSION, int(msg_type), seq, length)


def encode(msg_type: MessageType, seq: int, payload: bytes) -> bytes:
    return Frame(msg_type, seq, payload).encode()


def decode(data: bytes) -> Frame:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise FrameError(f"frame must be bytes-like, got {type(data).__name__}")
    data = bytes(data)

    if len(data) < HEADER_LEN:
        raise FrameError(f"frame shorter than header: {len(data)} < {HEADER_LEN}")

    version, raw_type, seq, length = _HEADER.unpack_from(data)

    if version != FRAME_VERSION:
        raise ProtocolError(f"unsupported frame version: {version} (expected {FRAME_VERSION})")

    if length > MAX_PAYLOAD:
        raise FrameError(f"declared length {length} exceeds MAX_PAYLOAD {MAX_PAYLOAD}")

    body = data[HEADER_LEN:]
    if len(body) != length:
        raise FrameError(
            f"length mismatch: header says {length}, {len(body)} bytes present "
            "(truncated or trailing data)"
        )

    try:
        msg_type = MessageType(raw_type)
    except ValueError as exc:
        raise ProtocolError(f"unknown message type byte: {raw_type}") from exc

    return Frame(msg_type=msg_type, seq=seq, payload=body)

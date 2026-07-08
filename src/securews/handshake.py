from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidTag
from noise.connection import Keypair, NoiseConnection
from noise.constants import Empty
from noise.exceptions import (
    NoiseHandshakeError,
    NoiseInvalidMessage,
    NoiseMaxNonceError,
    NoiseValidationError,
    NoiseValueError,
)

from .crypto import load_x25519_private, x25519_private_to_raw, x25519_public_raw
from .errors import HandshakeError
from .protocol import NOISE_PROTOCOL_NAME, build_prologue

_HANDSHAKE_ERRORS = (
    NoiseHandshakeError,
    NoiseInvalidMessage,
    NoiseMaxNonceError,
    NoiseValidationError,
    NoiseValueError,
    InvalidTag,
)


_XX_MESSAGE_COUNT = 3


class CipherStateLike(Protocol):
    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes: ...

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes: ...

    def rekey(self) -> None: ...


@dataclass(slots=True)
class HandshakeResult:
    is_initiator: bool
    handshake_hash: bytes

    remote_static: bytes

    local_static: bytes

    send_cipher: CipherStateLike

    recv_cipher: CipherStateLike


class NoiseXXHandshake:
    __slots__ = ("_conn", "_initiator", "_local_static_pub", "_remote_static", "_step")

    def __init__(
        self, *, initiator: bool, static_private: bytes, prologue: bytes | None = None
    ) -> None:
        self._initiator = initiator
        self._remote_static: bytes | None = None
        self._step = 0

        private = load_x25519_private(static_private)
        self._local_static_pub = x25519_public_raw(private)

        conn = NoiseConnection.from_name(NOISE_PROTOCOL_NAME.encode("ascii"))
        if initiator:
            conn.set_as_initiator()
        else:
            conn.set_as_responder()
        conn.set_keypair_from_private_bytes(Keypair.STATIC, x25519_private_to_raw(private))
        conn.set_prologue(prologue if prologue is not None else build_prologue())
        conn.start_handshake()
        self._conn = conn

    @property
    def is_initiator(self) -> bool:
        return self._initiator

    @property
    def is_complete(self) -> bool:
        return self._conn.handshake_finished

    def next_is_write(self) -> bool:

        return (self._step % 2 == 0) == self._initiator

    def write_message(self, payload: bytes = b"") -> bytes:
        try:
            data = bytes(self._conn.write_message(payload))
        except _HANDSHAKE_ERRORS as exc:
            raise HandshakeError(f"failed to write handshake message: {exc}") from exc
        self._step += 1
        return data

    def read_message(self, data: bytes) -> bytes:

        hs_state = self._conn.noise_protocol.handshake_state
        try:
            payload = bytes(self._conn.read_message(data))
        except _HANDSHAKE_ERRORS as exc:
            raise HandshakeError(f"handshake message rejected: {exc}") from exc
        self._capture_remote_static(hs_state)
        self._step += 1
        return payload

    def _capture_remote_static(self, hs_state: object) -> None:
        rs = getattr(hs_state, "rs", None)
        if rs is not None and not isinstance(rs, Empty):
            self._remote_static = bytes(rs.public_bytes)

    def result(self) -> HandshakeResult:
        if not self.is_complete:
            raise HandshakeError("handshake not finished")
        if self._remote_static is None:
            raise HandshakeError("peer static key was not captured")
        np = self._conn.noise_protocol
        return HandshakeResult(
            is_initiator=self._initiator,
            handshake_hash=bytes(self._conn.get_handshake_hash()),
            remote_static=self._remote_static,
            local_static=self._local_static_pub,
            send_cipher=np.cipher_state_encrypt,
            recv_cipher=np.cipher_state_decrypt,
        )

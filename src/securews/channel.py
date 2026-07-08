from __future__ import annotations

from cryptography.exceptions import InvalidTag

from .crypto import key_fingerprint, safety_number
from .errors import ChannelClosedError, DecryptionError, ProtocolError
from .framing import AEAD_TAG_LEN, MAX_PLAINTEXT, MessageType, decode, pack_header
from .handshake import HandshakeResult
from .logging_policy import logger
from .rekey import RekeyPolicy
from .replay import ReplayWindow


class SecureChannel:
    def __init__(
        self,
        result: HandshakeResult,
        *,
        replay_window: ReplayWindow | None = None,
        rekey_policy: RekeyPolicy | None = None,
    ) -> None:
        self._send_cipher = result.send_cipher
        self._recv_cipher = result.recv_cipher
        self._handshake_hash = result.handshake_hash
        self._remote_static = result.remote_static
        self._local_static = result.local_static
        self._replay = replay_window if replay_window is not None else ReplayWindow()
        self._rekey = rekey_policy if rekey_policy is not None else RekeyPolicy()
        self._send_seq = 0
        self._closed = False

    @property
    def handshake_hash(self) -> bytes:
        return self._handshake_hash

    @property
    def remote_static(self) -> bytes:
        return self._remote_static

    @property
    def local_static(self) -> bytes:
        return self._local_static

    @property
    def remote_fingerprint(self) -> str:
        return key_fingerprint(self._remote_static)

    def safety_number(self) -> str:
        return safety_number(self._handshake_hash)

    @property
    def is_closed(self) -> bool:
        return self._closed

    def encrypt(self, plaintext: bytes) -> list[bytes]:
        self._ensure_open()
        if not isinstance(plaintext, (bytes, bytearray, memoryview)):
            raise ProtocolError("plaintext must be bytes-like")
        plaintext = bytes(plaintext)
        if len(plaintext) > MAX_PLAINTEXT:
            raise ProtocolError(f"message too large: {len(plaintext)} > {MAX_PLAINTEXT}")

        frames: list[bytes] = []
        if self._rekey.due():
            logger.debug("rekey due after %d messages", self._rekey.messages_since_rekey)
            frames.append(self._emit_control(MessageType.REKEY))
            self._send_cipher.rekey()
            self._rekey.reset()

        frames.append(self._emit_transport(plaintext))
        self._rekey.note_message()
        return frames

    def close_frame(self) -> bytes:
        self._ensure_open()
        frame = self._emit_control(MessageType.CLOSE)
        self._closed = True
        return frame

    def _emit_transport(self, plaintext: bytes) -> bytes:
        seq = self._next_send_seq()
        header = pack_header(MessageType.TRANSPORT, seq, len(plaintext) + AEAD_TAG_LEN)
        ciphertext = self._send_cipher.encrypt_with_ad(header, plaintext)
        logger.debug("send TRANSPORT seq=%d len=%d", seq, len(plaintext))
        return header + ciphertext

    def _emit_control(self, msg_type: MessageType) -> bytes:
        seq = self._next_send_seq()
        header = pack_header(msg_type, seq, AEAD_TAG_LEN)
        ciphertext = self._send_cipher.encrypt_with_ad(header, b"")
        logger.debug("send %s seq=%d", msg_type.name, seq)
        return header + ciphertext

    def _next_send_seq(self) -> int:
        seq = self._send_seq
        self._send_seq += 1
        return seq

    def decrypt(self, wire: bytes) -> bytes | None:
        if self._closed:
            raise ChannelClosedError("channel is closed")

        frame = decode(wire)
        self._replay.check(frame.seq)

        header = frame.header()
        cipher_payload = frame.payload
        try:
            plaintext = self._recv_cipher.decrypt_with_ad(header, cipher_payload)
        except InvalidTag as exc:
            raise DecryptionError(
                f"authentication failed for {frame.msg_type.name} seq={frame.seq} "
                "(tampered or truncated)"
            ) from exc

        self._replay.commit(frame.seq)

        if frame.msg_type is MessageType.TRANSPORT:
            logger.debug("recv TRANSPORT seq=%d len=%d", frame.seq, len(plaintext))
            return plaintext
        if frame.msg_type is MessageType.REKEY:
            self._recv_cipher.rekey()
            logger.debug("recv REKEY seq=%d -> ratcheted recv key", frame.seq)
            return None
        if frame.msg_type is MessageType.CLOSE:
            self._closed = True
            logger.debug("recv CLOSE seq=%d -> channel closed", frame.seq)
            raise ChannelClosedError("peer closed the channel")
        raise ProtocolError(f"unexpected message type in transport phase: {frame.msg_type.name}")

    def _ensure_open(self) -> None:
        if self._closed:
            raise ChannelClosedError("channel is closed")

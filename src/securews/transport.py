from __future__ import annotations

import asyncio
import hashlib
import ssl
from collections.abc import Awaitable, Callable
from typing import Any, Final

import websockets
from websockets.exceptions import ConnectionClosed

from .ca import IdentityCertificate, RevocationList
from .channel import SecureChannel
from .crypto import constant_time_equal, key_fingerprint, validate_public_key
from .errors import HandshakeError, IdentityError, ProtocolError, SecureWebSocketError
from .framing import HEADER_LEN, MAX_PAYLOAD, MessageType, decode, encode
from .handshake import HandshakeResult, NoiseXXHandshake
from .identity import KnownPeers, StaticIdentity
from .logging_policy import logger
from .protocol import build_prologue
from .rekey import RekeyPolicy
from .replay import ReplayWindow


class _AnySubject:
    __slots__ = ()

    def __repr__(self) -> str:
        return "ANY_SUBJECT"


ANY_SUBJECT: Final = _AnySubject()


DEFAULT_HANDSHAKE_TIMEOUT: Final = 10.0


_MAX_FRAME_BYTES: Final = HEADER_LEN + MAX_PAYLOAD


def _validate_handshake_timeout(handshake_timeout: float | None) -> None:
    if handshake_timeout is not None and handshake_timeout <= 0:
        raise ValueError("handshake_timeout must be positive, or None to disable it")


async def _drive_handshake_timed(
    hs: NoiseXXHandshake,
    ws: Any,
    local_cert_bytes: bytes,
    handshake_timeout: float | None,
) -> tuple[HandshakeResult, bytes]:
    if handshake_timeout is None:
        return await _drive_handshake(hs, ws, local_cert_bytes)
    try:
        return await asyncio.wait_for(_drive_handshake(hs, ws, local_cert_bytes), handshake_timeout)
    except asyncio.TimeoutError as exc:
        raise HandshakeError(f"handshake did not complete within {handshake_timeout}s") from exc


def _as_bytes(message: str | bytes) -> bytes:
    if isinstance(message, str):
        raise ProtocolError("expected a binary WebSocket message, got text")
    return message


def certificate_fingerprint(der_cert: bytes) -> str:
    return hashlib.sha256(der_cert).hexdigest()


def _peer_cert_der(ws: Any) -> bytes | None:
    transport = getattr(ws, "transport", None)
    if transport is None:
        return None
    ssl_object = transport.get_extra_info("ssl_object")
    if ssl_object is None:
        return None
    return ssl_object.getpeercert(binary_form=True)


async def _drive_handshake(
    hs: NoiseXXHandshake, ws: Any, local_cert_bytes: bytes = b""
) -> tuple[HandshakeResult, bytes]:
    peer_cert = b""
    write_index = 0
    while not hs.is_complete:
        if hs.next_is_write():
            cert_write = (write_index == 1) if hs.is_initiator else (write_index == 0)
            payload = local_cert_bytes if cert_write else b""
            msg = hs.write_message(payload)
            await ws.send(encode(MessageType.HANDSHAKE, write_index, msg))
            write_index += 1
        else:
            frame = decode(_as_bytes(await ws.recv()))
            if frame.msg_type is not MessageType.HANDSHAKE:
                raise ProtocolError(f"expected HANDSHAKE frame, got {frame.msg_type.name}")
            received = hs.read_message(frame.payload)
            if received:
                peer_cert = received
    return hs.result(), peer_cert


def _verify_certificate(
    peer_cert_bytes: bytes,
    *,
    trusted_issuer: bytes | None,
    expected_subject: str | _AnySubject | None,
    remote_static: bytes,
    revocation: RevocationList | None = None,
) -> bool:
    if trusted_issuer is None:
        return False
    if not peer_cert_bytes:
        raise IdentityError("peer presented no identity certificate")
    cert = IdentityCertificate.from_bytes(peer_cert_bytes)
    cert.verify(trusted_issuer, revocation=revocation)
    if not constant_time_equal(cert.public_key, remote_static):
        raise IdentityError("certificate key does not match the peer's Noise static key")
    if isinstance(expected_subject, _AnySubject):
        pass
    elif expected_subject is None:
        raise IdentityError("expected_subject is required when trusted_issuer is set")
    elif cert.subject != expected_subject:
        raise IdentityError(
            f"certificate subject {cert.subject!r} does not match {expected_subject!r}"
        )
    logger.debug("peer certificate verified (subject=%s)", cert.subject)
    return True


class SecureConnection:
    def __init__(self, ws: Any, channel: SecureChannel) -> None:
        self._ws = ws
        self._channel = channel

    @property
    def remote_static(self) -> bytes:
        return self._channel.remote_static

    @property
    def remote_fingerprint(self) -> str:
        return self._channel.remote_fingerprint

    @property
    def handshake_hash(self) -> bytes:
        return self._channel.handshake_hash

    def safety_number(self) -> str:
        return self._channel.safety_number()

    async def send(self, data: bytes) -> None:
        for frame in self._channel.encrypt(data):
            await self._ws.send(frame)

    async def recv(self) -> bytes:
        while True:
            plaintext = self._channel.decrypt(_as_bytes(await self._ws.recv()))
            if plaintext is not None:
                return plaintext

    def __aiter__(self) -> SecureConnection:
        return self

    async def __anext__(self) -> bytes:
        try:
            return await self.recv()
        except (SecureWebSocketError, ConnectionClosed) as exc:
            logger.debug("iteration stopped: %s", type(exc).__name__)
            raise StopAsyncIteration from exc

    async def close(self) -> None:
        try:
            if not self._channel.is_closed:
                await self._ws.send(self._channel.close_frame())
        except (SecureWebSocketError, ConnectionClosed):
            pass
        await self._ws.close()


def _authenticate_peer(
    remote_static: bytes,
    *,
    known_peers: KnownPeers | None,
    peer_label: str | None,
    expected_peer_key: bytes | None,
    require: bool,
) -> bool:
    verified = False

    if expected_peer_key is not None:
        validate_public_key(expected_peer_key)
        if not constant_time_equal(remote_static, expected_peer_key):
            raise IdentityError(
                f"peer static key {key_fingerprint(remote_static)} does not match the "
                f"expected key {key_fingerprint(expected_peer_key)}"
            )
        verified = True
        logger.debug("peer verified against expected_peer_key")

    if known_peers is not None and peer_label is not None:
        if known_peers.is_known(peer_label):
            known_peers.verify(peer_label, remote_static)
            verified = True
            logger.debug("peer %s verified against existing pin", peer_label)
        elif not require:
            known_peers.pin(peer_label, remote_static)
            logger.debug("peer %s trusted on first use (pinned)", peer_label)

    return verified


def _enforce_authentication(
    *,
    require: bool,
    verified_by_key_or_pin: bool,
    verified_by_certificate: bool,
) -> None:
    if require and not (verified_by_key_or_pin or verified_by_certificate):
        raise IdentityError(
            "refusing unauthenticated connection: provide trusted_issuer, "
            "expected_peer_key, or a pre-pinned known_peers/peer_label"
        )


def _require_subject_with_issuer(
    trusted_issuer: bytes | None, expected_subject: str | _AnySubject | None
) -> None:
    if trusted_issuer is not None and expected_subject is None:
        raise ValueError(
            "trusted_issuer requires expected_subject (or ANY_SUBJECT to accept "
            "any subject signed by that issuer)"
        )


def _enforce_not_revoked(remote_static: bytes, revocation: RevocationList | None) -> None:
    if revocation is not None and revocation.is_revoked_key(remote_static):
        raise IdentityError(f"peer static key {key_fingerprint(remote_static)} has been revoked")


async def connect(
    uri: str,
    *,
    identity: StaticIdentity | None = None,
    ssl_context: ssl.SSLContext | None = None,
    cert_pin: str | None = None,
    known_peers: KnownPeers | None = None,
    peer_label: str | None = None,
    expected_peer_key: bytes | None = None,
    require_known_peer: bool = False,
    local_certificate: IdentityCertificate | None = None,
    trusted_issuer: bytes | None = None,
    expected_subject: str | _AnySubject | None = None,
    revocation: RevocationList | None = None,
    secure: bool = False,
    handshake_timeout: float | None = DEFAULT_HANDSHAKE_TIMEOUT,
    replay_window: ReplayWindow | None = None,
    rekey_policy: RekeyPolicy | None = None,
    **connect_kwargs: Any,
) -> SecureConnection:
    require = require_known_peer or secure
    _validate_handshake_timeout(handshake_timeout)
    _require_subject_with_issuer(trusted_issuer, expected_subject)
    has_authenticator = (
        trusted_issuer is not None
        or expected_peer_key is not None
        or (known_peers is not None and peer_label is not None)
    )
    if secure:
        if not has_authenticator:
            raise ValueError(
                "secure=True requires an authenticator: trusted_issuer, "
                "expected_peer_key, or known_peers + peer_label"
            )
        if ssl_context is None:
            ssl_context = ssl.create_default_context()
        elif ssl_context.verify_mode == ssl.CERT_NONE:
            raise ValueError("secure=True requires a TLS context that verifies the server")

    identity = identity or StaticIdentity.generate()
    local_cert_bytes = local_certificate.to_bytes() if local_certificate is not None else b""
    connect_kwargs.setdefault("max_size", _MAX_FRAME_BYTES)
    ws = await websockets.connect(uri, ssl=ssl_context, **connect_kwargs)
    try:
        if cert_pin is not None:
            der = _peer_cert_der(ws)
            if der is None:
                raise IdentityError("cert pinning requested but connection is not TLS")
            got = certificate_fingerprint(der)
            if got != cert_pin:
                raise IdentityError(f"certificate pin mismatch: expected {cert_pin}, got {got}")

        hs = NoiseXXHandshake(
            initiator=True, static_private=identity.private, prologue=build_prologue()
        )
        result, peer_cert = await _drive_handshake_timed(
            hs, ws, local_cert_bytes, handshake_timeout
        )
        _enforce_not_revoked(result.remote_static, revocation)
        verified_pin = _authenticate_peer(
            result.remote_static,
            known_peers=known_peers,
            peer_label=peer_label,
            expected_peer_key=expected_peer_key,
            require=require,
        )
        verified_cert = _verify_certificate(
            peer_cert,
            trusted_issuer=trusted_issuer,
            expected_subject=expected_subject,
            remote_static=result.remote_static,
            revocation=revocation,
        )
        _enforce_authentication(
            require=require,
            verified_by_key_or_pin=verified_pin,
            verified_by_certificate=verified_cert,
        )
        channel = SecureChannel(result, replay_window=replay_window, rekey_policy=rekey_policy)
        return SecureConnection(ws, channel)
    except BaseException:
        await ws.close()
        raise


ConnectionHandler = Callable[[SecureConnection], Awaitable[None]]


async def serve(
    handler: ConnectionHandler,
    host: str,
    port: int,
    *,
    identity: StaticIdentity,
    ssl_context: ssl.SSLContext,
    known_peers: KnownPeers | None = None,
    peer_label: str | None = None,
    expected_peer_key: bytes | None = None,
    require_known_peer: bool = False,
    local_certificate: IdentityCertificate | None = None,
    trusted_issuer: bytes | None = None,
    expected_subject: str | _AnySubject | None = None,
    revocation: RevocationList | None = None,
    secure: bool = False,
    handshake_timeout: float | None = DEFAULT_HANDSHAKE_TIMEOUT,
    **serve_kwargs: Any,
) -> object:
    require = require_known_peer or secure
    _validate_handshake_timeout(handshake_timeout)
    _require_subject_with_issuer(trusted_issuer, expected_subject)
    local_cert_bytes = local_certificate.to_bytes() if local_certificate is not None else b""
    serve_kwargs.setdefault("max_size", _MAX_FRAME_BYTES)

    async def _on_connection(ws: Any) -> None:
        peer = getattr(ws, "remote_address", "?")
        try:
            hs = NoiseXXHandshake(
                initiator=False, static_private=identity.private, prologue=build_prologue()
            )
            result, peer_cert = await _drive_handshake_timed(
                hs, ws, local_cert_bytes, handshake_timeout
            )
            _enforce_not_revoked(result.remote_static, revocation)
            verified_pin = _authenticate_peer(
                result.remote_static,
                known_peers=known_peers,
                peer_label=peer_label,
                expected_peer_key=expected_peer_key,
                require=require,
            )
            verified_cert = _verify_certificate(
                peer_cert,
                trusted_issuer=trusted_issuer,
                expected_subject=expected_subject,
                remote_static=result.remote_static,
                revocation=revocation,
            )
            _enforce_authentication(
                require=require,
                verified_by_key_or_pin=verified_pin,
                verified_by_certificate=verified_cert,
            )
            channel = SecureChannel(result)
            await handler(SecureConnection(ws, channel))
        except ConnectionClosed:
            logger.debug("client %s disconnected", peer)
        except SecureWebSocketError as exc:
            logger.warning("rejecting client %s: %s", peer, type(exc).__name__)
            await ws.close(code=1008, reason="handshake failed")

    return await websockets.serve(_on_connection, host, port, ssl=ssl_context, **serve_kwargs)

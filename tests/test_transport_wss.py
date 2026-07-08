from __future__ import annotations

import asyncio
import datetime
import ipaddress
import ssl
from contextlib import asynccontextmanager

import pytest
import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from websockets.exceptions import ConnectionClosed

from securews import ANY_SUBJECT, connect, serve
from securews.ca import CertificateAuthority, RevocationList
from securews.errors import HandshakeError, IdentityError
from securews.framing import HEADER_LEN, MAX_PAYLOAD
from securews.identity import KnownPeers, StaticIdentity, key_fingerprint
from securews.transport import certificate_fingerprint


@pytest.fixture(scope="module")
def tls(tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    d = tmp_path_factory.mktemp("tls")
    certfile = d / "cert.pem"
    keyfile = d / "key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return {
        "certfile": str(certfile),
        "keyfile": str(keyfile),
        "cert_pin": certificate_fingerprint(cert.public_bytes(serialization.Encoding.DER)),
    }


def _server_ctx(tls: dict[str, object]) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tls["certfile"], tls["keyfile"])
    return ctx


def _client_ctx_trusting(tls: dict[str, object]) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(tls["certfile"])
    ctx.check_hostname = True
    return ctx


def _client_ctx_no_verify() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


@asynccontextmanager
async def running_server(tls, server_identity, handler, **serve_kwargs):
    server = await serve(
        handler,
        "127.0.0.1",
        0,
        identity=server_identity,
        ssl_context=_server_ctx(tls),
        **serve_kwargs,
    )
    try:
        port = server.sockets[0].getsockname()[1]
        yield port
    finally:
        server.close()
        await server.wait_closed()


async def _echo(conn) -> None:
    async for message in conn:
        await conn.send(message)


async def test_wss_echo_roundtrip(tls) -> None:
    server_id = StaticIdentity.generate()
    client_id = StaticIdentity.generate()

    async with running_server(tls, server_id, _echo) as port:
        conn = await connect(
            f"wss://localhost:{port}",
            identity=client_id,
            ssl_context=_client_ctx_trusting(tls),
        )
        try:
            await conn.send(b"hello over wss")
            assert await conn.recv() == b"hello over wss"
            await conn.send(b"second message")
            assert await conn.recv() == b"second message"

            assert conn.remote_fingerprint == key_fingerprint(server_id.public)

            assert len(conn.safety_number().split(" ")) == 12
        finally:
            await conn.close()


async def test_wss_cert_pinning_success(tls) -> None:
    server_id = StaticIdentity.generate()
    async with running_server(tls, server_id, _echo) as port:
        conn = await connect(
            f"wss://localhost:{port}",
            identity=StaticIdentity.generate(),
            ssl_context=_client_ctx_no_verify(),
            cert_pin=tls["cert_pin"],
        )
        try:
            await conn.send(b"pinned")
            assert await conn.recv() == b"pinned"
        finally:
            await conn.close()


async def test_wss_cert_pin_mismatch_rejected(tls) -> None:
    server_id = StaticIdentity.generate()
    async with running_server(tls, server_id, _echo) as port:
        with pytest.raises(IdentityError):
            await connect(
                f"wss://localhost:{port}",
                identity=StaticIdentity.generate(),
                ssl_context=_client_ctx_no_verify(),
                cert_pin="00" * 32,
            )


async def test_wss_tofu_pin_then_mismatch_rejected(tls) -> None:
    server_id = StaticIdentity.generate()
    attacker_id = StaticIdentity.generate()

    async with running_server(tls, server_id, _echo) as port:
        peers = KnownPeers()
        peers.pin("server", attacker_id.public)
        with pytest.raises(IdentityError):
            await connect(
                f"wss://localhost:{port}",
                identity=StaticIdentity.generate(),
                ssl_context=_client_ctx_trusting(tls),
                known_peers=peers,
                peer_label="server",
            )


async def test_wss_require_known_peer_refuses_when_nothing_provided(tls) -> None:
    server_id = StaticIdentity.generate()
    async with running_server(tls, server_id, _echo) as port:
        with pytest.raises(IdentityError):
            await connect(
                f"wss://localhost:{port}",
                identity=StaticIdentity.generate(),
                ssl_context=_client_ctx_trusting(tls),
                require_known_peer=True,
            )


async def test_wss_require_known_peer_disallows_tofu_first_use(tls) -> None:
    server_id = StaticIdentity.generate()
    async with running_server(tls, server_id, _echo) as port:
        peers = KnownPeers()
        with pytest.raises(IdentityError):
            await connect(
                f"wss://localhost:{port}",
                identity=StaticIdentity.generate(),
                ssl_context=_client_ctx_trusting(tls),
                known_peers=peers,
                peer_label="server",
                require_known_peer=True,
            )
        assert not peers.is_known("server")


async def test_wss_expected_peer_key_success(tls) -> None:
    server_id = StaticIdentity.generate()
    async with running_server(tls, server_id, _echo) as port:
        conn = await connect(
            f"wss://localhost:{port}",
            identity=StaticIdentity.generate(),
            ssl_context=_client_ctx_trusting(tls),
            expected_peer_key=server_id.public,
            require_known_peer=True,
        )
        try:
            await conn.send(b"authenticated")
            assert await conn.recv() == b"authenticated"
        finally:
            await conn.close()


async def test_wss_expected_peer_key_mismatch_refused(tls) -> None:
    server_id = StaticIdentity.generate()
    wrong_key = StaticIdentity.generate().public
    async with running_server(tls, server_id, _echo) as port:
        with pytest.raises(IdentityError):
            await connect(
                f"wss://localhost:{port}",
                identity=StaticIdentity.generate(),
                ssl_context=_client_ctx_trusting(tls),
                expected_peer_key=wrong_key,
                require_known_peer=True,
            )


async def test_wss_require_known_peer_allows_prepinned(tls) -> None:
    server_id = StaticIdentity.generate()
    async with running_server(tls, server_id, _echo) as port:
        peers = KnownPeers()
        peers.pin("server", server_id.public)
        conn = await connect(
            f"wss://localhost:{port}",
            identity=StaticIdentity.generate(),
            ssl_context=_client_ctx_trusting(tls),
            known_peers=peers,
            peer_label="server",
            require_known_peer=True,
        )
        try:
            await conn.send(b"ok")
            assert await conn.recv() == b"ok"
        finally:
            await conn.close()


async def test_wss_minimal_client_without_identity(tls) -> None:
    server_id = StaticIdentity.generate()
    async with running_server(tls, server_id, _echo) as port:
        conn = await connect(f"wss://localhost:{port}", ssl_context=_client_ctx_trusting(tls))
        try:
            await conn.send(b"minimal")
            assert await conn.recv() == b"minimal"
        finally:
            await conn.close()


async def test_wss_ca_verified_success(tls) -> None:
    ca = CertificateAuthority()
    server_id = StaticIdentity.generate()
    cert = ca.issue("server", server_id.public, lifetime=datetime.timedelta(days=30))
    async with running_server(tls, server_id, _echo, local_certificate=cert) as port:
        conn = await connect(
            f"wss://localhost:{port}",
            ssl_context=_client_ctx_trusting(tls),
            trusted_issuer=ca.public_key,
            expected_subject="server",
        )
        try:
            await conn.send(b"ca-authenticated")
            assert await conn.recv() == b"ca-authenticated"
        finally:
            await conn.close()


async def test_wss_ca_missing_cert_refused(tls) -> None:
    ca = CertificateAuthority()
    server_id = StaticIdentity.generate()
    async with running_server(tls, server_id, _echo) as port:
        with pytest.raises(IdentityError):
            await connect(
                f"wss://localhost:{port}",
                ssl_context=_client_ctx_trusting(tls),
                trusted_issuer=ca.public_key,
                expected_subject="server",
            )


async def test_wss_ca_wrong_issuer_refused(tls) -> None:
    ca = CertificateAuthority()
    attacker_ca = CertificateAuthority()
    server_id = StaticIdentity.generate()
    cert = ca.issue("server", server_id.public, lifetime=datetime.timedelta(days=30))
    async with running_server(tls, server_id, _echo, local_certificate=cert) as port:
        with pytest.raises(IdentityError):
            await connect(
                f"wss://localhost:{port}",
                ssl_context=_client_ctx_trusting(tls),
                trusted_issuer=attacker_ca.public_key,
                expected_subject="server",
            )


async def test_wss_ca_key_mismatch_refused(tls) -> None:
    ca = CertificateAuthority()
    server_id = StaticIdentity.generate()
    other_key = StaticIdentity.generate().public
    cert = ca.issue("server", other_key, lifetime=datetime.timedelta(days=30))
    async with running_server(tls, server_id, _echo, local_certificate=cert) as port:
        with pytest.raises(IdentityError):
            await connect(
                f"wss://localhost:{port}",
                ssl_context=_client_ctx_trusting(tls),
                trusted_issuer=ca.public_key,
                expected_subject="server",
            )


async def test_wss_trusted_issuer_requires_expected_subject(tls) -> None:
    ca = CertificateAuthority()
    with pytest.raises(ValueError):
        await connect(
            "wss://localhost:1/ws",
            ssl_context=_client_ctx_trusting(tls),
            trusted_issuer=ca.public_key,
        )


async def test_wss_ca_any_subject_accepts_signed_peer(tls) -> None:
    ca = CertificateAuthority()
    server_id = StaticIdentity.generate()
    cert = ca.issue("some-service", server_id.public, lifetime=datetime.timedelta(days=30))
    async with running_server(tls, server_id, _echo, local_certificate=cert) as port:
        conn = await connect(
            f"wss://localhost:{port}",
            ssl_context=_client_ctx_trusting(tls),
            trusted_issuer=ca.public_key,
            expected_subject=ANY_SUBJECT,
        )
        try:
            await conn.send(b"any")
            assert await conn.recv() == b"any"
        finally:
            await conn.close()


async def test_wss_revoked_key_refused(tls) -> None:
    server_id = StaticIdentity.generate()
    revocation = RevocationList(revoked_keys=[server_id.public])
    async with running_server(tls, server_id, _echo) as port:
        with pytest.raises(IdentityError):
            await connect(
                f"wss://localhost:{port}",
                ssl_context=_client_ctx_trusting(tls),
                expected_peer_key=server_id.public,
                revocation=revocation,
            )


async def test_wss_revoked_subject_refused(tls) -> None:
    ca = CertificateAuthority()
    server_id = StaticIdentity.generate()
    cert = ca.issue("server", server_id.public, lifetime=datetime.timedelta(days=30))
    revocation = RevocationList(revoked_subjects=["server"])
    async with running_server(tls, server_id, _echo, local_certificate=cert) as port:
        with pytest.raises(IdentityError):
            await connect(
                f"wss://localhost:{port}",
                ssl_context=_client_ctx_trusting(tls),
                trusted_issuer=ca.public_key,
                expected_subject="server",
                revocation=revocation,
            )


async def test_wss_unrevoked_peer_allowed(tls) -> None:
    server_id = StaticIdentity.generate()
    other = StaticIdentity.generate()
    revocation = RevocationList(revoked_keys=[other.public])
    async with running_server(tls, server_id, _echo) as port:
        conn = await connect(
            f"wss://localhost:{port}",
            ssl_context=_client_ctx_trusting(tls),
            expected_peer_key=server_id.public,
            revocation=revocation,
        )
        try:
            await conn.send(b"ok")
            assert await conn.recv() == b"ok"
        finally:
            await conn.close()


async def test_wss_ca_wrong_subject_refused(tls) -> None:
    ca = CertificateAuthority()
    server_id = StaticIdentity.generate()
    cert = ca.issue("server", server_id.public, lifetime=datetime.timedelta(days=30))
    async with running_server(tls, server_id, _echo, local_certificate=cert) as port:
        with pytest.raises(IdentityError):
            await connect(
                f"wss://localhost:{port}",
                ssl_context=_client_ctx_trusting(tls),
                trusted_issuer=ca.public_key,
                expected_subject="api",
            )


async def test_wss_secure_with_ca_success(tls) -> None:
    ca = CertificateAuthority()
    server_id = StaticIdentity.generate()
    cert = ca.issue("server", server_id.public, lifetime=datetime.timedelta(days=30))
    async with running_server(tls, server_id, _echo, local_certificate=cert) as port:
        conn = await connect(
            f"wss://localhost:{port}",
            ssl_context=_client_ctx_trusting(tls),
            secure=True,
            trusted_issuer=ca.public_key,
            expected_subject="server",
        )
        try:
            await conn.send(b"max protection")
            assert await conn.recv() == b"max protection"
        finally:
            await conn.close()


async def test_wss_secure_with_expected_key_success(tls) -> None:
    server_id = StaticIdentity.generate()
    async with running_server(tls, server_id, _echo) as port:
        conn = await connect(
            f"wss://localhost:{port}",
            ssl_context=_client_ctx_trusting(tls),
            secure=True,
            expected_peer_key=server_id.public,
        )
        try:
            await conn.send(b"ok")
            assert await conn.recv() == b"ok"
        finally:
            await conn.close()


async def test_handshake_timeout_must_be_positive() -> None:
    with pytest.raises(ValueError):
        await connect("wss://localhost:1/ws", handshake_timeout=0)


async def test_wss_client_handshake_timeout(tls) -> None:
    async def stall(ws) -> None:
        await asyncio.sleep(10)

    server = await websockets.serve(stall, "127.0.0.1", 0, ssl=_server_ctx(tls))
    port = server.sockets[0].getsockname()[1]
    try:
        with pytest.raises(HandshakeError):
            await connect(
                f"wss://localhost:{port}",
                ssl_context=_client_ctx_trusting(tls),
                handshake_timeout=0.3,
            )
    finally:
        server.close()
        await server.wait_closed()


async def test_wss_server_drops_stalling_handshake(tls) -> None:
    server_id = StaticIdentity.generate()
    async with running_server(tls, server_id, _echo, handshake_timeout=0.3) as port:
        raw = await websockets.connect(f"wss://localhost:{port}", ssl=_client_ctx_trusting(tls))
        try:
            with pytest.raises(ConnectionClosed):
                await asyncio.wait_for(raw.recv(), timeout=5)
        finally:
            await raw.close()


async def test_wss_server_rejects_oversize_frame(tls) -> None:
    server_id = StaticIdentity.generate()
    async with running_server(tls, server_id, _echo) as port:
        raw = await websockets.connect(
            f"wss://localhost:{port}", ssl=_client_ctx_trusting(tls), max_size=None
        )
        try:
            await raw.send(b"\x00" * (HEADER_LEN + MAX_PAYLOAD + 1))
            with pytest.raises(ConnectionClosed) as excinfo:
                await asyncio.wait_for(raw.recv(), timeout=5)
            assert excinfo.value.rcvd.code == 1009
        finally:
            await raw.close()


async def test_wss_secure_without_authenticator_raises() -> None:
    with pytest.raises(ValueError):
        await connect("wss://localhost:1/ws", secure=True)


async def test_wss_secure_rejects_insecure_tls_context() -> None:
    with pytest.raises(ValueError):
        await connect(
            "wss://localhost:1/ws",
            secure=True,
            trusted_issuer=CertificateAuthority().public_key,
            expected_subject="server",
            ssl_context=_client_ctx_no_verify(),
        )

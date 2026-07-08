from __future__ import annotations

import datetime
import ipaddress
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from securews.identity import StaticIdentity
from securews.transport import certificate_fingerprint

HERE = Path(__file__).resolve().parent
CERT_DIR = HERE / "certs"
CERTFILE = CERT_DIR / "cert.pem"
KEYFILE = CERT_DIR / "key.pem"


def load_or_create_identity(path: str | Path) -> StaticIdentity:
    p = Path(path)
    if p.exists():
        return StaticIdentity.from_private(bytes.fromhex(p.read_text("utf-8").strip()))
    identity = StaticIdentity.generate()
    p.write_text(identity.private.hex(), "utf-8")
    return identity


def ensure_demo_certificate() -> str:
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    if not (CERTFILE.exists() and KEYFILE.exists()):
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
                    [
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        CERTFILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        KEYFILE.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    der = x509.load_pem_x509_certificate(CERTFILE.read_bytes()).public_bytes(
        serialization.Encoding.DER
    )
    return certificate_fingerprint(der)


def server_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERTFILE), str(KEYFILE))
    return ctx


def client_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(str(CERTFILE))
    ctx.check_hostname = True
    return ctx

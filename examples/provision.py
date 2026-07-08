from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _demo_util import ensure_demo_certificate
from securews import CertificateAuthority, StaticIdentity

OUT = Path(__file__).resolve().parent / "provision_out"
SUBJECT = "server"
CERT_LIFETIME = timedelta(days=365)


def main() -> None:
    OUT.mkdir(exist_ok=True)

    ca = CertificateAuthority()
    (OUT / "ca_private.key").write_text(ca.private_key.hex(), "utf-8")
    ca_pub_hex = ca.public_key.hex()

    server = StaticIdentity.generate()
    (OUT / "server_identity.hex").write_text(server.private.hex(), "utf-8")

    cert = ca.issue(SUBJECT, server.public, lifetime=CERT_LIFETIME)
    (OUT / "server.cert").write_bytes(cert.to_bytes())

    tls_fingerprint = ensure_demo_certificate()

    line = "=" * 72
    print(line)
    print(" PROVISIONED VALUES  --  put the PUBLIC ones into your client")
    print(line)

    print("\n[ca_public_key]  32 bytes, ship this WITH the client (trust anchor):")
    print(f'    trusted_issuer = bytes.fromhex("{ca_pub_hex}")')

    print("\n[expected_subject]  the label you signed the certificate with:")
    print(f'    expected_subject = "{SUBJECT}"')

    print("\n[server_cert_fingerprint]  SHA-256 of the server's TLS certificate:")
    print(f'    cert_pin = "{tls_fingerprint}"')
    print("    get it from a live server with:")
    print("      openssl s_client -connect HOST:443 </dev/null 2>/dev/null \\")
    print("        | openssl x509 -outform der | openssl dgst -sha256")
    print("    or from a PEM in Python:")
    print("      from cryptography import x509")
    print("      from cryptography.hazmat.primitives.serialization import Encoding")
    print("      from securews import certificate_fingerprint")
    print(
        "      der = x509.load_pem_x509_certificate(open('tls.pem','rb').read())"
        ".public_bytes(Encoding.DER)"
    )
    print("      cert_pin = certificate_fingerprint(der)")

    print("\n[strict_tls_ctx]  build it from the ssl module:")
    print("    import ssl")
    print("    # public server with a real (CA-issued) TLS cert -> verifies system CAs:")
    print("    strict_tls_ctx = ssl.create_default_context()")
    print("    # self-signed / private TLS cert -> trust that cert file:")
    print('    strict_tls_ctx = ssl.create_default_context(cafile="server-tls.pem")')

    print("\n" + line)
    print(" CLIENT  --  maximum protection in one call")
    print(line)
    print("    from securews import connect")
    print("    conn = await connect(uri,")
    print("        ssl_context=strict_tls_ctx,")
    print(f'        trusted_issuer=bytes.fromhex("{ca_pub_hex}"),')
    print(f'        expected_subject="{SUBJECT}",')
    print("        secure=True)")

    print("\n" + line)
    print(" SERVER  --  present the signed identity certificate")
    print(line)
    print("    from securews import serve, IdentityCertificate")
    print("    from securews.identity import StaticIdentity")
    print(
        "    identity = StaticIdentity.from_private(bytes.fromhex(open("
        "'server_identity.hex').read()))"
    )
    print("    cert = IdentityCertificate.from_bytes(open('server.cert','rb').read())")
    print("    await serve(handler, host, port, identity=identity,")
    print("                ssl_context=server_tls_ctx, local_certificate=cert)")

    print("\n" + line)
    print(f" secrets written to {OUT} (gitignored):")
    print("   ca_private.key       -> KEEP SECRET, signs new identities")
    print("   server_identity.hex  -> KEEP SECRET, the server's Noise key")
    print("   server.cert          -> public, the server presents it")
    print(line)


if __name__ == "__main__":
    main()

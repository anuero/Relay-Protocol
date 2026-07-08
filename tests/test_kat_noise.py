from __future__ import annotations

from noise.connection import Keypair, NoiseConnection

from securews.protocol import NOISE_PROTOCOL_NAME, build_prologue

CLIENT_STATIC = bytes(range(0, 32))
SERVER_STATIC = bytes(range(32, 64))
CLIENT_EPHEMERAL = bytes((0xA0 + (i % 16)) for i in range(32))
SERVER_EPHEMERAL = bytes((0xB0 + (i % 16)) for i in range(32))

TRANSPORT_AD = bytes.fromhex("0102030405060708090a0b0c0d0e")
TRANSPORT_PLAINTEXT = b"known-answer transport payload"


def _fixed_connection(role: str, static: bytes, ephemeral: bytes) -> NoiseConnection:
    conn = NoiseConnection.from_name(NOISE_PROTOCOL_NAME.encode("ascii"))
    getattr(conn, f"set_as_{role}")()
    conn.set_keypair_from_private_bytes(Keypair.STATIC, static)
    conn.set_keypair_from_private_bytes(Keypair.EPHEMERAL, ephemeral)
    conn.set_prologue(build_prologue())
    conn.start_handshake()
    return conn


def _run_fixed_handshake() -> dict[str, bytes]:
    ini = _fixed_connection("initiator", CLIENT_STATIC, CLIENT_EPHEMERAL)
    res = _fixed_connection("responder", SERVER_STATIC, SERVER_EPHEMERAL)

    m1 = bytes(ini.write_message())
    res.read_message(m1)
    m2 = bytes(res.write_message())
    ini.read_message(m2)
    m3 = bytes(ini.write_message())
    res.read_message(m3)

    assert ini.get_handshake_hash() == res.get_handshake_hash()

    ct = ini.noise_protocol.cipher_state_encrypt.encrypt_with_ad(TRANSPORT_AD, TRANSPORT_PLAINTEXT)
    pt = res.noise_protocol.cipher_state_decrypt.decrypt_with_ad(TRANSPORT_AD, ct)
    assert pt == TRANSPORT_PLAINTEXT

    return {
        "m1": m1,
        "m2": m2,
        "m3": m3,
        "hh": bytes(ini.get_handshake_hash()),
        "ct": bytes(ct),
    }


def test_fixed_key_handshake_is_deterministic() -> None:
    a = _run_fixed_handshake()
    b = _run_fixed_handshake()
    assert a == b, "handshake transcript must be reproducible for fixed keys"


def test_transcript_shapes() -> None:
    v = _run_fixed_handshake()

    assert len(v["m1"]) == 32

    assert len(v["m2"]) == 32 + (32 + 16) + 16

    assert len(v["m3"]) == (32 + 16) + 16

    assert len(v["hh"]) == 32

    assert len(v["ct"]) == len(TRANSPORT_PLAINTEXT) + 16


def test_reproducible_handshake_hash_is_nonzero() -> None:
    v = _run_fixed_handshake()
    assert v["hh"] != bytes(32)

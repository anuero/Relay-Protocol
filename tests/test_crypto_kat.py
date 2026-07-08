from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from securews.crypto import (
    constant_time_equal,
    key_fingerprint,
    safety_number,
    secure_zero,
    validate_public_key,
)


def test_chacha20poly1305_rfc8439_2_8_2() -> None:
    key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    expected = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd060"
        "0691"
    )
    got = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    assert got == expected

    assert ChaCha20Poly1305(key).decrypt(nonce, got, aad) == plaintext


def test_x25519_rfc7748_5_2() -> None:
    scalar = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    expected = bytes.fromhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    shared = X25519PrivateKey.from_private_bytes(scalar).exchange(
        X25519PublicKey.from_public_bytes(u)
    )
    assert shared == expected


def test_secure_zero_wipes_bytearray() -> None:
    buf = bytearray(b"super-secret-key-material")
    secure_zero(buf)
    assert buf == bytearray(len(buf))


def test_secure_zero_rejects_immutable() -> None:
    with pytest.raises(TypeError):
        secure_zero(b"immutable")


def test_constant_time_equal() -> None:
    assert constant_time_equal(b"abc", b"abc")
    assert not constant_time_equal(b"abc", b"abd")


def test_validate_public_key_length() -> None:
    validate_public_key(b"\x00" * 32)
    with pytest.raises(ValueError):
        validate_public_key(b"\x00" * 31)


def test_safety_number_is_deterministic() -> None:
    h = bytes(range(32))
    assert safety_number(h) == safety_number(h)


def test_safety_number_requires_32_bytes() -> None:
    with pytest.raises(ValueError):
        safety_number(b"\x00" * 16)


def test_key_fingerprint_format() -> None:
    fp = key_fingerprint(bytes(range(32)))
    assert fp.count(":") == 7
    assert all(len(part) == 2 for part in fp.split(":"))

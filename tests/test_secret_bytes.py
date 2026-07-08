from __future__ import annotations

import pytest

from securews.crypto import SecretBytes


def test_secret_bytes_exposes_contents() -> None:
    sb = SecretBytes(b"super-secret")
    assert bytes(sb) == b"super-secret"
    assert len(sb) == len(b"super-secret")


def test_secret_bytes_wipe_zeros_but_keeps_length() -> None:
    sb = SecretBytes(b"super-secret-key")
    n = len(sb)
    sb.wipe()
    assert bytes(sb) == bytes(n)
    assert len(sb) == n


def test_secret_bytes_context_manager_wipes_on_exit() -> None:
    sb = SecretBytes(b"key-material-here")
    n = len(sb)
    with sb as inner:
        assert bytes(inner) == b"key-material-here"
    assert bytes(sb) == bytes(n)


def test_secret_bytes_copy_is_independent() -> None:
    sb = SecretBytes(b"abc")
    out = bytes(sb)
    sb.wipe()
    assert out == b"abc"


def test_secret_bytes_rejects_non_bytes_like() -> None:
    with pytest.raises(TypeError):
        SecretBytes(32)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        SecretBytes("string")  # type: ignore[arg-type]

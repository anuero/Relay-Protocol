from __future__ import annotations

import logging

from securews.logging_policy import RedactingFilter, install_redacting_filter, logger

from .conftest import make_channel_pair


class _CaptureHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record.getMessage())


def test_full_exchange_never_logs_plaintext_or_keys() -> None:
    handler = _CaptureHandler()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        pair = make_channel_pair()
        marker = b"TOP-SECRET-PLAINTEXT-MARKER-123"
        assert pair.client_to_server(marker) == marker
        assert pair.server_to_client(b"ANOTHER-SECRET-XYZ") == b"ANOTHER-SECRET-XYZ"

        blob = "\n".join(handler.records)
        assert "TOP-SECRET-PLAINTEXT-MARKER-123" not in blob
        assert "ANOTHER-SECRET-XYZ" not in blob

        assert pair.client_id.private.hex() not in blob
        assert pair.server_id.private.hex() not in blob

        assert any("seq=" in r for r in handler.records)
    finally:
        logger.removeHandler(handler)


def test_redacting_filter_suppresses_hexish_blob() -> None:
    record = logging.LogRecord(
        "securews",
        logging.INFO,
        __file__,
        1,
        "leaked key %s",
        ("00112233445566778899aabbccddeeff00112233",),
        None,
    )
    assert RedactingFilter().filter(record) is True
    assert "<redacted>" in record.getMessage()


def test_redacting_filter_suppresses_raw_bytes_arg() -> None:
    record = logging.LogRecord(
        "securews",
        logging.INFO,
        __file__,
        1,
        "payload=%r",
        (b"secretbytes",),
        None,
    )
    RedactingFilter().filter(record)
    assert "secretbytes" not in record.getMessage()


def test_install_redacting_filter_smoke() -> None:
    install_redacting_filter()

    install_redacting_filter(logger)

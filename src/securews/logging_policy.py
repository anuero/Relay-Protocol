from __future__ import annotations

import logging
import re

logger = logging.getLogger("securews")

REDACTED = "<redacted>"


_HEXISH = re.compile(r"(?:0x)?[0-9a-fA-F]{32,}")
_BYTES_REPR = re.compile(r"b['\"]")


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            record.msg = REDACTED
            record.args = ()
            return True

        if _looks_sensitive(record) or _HEXISH.search(message) or _BYTES_REPR.search(message):
            record.msg = f"{REDACTED} (message suppressed by RedactingFilter)"
            record.args = ()
        return True


def _looks_sensitive(record: logging.LogRecord) -> bool:
    args = record.args
    if isinstance(args, tuple):
        return any(isinstance(a, (bytes, bytearray, memoryview)) for a in args)
    return isinstance(args, (bytes, bytearray, memoryview))


def install_redacting_filter(target: logging.Logger | logging.Handler | None = None) -> None:
    (target or logger).addFilter(RedactingFilter())

from __future__ import annotations

import time
from collections.abc import Callable

DEFAULT_MAX_MESSAGES = 10_000


DEFAULT_MAX_SECONDS = 900.0


class RekeyPolicy:
    __slots__ = ("_clock", "_count", "_last_rekey", "_max_messages", "_max_seconds")

    def __init__(
        self,
        max_messages: int = DEFAULT_MAX_MESSAGES,
        max_seconds: float = DEFAULT_MAX_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_messages < 1:
            raise ValueError("max_messages must be >= 1")
        if max_seconds <= 0:
            raise ValueError("max_seconds must be > 0")
        self._max_messages = max_messages
        self._max_seconds = max_seconds
        self._clock = clock
        self._count = 0
        self._last_rekey = clock()

    def note_message(self) -> None:
        self._count += 1

    def due(self) -> bool:
        if self._count >= self._max_messages:
            return True
        return (self._clock() - self._last_rekey) >= self._max_seconds

    def reset(self) -> None:
        self._count = 0
        self._last_rekey = self._clock()

    @property
    def messages_since_rekey(self) -> int:
        return self._count

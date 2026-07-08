from __future__ import annotations

from .errors import ReplayError
from .framing import MAX_SEQ

DEFAULT_WINDOW_SIZE = 1024


class ReplayWindow:
    __slots__ = ("_bitmap", "_highest", "_mask", "_size")

    def __init__(self, size: int = DEFAULT_WINDOW_SIZE) -> None:
        if size < 1:
            raise ValueError("window size must be >= 1")
        self._size = size
        self._mask = (1 << size) - 1
        self._highest = -1
        self._bitmap = 0

    @property
    def size(self) -> int:
        return self._size

    @property
    def highest(self) -> int:
        return self._highest

    def check(self, seq: int) -> None:
        if not (0 <= seq <= MAX_SEQ):
            raise ReplayError(f"sequence number out of range: {seq}")
        if self._highest < 0 or seq > self._highest:
            return
        offset = self._highest - seq
        if offset >= self._size:
            raise ReplayError(f"sequence number {seq} is too old (window={self._size})")
        if self._bitmap & (1 << offset):
            raise ReplayError(f"replayed sequence number: {seq}")

    def commit(self, seq: int) -> None:
        if self._highest < 0:
            self._highest = seq
            self._bitmap = 1
            return
        if seq > self._highest:
            shift = seq - self._highest
            if shift >= self._size:
                self._bitmap = 1
            else:
                self._bitmap = ((self._bitmap << shift) | 1) & self._mask
            self._highest = seq
            return
        offset = self._highest - seq
        if offset < self._size:
            self._bitmap |= 1 << offset

    def check_and_update(self, seq: int) -> None:
        self.check(seq)
        self.commit(seq)

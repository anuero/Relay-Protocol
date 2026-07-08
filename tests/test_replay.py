from __future__ import annotations

import pytest

from securews.errors import ReplayError
from securews.replay import ReplayWindow


def test_in_order_sequence_accepted() -> None:
    w = ReplayWindow(size=64)
    for seq in range(1000):
        w.check_and_update(seq)
    assert w.highest == 999


def test_duplicate_rejected() -> None:
    w = ReplayWindow(size=64)
    w.check_and_update(5)
    with pytest.raises(ReplayError):
        w.check_and_update(5)


def test_reorder_within_window_accepted() -> None:
    w = ReplayWindow(size=64)
    for seq in [10, 12, 11, 9, 13]:
        w.check_and_update(seq)

    with pytest.raises(ReplayError):
        w.check_and_update(11)


def test_too_old_rejected() -> None:
    w = ReplayWindow(size=64)
    w.check_and_update(100)
    with pytest.raises(ReplayError):
        w.check_and_update(100 - 64)


def test_far_ahead_jump_resets_window() -> None:
    w = ReplayWindow(size=64)
    w.check_and_update(5)
    w.check_and_update(10_000)
    assert w.highest == 10_000

    with pytest.raises(ReplayError):
        w.check_and_update(5)


def test_check_does_not_mutate() -> None:
    w = ReplayWindow(size=64)
    w.check_and_update(7)
    w.check(8)
    w.check(8)
    w.commit(8)
    with pytest.raises(ReplayError):
        w.check(8)


def test_forged_seq_check_then_failed_decrypt_does_not_block_real_frame() -> None:
    w = ReplayWindow(size=64)
    w.check_and_update(0)
    w.check(1)

    w.check_and_update(1)
    assert w.highest == 1


def test_out_of_range_rejected() -> None:
    w = ReplayWindow(size=8)
    with pytest.raises(ReplayError):
        w.check_and_update(-1)
    with pytest.raises(ReplayError):
        w.check_and_update(1 << 64)


def test_invalid_size() -> None:
    with pytest.raises(ValueError):
        ReplayWindow(size=0)

from __future__ import annotations

from securews.framing import MessageType, decode
from securews.identity import StaticIdentity
from securews.rekey import RekeyPolicy

from .conftest import make_channel_pair, run_handshake


class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def test_policy_due_by_message_count() -> None:
    clock = FakeClock()
    policy = RekeyPolicy(max_messages=3, max_seconds=1e9, clock=clock)
    assert not policy.due()
    policy.note_message()
    policy.note_message()
    assert not policy.due()
    policy.note_message()
    assert policy.due()
    policy.reset()
    assert not policy.due()
    assert policy.messages_since_rekey == 0


def test_policy_due_by_time() -> None:
    clock = FakeClock()
    policy = RekeyPolicy(max_messages=1_000_000, max_seconds=60, clock=clock)
    assert not policy.due()
    clock.t += 61
    assert policy.due()
    policy.reset()
    assert not policy.due()


def test_policy_validates_args() -> None:
    import pytest

    with pytest.raises(ValueError):
        RekeyPolicy(max_messages=0)
    with pytest.raises(ValueError):
        RekeyPolicy(max_seconds=0)


def test_channel_emits_rekey_frame_when_due() -> None:
    pair = make_channel_pair(client_rekey=RekeyPolicy(max_messages=2, max_seconds=1e9))
    saw_rekey = False
    for i in range(6):
        frames = pair.client.encrypt(f"m{i}".encode())
        if len(frames) == 2:
            assert decode(frames[0]).msg_type is MessageType.REKEY
            saw_rekey = True

        out = None
        for f in frames:
            out = pair.server.decrypt(f)
        assert out == f"m{i}".encode()
    assert saw_rekey, "expected at least one rekey during the exchange"


def test_rekey_keeps_both_directions_working() -> None:
    pair = make_channel_pair(
        client_rekey=RekeyPolicy(max_messages=3, max_seconds=1e9),
        server_rekey=RekeyPolicy(max_messages=5, max_seconds=1e9),
    )
    for i in range(50):
        assert pair.client_to_server(f"c{i}".encode()) == f"c{i}".encode()
        assert pair.server_to_client(f"s{i}".encode()) == f"s{i}".encode()


def test_session_level_forward_secrecy() -> None:
    client = StaticIdentity.generate()
    server = StaticIdentity.generate()
    a_client, _ = run_handshake(client, server)
    b_client, _ = run_handshake(client, server)
    assert a_client.handshake_hash != b_client.handshake_hash

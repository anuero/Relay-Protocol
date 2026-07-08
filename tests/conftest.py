from __future__ import annotations

from dataclasses import dataclass

import pytest

from securews.channel import SecureChannel
from securews.handshake import HandshakeResult, NoiseXXHandshake
from securews.identity import StaticIdentity
from securews.protocol import build_prologue
from securews.rekey import RekeyPolicy


def run_handshake(
    client_id: StaticIdentity,
    server_id: StaticIdentity,
    *,
    client_prologue: bytes | None = None,
    server_prologue: bytes | None = None,
) -> tuple[HandshakeResult, HandshakeResult]:
    ini = NoiseXXHandshake(
        initiator=True,
        static_private=client_id.private,
        prologue=client_prologue if client_prologue is not None else build_prologue(),
    )
    res = NoiseXXHandshake(
        initiator=False,
        static_private=server_id.private,
        prologue=server_prologue if server_prologue is not None else build_prologue(),
    )

    for _ in range(8):
        if ini.is_complete and res.is_complete:
            break
        if ini.next_is_write():
            res.read_message(ini.write_message())
        elif res.next_is_write():
            ini.read_message(res.write_message())
    return ini.result(), res.result()


@dataclass(slots=True)
class ChannelPair:
    client: SecureChannel
    server: SecureChannel
    client_id: StaticIdentity
    server_id: StaticIdentity

    def client_to_server(self, plaintext: bytes) -> bytes | None:
        out: bytes | None = None
        for frame in self.client.encrypt(plaintext):
            out = self.server.decrypt(frame)
        return out

    def server_to_client(self, plaintext: bytes) -> bytes | None:
        out: bytes | None = None
        for frame in self.server.encrypt(plaintext):
            out = self.client.decrypt(frame)
        return out


def make_channel_pair(
    *,
    client_rekey: RekeyPolicy | None = None,
    server_rekey: RekeyPolicy | None = None,
) -> ChannelPair:
    client_id = StaticIdentity.generate()
    server_id = StaticIdentity.generate()
    client_result, server_result = run_handshake(client_id, server_id)
    return ChannelPair(
        client=SecureChannel(client_result, rekey_policy=client_rekey),
        server=SecureChannel(server_result, rekey_policy=server_rekey),
        client_id=client_id,
        server_id=server_id,
    )


@pytest.fixture
def channel_pair() -> ChannelPair:
    return make_channel_pair()

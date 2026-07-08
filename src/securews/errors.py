from __future__ import annotations


class SecureWebSocketError(Exception):
    pass


class FrameError(SecureWebSocketError):
    pass


class ProtocolError(SecureWebSocketError):
    pass


class HandshakeError(SecureWebSocketError):
    pass


class DowngradeError(HandshakeError):
    pass


class ReplayError(SecureWebSocketError):
    pass


class DecryptionError(SecureWebSocketError):
    pass


class IdentityError(SecureWebSocketError):
    pass


class ChannelClosedError(SecureWebSocketError):
    pass

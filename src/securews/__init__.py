from __future__ import annotations

from .ca import CertificateAuthority, IdentityCertificate, RevocationList
from .channel import SecureChannel
from .crypto import SecretBytes, key_fingerprint, safety_number, secure_zero
from .errors import (
    ChannelClosedError,
    DecryptionError,
    DowngradeError,
    FrameError,
    HandshakeError,
    IdentityError,
    ProtocolError,
    ReplayError,
    SecureWebSocketError,
)
from .framing import Frame, MessageType
from .handshake import HandshakeResult, NoiseXXHandshake
from .identity import KnownPeers, StaticIdentity
from .protocol import (
    NOISE_PROTOCOL_NAME,
    PROTOCOL_NAME,
    PROTOCOL_VERSION,
    build_prologue,
)
from .rekey import RekeyPolicy
from .replay import ReplayWindow
from .transport import ANY_SUBJECT, SecureConnection, certificate_fingerprint, connect, serve

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "connect",
    "serve",
    "ANY_SUBJECT",
    "SecureConnection",
    "certificate_fingerprint",
    "SecureChannel",
    "NoiseXXHandshake",
    "HandshakeResult",
    "StaticIdentity",
    "KnownPeers",
    "CertificateAuthority",
    "IdentityCertificate",
    "RevocationList",
    "safety_number",
    "key_fingerprint",
    "secure_zero",
    "SecretBytes",
    "Frame",
    "MessageType",
    "ReplayWindow",
    "RekeyPolicy",
    "build_prologue",
    "PROTOCOL_NAME",
    "PROTOCOL_VERSION",
    "NOISE_PROTOCOL_NAME",
    "SecureWebSocketError",
    "FrameError",
    "ProtocolError",
    "HandshakeError",
    "DowngradeError",
    "ReplayError",
    "DecryptionError",
    "IdentityError",
    "ChannelClosedError",
]

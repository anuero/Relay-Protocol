# Relay

End-to-end encrypted messages over a WebSocket. The server that relays your
traffic moves the bytes but cannot read them.

It runs the Noise Protocol Framework (the Noise XX handshake) with
ChaCha20-Poly1305 and X25519 inside a normal `wss://` (WebSocket over TLS)
connection. You get an encrypted channel that the server cannot decrypt, plus
mutual authentication, forward secrecy, replay protection, and downgrade
protection.

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-Apache--2.0-green)
![tests](https://img.shields.io/badge/tests-133%20passing-brightgreen)

---

### Why it exists

`wss://` already gives you TLS, so a network eavesdropper is handled. What TLS
does not give you is protection from the server itself: the server terminates
TLS and sees your plaintext. This SDK adds a second, inner layer of encryption
that the server cannot read. That inner layer is the Noise protocol, the same
family used by WhatsApp, WireGuard, and the Signal transport, so the handshake,
nonces, replay handling, and forward secrecy are done correctly instead of by
hand.

### How it works

Three layers, outer to inner:

```
your app          send(bytes) / async for message in conn
SecureChannel     Noise XX handshake, ChaCha20-Poly1305 frames,
                  sequence numbers, replay window, rekey
WebSocket (WSS)   TLS, optional certificate pinning
```

TLS stays on the outside because it is free and useful. The Noise channel on the
inside is what the server cannot decrypt.

### Install

There is no PyPI release yet, so clone the repo and install it in place:

```bash
git clone https://github.com/anuero/Relay-Protocol.git secure-websocket-sdk
cd secure-websocket-sdk
python -m venv .venv
. .venv/Scripts/activate       # Windows
# source .venv/bin/activate    # Linux or macOS
pip install -e ".[dev]"
```

Runtime dependencies only: `pip install cryptography noiseprotocol websockets`.

### Run the demo

Open two terminals.

```bash
python examples/server.py      # terminal 1, prints: listening on wss://localhost:8765
python examples/client.py      # terminal 2, connects and echoes a few messages
```

Both print a safety number. They must match. If they differ, someone is between
you. The demo creates a self-signed TLS certificate and a stored identity on the
first run.

### Use it in your project

Minimal client, three lines. No identity given means an ephemeral key, and TLS
is verified against the system certificate store:

```python
from securews import connect

conn = await connect("wss://example.com/ws")
await conn.send(b"hello, encrypted end to end")
print(await conn.recv())
```

Server:

```python
from securews import serve
from securews.identity import StaticIdentity

async def handler(conn):
    async for message in conn:
        await conn.send(message)

identity = StaticIdentity.generate()   # store this so it stays stable
server = await serve(handler, "0.0.0.0", 8765,
                     identity=identity, ssl_context=server_tls_ctx)
await server.wait_closed()
```

Messages are bytes. Serialize your own JSON or protobuf before sending. One
message holds up to 65519 bytes; split larger data yourself.

### Turn on maximum protection

One flag, `secure=True`, refuses to connect unless the server is authenticated
and TLS is verified:

```python
from securews import connect

conn = await connect("wss://example.com/ws",
                     ssl_context=strict_tls_ctx,
                     trusted_issuer=ca_public_key,
                     expected_subject="server",
                     secure=True)
```

`secure=True` does four things: it requires an authenticator (`trusted_issuer`,
`expected_peer_key`, or a pre-pinned peer), it uses a verifying TLS context by
default, it rejects a TLS context set to `CERT_NONE`, and it refuses
trust-on-first-use.

Whenever you pass `trusted_issuer`, you must also pass `expected_subject`, so
"signed by our CA" cannot be confused with "the specific server I meant". To
accept any subject that issuer has signed, opt in explicitly with
`expected_subject=ANY_SUBJECT` (imported from `securews`).

### Where the values come from

Run one script and it prints every value, plus how to obtain each:

```bash
python examples/provision.py
```

Short version:

`ca_public_key` is yours to create, not something you download. You run a
certificate authority once, keep its private key secret, and ship its public key
inside your client:

```python
from securews import CertificateAuthority
ca = CertificateAuthority()
open("ca_private.key", "w").write(ca.private_key.hex())   # secret
print(ca.public_key.hex())                                 # put this in the client
```

`strict_tls_ctx` is a standard `ssl.SSLContext`:

```python
import ssl
strict_tls_ctx = ssl.create_default_context()                    # public TLS certificate
# strict_tls_ctx = ssl.create_default_context(cafile="tls.pem")  # self-signed / private CA
```

For a public server with a real certificate you can skip `strict_tls_ctx`:
`secure=True` builds a verifying context for you.

`expected_subject` is just the label you signed the certificate with in
`ca.issue("server", key, lifetime=timedelta(days=365))`. Every certificate must
carry an expiry: pass `lifetime=` (a `datetime.timedelta`) or `not_after=` (an
absolute Unix time). `cert_pin` is the SHA-256 of the server's TLS certificate;
get it from a live server with `openssl s_client` or from a PEM with
`securews.certificate_fingerprint(der)`.

### Hardening knobs

- **Certificate expiry is mandatory.** `CertificateAuthority.issue(...)` refuses
  to mint an eternal certificate; a verifier rejects one whose expiry has passed
  or is missing.
- **Revocation.** Build a `RevocationList` of compromised static keys and/or
  subjects and pass it as `revocation=` to `connect`/`serve`. A revoked static
  key is refused regardless of how the peer authenticates (certificate, pin, or
  `expected_peer_key`); a revoked subject is refused on the certificate path.
  Distribute the list with `to_dict`/`from_dict` or `save`/`load`.
- **Handshake timeout.** `connect`/`serve` take `handshake_timeout` (default
  `10.0` seconds) so a peer that stalls mid-handshake is dropped instead of
  pinning a coroutine open; pass `None` to disable. Oversize frames are also
  refused by the transport before they are buffered.
- **Key wiping.** `StaticIdentity` holds its private key in a wipeable
  `SecretBytes`. Call `identity.wipe()` or use the identity as a context manager
  to zero the copy it owns. This is best effort only: `cryptography` and Noise
  keep internal copies that Python cannot reach.

### Verify there is no man in the middle

The MITM lab shows the attack and the defense. See it yourself:

```bash
python examples/server.py                                          # terminal 1
python examples/mitm/active_mitm.py --tamper                       # terminal 2, reads and alters traffic
python examples/mitm/victim_client.py --url wss://localhost:8770   # terminal 3, no auth: gets intercepted
```

Now defend, and the attack stops before a single message is sent:

```bash
python examples/mitm/victim_client.py --url wss://localhost:8765 --pin          # trust the real server once
python examples/mitm/victim_client.py --url wss://localhost:8770 --require-pin  # attacker refused
```

There is also a curious-relay demo using mitmproxy that shows the intercepted
frames are ciphertext:

```bash
python examples/server.py
mitmweb --mode reverse:https://localhost:8765 --listen-port 8080 --ssl-insecure \
        -s examples/mitm/mitm_addon.py
python examples/mitm/curious_client.py --url wss://localhost:8080
```

### Run the tests and checks

```bash
pytest -q                                       # 133 tests
pytest -q --cov=securews --cov-report=term-missing
ruff check . && ruff format --check .
mypy
bandit -r src
```

Or all of them at once:

```bash
bash scripts/check.sh
```

The tests cover known-answer vectors from RFC 8439 and RFC 7748, a fuzzed frame
parser, tamper and truncation and replay rejection, downgrade rejection, rekey,
forward secrecy, identity pinning, the certificate authority, certificate expiry
and revocation, handshake timeouts and oversize-frame rejection, secret wiping,
and a real localhost WSS round trip.

### What it protects, and what it does not

Protects against:

- a network attacker who intercepts, changes, reorders, or replays traffic
- a compromised or curious server: it routes ciphertext it cannot read
- leak of an old key: past messages stay secret (forward secrecy)
- downgrade of the protocol version or cipher suite
- a man in the middle, via key pinning, a certificate authority, and safety
  numbers you read out loud

Does not protect:

- a compromised device: if the endpoint is owned, encryption cannot help
- metadata: the server still sees who talks to whom and when
- traffic analysis by size or timing (there is no padding)
- future key compromise recovery (no Double Ratchet yet)

### Project layout

```
src/securews/      the SDK (protocol, framing, handshake, channel, replay,
                   rekey, identity, ca, transport, crypto, logging_policy)
tests/             133 tests: unit, fuzz, known-answer vectors, WSS integration
examples/          runnable client and server, provision.py, the MITM lab
scripts/           check.sh and check.ps1
```

### Security research

This project welcomes independent security research.

If you believe you have found a way to bypass the protocol, violate its security
guarantees, or discovered any cryptographic or implementation vulnerability,
please report it responsibly. Every confirmed report helps improve the project
and makes the protocol more secure for everyone.

If your report leads to a confirmed security improvement, you will be credited
in the project (unless you prefer to remain anonymous).

Contact: TG **@extendio**

### License

Apache-2.0.

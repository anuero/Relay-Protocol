import os

PLAINTEXT_MARKERS = [
    b"secret message",
    b"password",
    b"hunter2",
    b"transfer",
    b"hello",
]


_LOG_PATH = os.environ.get("MITM_ADDON_LOG")


def _emit(line: str) -> None:
    print(line, flush=True)
    if _LOG_PATH:
        with open(_LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


class NoiseInterceptor:
    def __init__(self) -> None:
        self.count = 0
        self.leaks = 0

    def websocket_message(self, flow) -> None:
        message = flow.websocket.messages[-1]
        data = bytes(message.content)
        self.count += 1
        direction = "client->server" if message.from_client else "server->client"
        leaked = [m for m in PLAINTEXT_MARKERS if m in data]
        preview = data[:24].hex()
        _emit(f"[mitm-addon] #{self.count} {direction} len={len(data)} hex={preview}...")
        if leaked:
            self.leaks += 1
            _emit(f"[mitm-addon]   !!! PLAINTEXT LEAK: {leaked}")
        else:
            _emit("[mitm-addon]   ciphertext only -- no plaintext markers visible")

    def done(self) -> None:
        _emit(
            f"[mitm-addon] summary: {self.count} frames intercepted, {self.leaks} plaintext leaks"
        )


addons = [NoiseInterceptor()]

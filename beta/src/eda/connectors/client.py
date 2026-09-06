"""Source-bound HTTP delivery; callers durably retain messages until acknowledged."""
import json
import re
import time
from urllib.parse import urlsplit
import httpx
from .contracts import SyncMessage


class DeliveryError(RuntimeError):
    """No confirmed acknowledgement. Retain and replay the identical message."""


class SyncClient:
    def __init__(self, base_url: str, source_id: str, token: str, *,
                 transport=None, allow_local_http=False, sleep=time.sleep):
        parsed = urlsplit(base_url)
        local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if (parsed.scheme != "https" and not
                (allow_local_http and local and parsed.scheme == "http")):
            raise ValueError("HTTPS required except explicitly enabled local development")
        if (not parsed.hostname or parsed.username or parsed.password or parsed.query
                or parsed.fragment or parsed.path not in {"", "/"}):
            raise ValueError("expected an origin without credentials, path, query or fragment")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", source_id):
            raise ValueError("invalid source identifier")
        if not token or any(c.isspace() for c in token):
            raise ValueError("invalid collector token")
        self.source_id = source_id
        self.url = base_url.rstrip("/") + f"/relationship-sources/{source_id}/sync"
        self._sleep = sleep
        self._client = httpx.Client(transport=transport, timeout=30, follow_redirects=False,
                                   trust_env=False, headers={"Authorization": f"Bearer {token}"})

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def send(self, message: SyncMessage) -> dict:
        # Freeze once: a retry must have the same sequence AND payload.
        payload = message.model_dump_json().encode()
        if len(payload) > 2 * 1024 * 1024:
            raise ValueError("sync message exceeds 2 MiB")
        for attempt in range(4):
            try:
                with self._client.stream("POST", self.url, content=payload,
                                         headers={"Content-Type": "application/json"}) as response:
                    if response.status_code in {429, 502, 503, 504}:
                        if attempt < 3:
                            self._sleep(2 ** attempt)
                            continue
                        raise DeliveryError("delivery unavailable; retain identical message for replay")
                    if response.status_code != 200:
                        raise DeliveryError(f"delivery rejected (HTTP {response.status_code}); acknowledgement unconfirmed")
                    raw = bytearray()
                    for chunk in response.iter_bytes():
                        raw.extend(chunk)
                        if len(raw) > 65536:
                            raise DeliveryError("oversized acknowledgement")
                    try:
                        receipt = json.loads(raw)
                    except (ValueError, UnicodeError):
                        raise DeliveryError("invalid acknowledgement") from None
                    if (not isinstance(receipt, dict) or receipt.get("source_id") != self.source_id
                            or type(receipt.get("sequence")) is not int
                            or receipt["sequence"] != message.sequence
                            or receipt.get("operation") != message.operation):
                        raise DeliveryError("acknowledgement does not match message")
                    return receipt
            except httpx.TransportError:
                if attempt == 3:
                    raise DeliveryError("transport failed; retain identical message for replay") from None
                self._sleep(2 ** attempt)
        raise DeliveryError("acknowledgement unconfirmed")

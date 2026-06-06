"""Invio (opzionale) del report all'autore via key-server: POST /integrity.

Firma HMAC per-installazione + nonce + timestamp, STESSO schema del client PHP /
key-server (dominio "vaultcode/req-sig/v1"). Canale sicuro (HTTPS). Solo stdlib.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.request

_SIG_SCHEME = b"vaultcode/req-sig/v1"
_PATH = "/integrity"


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def _canonical(method: str, path: str, install_uuid: str, nonce: str, ts: str, body: bytes) -> bytes:
    parts = [_SIG_SCHEME, method.upper().encode(), path.encode(), install_uuid.encode(),
             nonce.encode(), ts.encode(), body]
    return b"".join(_lp(p) for p in parts)


def send_report(key_server_url: str, *, install_uuid: str, install_secret_hex: str,
                report: dict, timeout: float = 15.0) -> dict:
    body = json.dumps(report).encode("utf-8")
    nonce = os.urandom(16).hex()
    ts = str(int(time.time()))
    secret = bytes.fromhex(install_secret_hex)
    sig = hmac.new(secret, _canonical("POST", _PATH, install_uuid, nonce, ts, body), hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        key_server_url.rstrip("/") + _PATH, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Install-UUID": install_uuid,
            "X-Nonce": nonce,
            "X-Timestamp": ts,
            "X-Signature": sig,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))

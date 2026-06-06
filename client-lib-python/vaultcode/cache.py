"""Cache locale delle content key — CIFRATA e AUTENTICATA (AES-256-GCM). §5.

File su disco = nonce(12) ‖ ciphertext‖tag. Contenuto: mappa "module:ck:frag" →
{content_key_hex, window, fetched_at}. La freschezza (TTL/grace) la decide il
Runtime, così è possibile il fallback "stale entro il grace" se il server è giù.
Formato identico alla ``Cache.php`` (la chiave di cache è la stessa derivazione).
"""

from __future__ import annotations

import hashlib
import json
import os

from . import crypto

_AAD = b"vaultcode/cache/v1"


class Cache:
    def __init__(self, path: str, key: bytes):
        self.path = path
        self.key = key

    @staticmethod
    def derive_key(install_secret: bytes) -> bytes:
        """Deriva la chiave di cache dal segreto per-installazione (deterministica,
        parità con Cache::deriveKey)."""
        return hashlib.sha256(install_secret + b"vaultcode/cache-key/v1").digest()[:32]

    def _load(self) -> dict:
        if not self.path or not os.path.isfile(self.path):
            return {}
        with open(self.path, "rb") as fh:
            blob = fh.read()
        if len(blob) < 13:
            return {}
        nonce, ct = blob[:12], blob[12:]
        try:
            data = json.loads(crypto.aes_gcm_decrypt(self.key, ct, nonce, _AAD).decode("utf-8"))
        except Exception:  # cache corrotta/manomessa → ignorata (verrà riscritta)
            return {}
        return data if isinstance(data, dict) else {}

    def _save(self, data: dict) -> None:
        if not self.path:
            return
        nonce = crypto.new_nonce()
        ct = crypto.aes_gcm_encrypt(self.key, json.dumps(data).encode("utf-8"), nonce, _AAD)
        d = os.path.dirname(self.path)
        if d and not os.path.isdir(d):
            os.makedirs(d, mode=0o700, exist_ok=True)
        with open(self.path, "wb") as fh:
            fh.write(nonce + ct)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def get(self, module: str, ck: int, frag: str) -> dict | None:
        entry = self._load().get(f"{module}:{ck}:{frag}")
        return entry if isinstance(entry, dict) else None

    def put(self, module: str, ck: int, frag: str, content_key_hex: str, window: str, now: int) -> None:
        data = self._load()
        data[f"{module}:{ck}:{frag}"] = {
            "content_key_hex": content_key_hex, "window": window, "fetched_at": now,
        }
        self._save(data)

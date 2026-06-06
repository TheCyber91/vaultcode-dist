"""Configurazione del client Python — stessi campi del ``vaultcode.config.json``
usato dalla versione PHP (un'unica config vale per entrambi i linguaggi)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class Config:
    install_uuid: str = ""
    install_secret: bytes = b""          # bytes grezzi (per la firma HMAC)
    license_token: str = ""
    key_server_url: str = ""
    ed25519_public_key_pem: str = ""
    key_server_pin: str = ""
    payload_dir: str = ""
    cache_path: str = ""
    rights_tag: str = ""
    escrow_path: str = ""
    banner_log_file: str = ""
    status_cache_path: str = ""
    status_ttl_seconds: int = 300
    badge_auto_display: bool = True
    ttl_seconds: int = 3600
    grace_seconds: int = 604800
    clock_skew_seconds: int = 300
    retries: int = 5
    timeout: float = 10.0

    @classmethod
    def from_dict(cls, a: dict) -> "Config":
        c = cls()
        c.install_uuid = str(a.get("install_uuid", "") or "")
        secret_hex = str(a.get("install_secret_hex", "") or "")
        c.install_secret = bytes.fromhex(secret_hex) if secret_hex else b""
        c.license_token = str(a.get("license_token", "") or "")
        c.key_server_url = str(a.get("key_server_url", "") or "").rstrip("/")
        c.ed25519_public_key_pem = str(a.get("ed25519_public_key_pem", "") or "")
        c.key_server_pin = str(a.get("key_server_pin", "") or "")
        c.payload_dir = str(a.get("payload_dir", "") or "")
        c.cache_path = str(a.get("cache_path", "") or "")
        c.rights_tag = str(a.get("rights_tag", "") or "")
        c.escrow_path = str(a.get("escrow_path", "") or "")
        c.banner_log_file = str(a.get("banner_log_file", "") or "")
        c.status_cache_path = str(a.get("status_cache_path", "") or "")
        c.badge_auto_display = bool(a.get("badge_auto_display", True))
        for k, attr in (("ttl_seconds", "ttl_seconds"), ("grace_seconds", "grace_seconds"),
                        ("clock_skew_seconds", "clock_skew_seconds"), ("retries", "retries"),
                        ("status_ttl_seconds", "status_ttl_seconds")):
            if a.get(k) is not None:
                setattr(c, attr, int(a[k]))
        if a.get("timeout") is not None:
            c.timeout = float(a["timeout"])
        return c

    @classmethod
    def from_json_file(cls, path: str) -> "Config":
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise RuntimeError(f"config non valida: {path}")
        return cls.from_dict(data)

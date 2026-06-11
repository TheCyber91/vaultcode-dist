"""Client HTTP del key-server: firma HMAC per-installazione + nonce + timestamp
(anti-replay) su TLS. Verifica le risposte firmate Ed25519. Parità con
``KeyServerClient.php``. Solo stdlib (`urllib`) + `cryptography`.

Nota: il pinning TLS della chiave pubblica (CURLOPT_PINNEDPUBLICKEY in PHP) non è
replicato qui (urllib non lo espone in modo pulito): la difesa primaria contro un
server contraffatto resta la **firma Ed25519** di /status, /revocations, /release.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import time
import urllib.request

from . import crypto
from .config import Config

RUNTIME_VERSION = "1.0.1"


def _install_context() -> dict:
    """Contesto d'installazione del bot (anti-copia §4): DOVE gira l'opera. Dati
    minimi e dichiarati (host/IP/macchina/percorso), mai contenuto o attività del
    cliente. Best-effort: ogni campo è opzionale e non solleva mai."""
    ctx: dict[str, str] = {}
    try:
        ctx["dominio"] = socket.getfqdn() or socket.gethostname()       # contesto (no HTTP host nei bot)
    except Exception:  # noqa: BLE001
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80)); ctx["host"] = s.getsockname()[0]  # IP locale/uscita (best-effort)
        finally:
            s.close()
    except Exception:  # noqa: BLE001
        pass
    try:
        mid = ""
        for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            if os.path.exists(p):
                mid = open(p, encoding="utf-8").read().strip()
                break
        ctx["machine_id"] = hashlib.sha256((mid or socket.gethostname()).encode()).hexdigest()[:24]
    except Exception:  # noqa: BLE001
        pass
    try:
        ctx["install_path"] = os.getcwd()
    except Exception:  # noqa: BLE001
        pass
    return {k: v for k, v in ctx.items() if v}


class KeyServerClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def _signed_headers(self, method: str, path: str, body: bytes) -> dict:
        nonce = os.urandom(16).hex()
        ts = str(int(time.time()))
        msg = crypto.build_canonical_message(method, path, self.cfg.install_uuid, nonce, ts, body)
        sig = crypto.compute_signature(self.cfg.install_secret, msg)
        return {
            "Content-Type": "application/json",
            "X-Install-UUID": self.cfg.install_uuid,
            "X-Nonce": nonce,
            "X-Timestamp": ts,
            "X-Signature": sig,
        }

    def _http(self, method: str, path: str, headers: dict, body: bytes | None):
        req = urllib.request.Request(self.cfg.key_server_url + path, data=body, method=method,
                                     headers=headers)
        with urllib.request.urlopen(req, timeout=self.cfg.timeout) as resp:  # noqa: S310 (HTTPS in prod)
            return resp.getcode(), resp.read()

    def fetch_key(self, module: str, ck: int, frag: str) -> dict:
        body = json.dumps({
            "module_id": module, "ck_version": ck, "frag_id": frag,
            "license_token": self.cfg.license_token,
        }).encode("utf-8")
        code, raw = self._http("POST", "/key", self._signed_headers("POST", "/key", body), body)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise RuntimeError(f"risposta /key non valida (HTTP {code})")
        data["_http"] = code
        return data

    def post_tamper(self, tipo: str, dettaglio: str | None) -> None:
        body = json.dumps({"tipo": tipo, "dettaglio": dettaglio}).encode("utf-8")
        try:
            self._http("POST", "/tamper", self._signed_headers("POST", "/tamper", body), body)
        except Exception:  # noqa: BLE001 - reporting non bloccante
            pass

    def fetch_status(self) -> dict | None:
        body = json.dumps({"client_version": RUNTIME_VERSION, **_install_context()}).encode("utf-8")
        try:
            _code, raw = self._http("POST", "/status", self._signed_headers("POST", "/status", body), body)
        except Exception:  # noqa: BLE001 - disponibilità: il chiamante tiene l'ultimo stato noto
            return None
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(data, dict) or "signed_status" not in data:
            return None
        token = str(data["signed_status"])
        payload = crypto.verify_token(self.cfg.ed25519_public_key_pem, token)
        if payload is None:
            return None
        if payload.get("type") != "vaultcode/status/v1":
            return None
        if payload.get("install_uuid") != self.cfg.install_uuid:
            return None
        payload["_token"] = token
        return payload

    def fetch_revocations(self) -> list[str] | None:
        try:
            _code, raw = self._http("GET", "/revocations", {"Accept": "application/json"}, None)
        except Exception:  # noqa: BLE001
            return None
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(data, dict) or "signed_document" not in data:
            return None
        payload = crypto.verify_token(self.cfg.ed25519_public_key_pem, str(data["signed_document"]))
        if payload is None or "revoked" not in payload:
            return None
        return [str(r["license_id"]) for r in payload.get("revoked", []) if isinstance(r, dict) and "license_id" in r]

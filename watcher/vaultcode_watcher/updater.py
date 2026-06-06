"""Auto-update delle risorse VaultCode (client-lib e watcher stesso).

Scarica dal key-server un BUNDLE FIRMATO Ed25519 (`GET /release/<component>`),
ne **verifica la firma** con la chiave pubblica dell'autore e gli hash dei file,
poi sostituisce i file **atomicamente** (con backup). Mai bloccante: un errore
non interrompe il watcher né l'app del cliente (INVARIANTE 1/7).

Sicurezza:
  - La verifica Ed25519 usa `cryptography` (OpenSSL) — INVARIANTE 6, niente
    primitive custom. È importata SOLO qui (il core del watcher resta stdlib).
  - La chiave pubblica è PINNATA (passata dall'agente di deploy): nessun bundle
    non firmato dall'autore viene applicato → no MITM/supply-chain via rete.
  - Si applica solo se la versione del bundle è diversa (o con --force).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time
import urllib.request
from pathlib import Path

RELEASE_FORMAT = "vaultcode/release/v1"
_SIG_SCHEME = b"vaultcode/req-sig/v1"


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def _signed_status_post(report_url: str, install_uuid: str, install_secret_hex: str,
                        body: bytes, timeout: float) -> bytes | None:
    """POST /status firmato HMAC (per-installazione). Ritorna il body o None."""
    path = "/status"
    nonce = os.urandom(16).hex()
    ts = str(int(time.time()))
    secret = bytes.fromhex(install_secret_hex)
    parts = [_SIG_SCHEME, b"POST", path.encode(), install_uuid.encode(),
             nonce.encode(), ts.encode(), body]
    sig = hmac.new(secret, b"".join(_lp(p) for p in parts), hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        report_url.rstrip("/") + path, data=body, method="POST",
        headers={"Content-Type": "application/json", "X-Install-UUID": install_uuid,
                 "X-Nonce": nonce, "X-Timestamp": ts, "X-Signature": sig})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.read()
    except Exception:  # noqa: BLE001
        return None


def ack_update(report_url: str, install_uuid: str, install_secret_hex: str, timeout: float = 20.0) -> bool:
    """Conferma al server che l'update richiesto è stato applicato → azzera la
    richiesta nello studio. Best-effort."""
    return _signed_status_post(report_url, install_uuid, install_secret_hex,
                               b'{"update_applied": true}', timeout) is not None


def fetch_status(report_url: str, install_uuid: str, install_secret_hex: str,
                 public_key_pem: bytes, timeout: float = 20.0) -> dict | None:
    """POST /status firmato HMAC; verifica la firma Ed25519 della risposta e
    ritorna il payload (con update_requested, current_client_version, ...). None
    se non disponibile/non verificabile. Per la 'coda comandi' lato server."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    raw = _signed_status_post(report_url, install_uuid, install_secret_hex, b"{}", timeout)
    if raw is None:
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None
    token = data.get("signed_status")
    if not token:
        return None
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        load_pem_public_key(public_key_pem).verify(_b64u_decode(sig_b64), payload_b64.encode("ascii"))
        payload = json.loads(_b64u_decode(payload_b64))
    except Exception:  # noqa: BLE001 - firma non valida → ignora il comando
        return None
    if payload.get("install_uuid") != install_uuid:
        return None
    return payload


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def fetch_release(report_url: str, component: str, timeout: float = 30.0) -> str:
    url = report_url.rstrip("/") + f"/release/{component}"
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (HTTPS in prod)
        data = json.loads(resp.read().decode("utf-8"))
    token = data.get("signed_release")
    if not token:
        raise ValueError("risposta /release priva di signed_release")
    return token


def verify_release(token: str, public_key_pem: bytes) -> dict:
    """Verifica la firma Ed25519 (su b64u(payload)) e ritorna il manifest.
    Solleva se la firma non è valida (cryptography richiesto)."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    try:
        payload_b64, sig_b64 = token.split(".", 1)
    except ValueError as exc:
        raise ValueError("token di release malformato") from exc
    pub = load_pem_public_key(public_key_pem)
    pub.verify(_b64u_decode(sig_b64), payload_b64.encode("ascii"))  # solleva se KO
    manifest = json.loads(_b64u_decode(payload_b64))
    if manifest.get("format") != RELEASE_FORMAT:
        raise ValueError("formato release inatteso")
    return manifest


def installed_version(component: str, target_dir) -> str | None:
    """Versione attualmente installata, dedotta dai file (per il confronto)."""
    base = Path(target_dir)
    if component == "client-lib":
        rt = base / "Runtime.php"
        if rt.is_file():
            m = re.search(r"const\s+VERSION\s*=\s*'([^']+)'", rt.read_text(encoding="utf-8", errors="replace"))
            return m.group(1) if m else None
    elif component == "watcher":
        ini = base / "vaultcode_watcher" / "__init__.py"
        if ini.is_file():
            m = re.search(r"__version__\s*=\s*'([^']+)'", ini.read_text(encoding="utf-8", errors="replace"))
            if not m:
                m = re.search(r'__version__\s*=\s*"([^"]+)"', ini.read_text(encoding="utf-8", errors="replace"))
            return m.group(1) if m else None
    return None


def apply_manifest(manifest: dict, target_dir) -> list[str]:
    """Scrive i file del manifest sotto target_dir, ATOMICAMENTE e con backup.
    Verifica lo sha256 di ogni file prima di installarlo."""
    base = Path(target_dir)
    written: list[str] = []
    for rel, info in sorted(manifest.get("files", {}).items()):
        data = base64.b64decode(info["content_b64"])
        if hashlib.sha256(data).hexdigest() != info["sha256"]:
            raise ValueError(f"hash non combacia per {rel} (bundle corrotto)")
        dst = base / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp = dst.with_suffix(dst.suffix + ".vcnew")
        tmp.write_bytes(data)
        if dst.is_file():
            dst.replace(dst.with_suffix(dst.suffix + ".vcbak"))  # backup atomico
        os.replace(tmp, dst)  # swap atomico
        written.append(rel)
    return written


def update_component(report_url: str, component: str, target_dir, public_key_pem: bytes,
                     force: bool = False) -> dict:
    """Aggiorna UN componente. Ritorna un esito (status: current|updated|error)."""
    try:
        token = fetch_release(report_url, component)
        manifest = verify_release(token, public_key_pem)
        cur = installed_version(component, target_dir)
        new = manifest.get("version")
        if not force and cur is not None and cur == new:
            return {"component": component, "status": "current", "version": cur}
        written = apply_manifest(manifest, target_dir)
        return {"component": component, "status": "updated", "from": cur, "to": new,
                "files": len(written)}
    except Exception as exc:  # noqa: BLE001 - mai bloccante
        return {"component": component, "status": "error", "error": str(exc)}

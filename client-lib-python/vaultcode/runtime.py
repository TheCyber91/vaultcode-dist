"""Facciata runtime Python: contratto v1 usato dal codice protetto

    exec(_vc.fragment('module','frag',ck), globals())

Restituisce il CODICE Python decifrato del frammento. Cascata di fallback (§5):
key-server (con retry) → cache locale (TTL/grace) → escrow → banner. NON bloccante:
in caso di indisponibilità ritorna stringa vuota (exec no-op) e lo script continua
(INVARIANTE 1). Logica e semantica identiche a ``client-lib-php/src/Runtime.php``.
"""

from __future__ import annotations

import html
import json
import os
import sys
import time

from . import crypto, sentinel
from .banner import Banner
from .cache import Cache
from .config import Config
from .key_server_client import KeyServerClient

VERSION = "1.0.0"


class Runtime:
    _instance: "Runtime | None" = None

    def __init__(self, cfg: Config, ks=None, cache=None, banner=None, tamper_detector=None):
        self.cfg = cfg
        self.ks = ks or KeyServerClient(cfg)
        if cache is None and cfg.cache_path and cfg.install_secret:
            cache = Cache(cfg.cache_path, Cache.derive_key(cfg.install_secret))
        self.cache = cache
        self.banner = banner or Banner(log_file=cfg.banner_log_file)
        self._tamper_detector = tamper_detector or sentinel.detect
        self._tamper_checked = False
        self._payloads: dict[str, dict] = {}
        self._escrow: dict | None = None
        self._fragment_cache: dict[str, str] = {}
        self._integrity_warnings: list[str] = []
        self._server_compromised: bool | None = None
        self._server_status_checked = False

    # --- bootstrap statico ---------------------------------------------------

    @classmethod
    def init(cls, cfg: Config, banner_sink=None) -> None:
        cls._instance = cls(cfg, banner=Banner(banner_sink, cfg.banner_log_file) if banner_sink else None)

    @classmethod
    def set_instance(cls, r: "Runtime") -> None:
        cls._instance = r

    @classmethod
    def fragment(cls, module: str, frag: str, ck: int, memo: bool = False) -> str:
        if cls._instance is None:
            sys.stderr.write("[VaultCode] Runtime non inizializzato: chiamare Runtime.init()\n")
            return ""
        # rights tag: preferisci la costante del MODULO chiamante (VAULTCODE_RIGHTS_TAG),
        # come fa il PHP con la costante in-file; fallback a cfg.rights_tag.
        caller_tag = ""
        try:
            caller_tag = str(sys._getframe(1).f_globals.get("VAULTCODE_RIGHTS_TAG", "") or "")
        except Exception:  # noqa: BLE001
            caller_tag = ""
        return cls._instance.get_fragment(module, frag, ck, memo, caller_tag)

    # --- stato d'integrità (badge) ------------------------------------------

    @classmethod
    def integrity_warnings(cls) -> list[str]:
        return list(cls._instance._integrity_warnings) if cls._instance else []

    @classmethod
    def native_active(cls) -> bool:
        return False  # nessuna estensione nativa per Python (hardening = Cython/Nuitka, §9)

    @classmethod
    def is_compromised(cls) -> bool:
        if cls._instance is None:
            return False
        cls._instance._ensure_server_status()
        return bool(cls._instance._integrity_warnings) or cls._instance._server_compromised is True

    @classmethod
    def scan(cls) -> None:
        if cls._instance is not None:
            cls._instance._tamper_check_once()

    @classmethod
    def integrity_badge(cls, label: str | None = None, tooltip: str | None = None) -> str:
        """Badge HTML (⚠ + tooltip) se compromesso, altrimenti ''. Per app web
        Python (Flask/Django): l'integratore lo inserisce nel template."""
        if not cls.is_compromised():
            return ""
        label = label or "Integrità licenza compromessa"
        tooltip = tooltip or ("VaultCode — Rilevata una possibile manomissione del sistema di licenza/"
                              "integrità di questo software. Il programma continua a funzionare "
                              "regolarmente. Si raccomanda di contattare il fornitore del software.")
        lab, tip = html.escape(label), html.escape(tooltip)
        pill = ("display:inline-flex;align-items:center;gap:6px;background:#7f1d1d;color:#fff;"
                "font:600 12px/1.2 system-ui,sans-serif;padding:6px 12px;border-radius:999px;"
                "cursor:help;white-space:nowrap")
        return (f'<span class="vc-badge" style="{pill}" title="{tip}" role="alert" aria-label="{tip}">'
                f'<span style="font-size:14px;line-height:1">&#9888;</span>'
                f'<span style="color:#fff">{lab}</span></span>')

    # --- logica d'istanza ----------------------------------------------------

    def _tamper(self, message: str) -> None:
        if message not in self._integrity_warnings:
            self._integrity_warnings.append(message)
        self.banner.notify(message)

    def _tamper_check_once(self) -> None:
        if self._tamper_checked:
            return
        self._tamper_checked = True
        for signal in self._tamper_detector():
            self._tamper(f"segnale anti-tamper rilevato: {signal} (registrato; software attivo)")
            self.ks.post_tamper(signal, None)

    def _ensure_server_status(self) -> None:
        if self._server_status_checked:
            return
        self._server_status_checked = True
        try:
            now = int(time.time())
            ttl = max(0, self.cfg.status_ttl_seconds)
            f = self.cfg.status_cache_path
            if f and os.path.isfile(f):
                try:
                    cached = json.loads(open(f, encoding="utf-8").read())
                except Exception:  # noqa: BLE001
                    cached = None
                if isinstance(cached, dict) and "token" in cached and "fetched_at" in cached:
                    payload = crypto.verify_token(self.cfg.ed25519_public_key_pem, str(cached["token"]))
                    if payload is not None and payload.get("install_uuid") == self.cfg.install_uuid:
                        self._server_compromised = (payload.get("integrity", "ok") == "alert")
                        if (now - int(cached["fetched_at"])) <= ttl:
                            return
            payload = self.ks.fetch_status()
            if payload is not None:
                self._server_compromised = (payload.get("integrity", "ok") == "alert")
                if f and "_token" in payload:
                    try:
                        with open(f, "w", encoding="utf-8") as fh:
                            json.dump({"token": payload["_token"], "fetched_at": now}, fh)
                    except OSError:
                        pass
        except Exception:  # noqa: BLE001 - lo stato è un di più: mai rompere
            pass

    def _load_payload(self, module: str) -> dict | None:
        if module in self._payloads:
            return self._payloads[module]
        path = os.path.join(self.cfg.payload_dir, f"{module}.vaultpayload.json")
        if not os.path.isfile(path):
            return None
        try:
            data = json.loads(open(path, encoding="utf-8").read())
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(data, dict):
            return None
        self._payloads[module] = data
        return data

    def _resolve_content_key(self, module: str, ck: int, frag: str) -> str | None:
        now = int(time.time())
        for _ in range(max(1, self.cfg.retries)):
            try:
                resp = self.ks.fetch_key(module, ck, frag)
            except Exception:  # noqa: BLE001 - disponibilità → riprova, poi cache (§5)
                continue
            status = str(resp.get("status", ""))
            if status == "granted" and resp.get("content_key"):
                hexk = str(resp["content_key"])
                win = str(resp.get("window", ""))
                if self.cache:
                    self.cache.put(module, ck, frag, hexk, win, now)
                return hexk
            self._tamper(f"contesto non autorizzato per {module}/{frag} ({resp.get('reason', status)})")
            break
        if self.cache:
            entry = self.cache.get(module, ck, frag)
            if entry is not None:
                age = now - int(entry.get("fetched_at", 0))
                if age <= self.cfg.grace_seconds:
                    if age > self.cfg.ttl_seconds:
                        self.banner.notify(f"server irraggiungibile: uso cache locale per {module}/{frag}")
                    return str(entry["content_key_hex"])
        ek = self._escrow_key(module, ck, frag)
        if ek is not None:
            return ek
        return None

    def _ensure_escrow(self) -> None:
        if self._escrow is not None:
            return
        self._escrow = {}
        path = self.cfg.escrow_path
        if not path or not os.path.isfile(path):
            return
        token = open(path, encoding="utf-8").read().strip()
        payload = crypto.verify_token(self.cfg.ed25519_public_key_pem, token)
        if payload is None:
            self._tamper("escrow: firma non valida (ignorato)")
            return
        if payload.get("install_uuid") != self.cfg.install_uuid:
            self._tamper("escrow: per un'altra installazione (ignorato)")
            return
        keys = payload.get("keys")
        self._escrow = keys if isinstance(keys, dict) else {}

    def _escrow_key(self, module: str, ck: int, frag: str) -> str | None:
        self._ensure_escrow()
        k = (self._escrow or {}).get(f"{module}:{ck}:{frag}")
        return k if isinstance(k, str) else None

    def get_fragment(self, module: str, frag: str, ck: int, memo: bool, caller_tag: str = "") -> str:
        self._tamper_check_once()
        cache_key = f"{module}:{frag}:{ck}"
        if memo and cache_key in self._fragment_cache:
            return self._fragment_cache[cache_key]
        payload = self._load_payload(module)
        if payload is None or frag not in (payload.get("fragments") or {}):
            self._tamper(f"payload mancante per {module}/{frag}")
            return ""
        entry = payload["fragments"][frag]
        hexk = self._resolve_content_key(module, ck, frag)
        if hexk is None:
            self.banner.notify(f"contesto non verificato: {module}/{frag} non eseguito (software comunque attivo)")
            return ""
        tag = caller_tag or self.cfg.rights_tag
        if not tag:
            self._tamper("informazioni di paternità assenti (VAULTCODE_RIGHTS_TAG): decifratura non possibile")
            return ""
        try:
            import base64
            key = bytes.fromhex(hexk)
            aad = crypto.aad_for(module, frag, ck, tag)
            plain = crypto.aes_gcm_decrypt(
                key, base64.b64decode(entry["ciphertext"]), base64.b64decode(entry["nonce"]), aad
            ).decode("utf-8")
            if memo and plain:
                self._fragment_cache[cache_key] = plain
            return plain
        except Exception:  # noqa: BLE001
            self._tamper(f"decifratura fallita per {module}/{frag} (paternità alterata?)")
            return ""

    def is_license_revoked(self) -> bool:
        revoked = self.ks.fetch_revocations()
        if revoked is None:
            return False
        payload = crypto.verify_token(self.cfg.ed25519_public_key_pem, self.cfg.license_token)
        license_id = (payload or {}).get("license_id")
        if license_id is not None and str(license_id) in revoked:
            self._tamper(f"licenza {license_id} revocata")
            return True
        return False

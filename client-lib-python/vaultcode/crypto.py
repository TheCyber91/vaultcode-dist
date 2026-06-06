"""Primitive crittografiche del client Python — PARITÀ byte-per-byte con
``client-lib-php/src/Crypto.php``, il protect-tool e il key-server.

Solo crittografia standard (`cryptography`: AES-256-GCM, Ed25519; `hmac`/`hashlib`).
Domini congelati sul wire (identici al resto del sistema):
  - firma richiesta:  "vaultcode/req-sig/v1"
  - AAD frammento:    "vaultcode/frag-aad/v1"
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_public_key

SIG_SCHEME = b"vaultcode/req-sig/v1"
AAD_DOMAIN = b"vaultcode/frag-aad/v1"


def lp(value: bytes) -> bytes:
    """Length-prefix uint32 big-endian + payload (domain separation)."""
    return len(value).to_bytes(4, "big") + value


def _b(v) -> bytes:
    return v if isinstance(v, bytes) else str(v).encode("utf-8")


# --- Firma richieste HMAC-SHA256 (parità con key-server hmac_auth) -----------

def build_canonical_message(method: str, path: str, install_uuid: str,
                            nonce: str, timestamp: str, body: bytes) -> bytes:
    parts = [SIG_SCHEME, method.upper().encode(), path.encode(),
             install_uuid.encode(), nonce.encode(), timestamp.encode(), _b(body)]
    return b"".join(lp(p) for p in parts)


def compute_signature(install_secret: bytes, canonical_message: bytes) -> str:
    """HMAC-SHA256 esadecimale minuscolo. ``install_secret`` in BYTES grezzi."""
    return hmac.new(install_secret, canonical_message, hashlib.sha256).hexdigest()


# --- AAD del frammento (parità con protect-tool bundle.aad_for) --------------

def aad_for(module: str, frag: str, ck: int, entanglement_tag: str) -> bytes:
    parts = [AAD_DOMAIN, module.encode(), frag.encode(),
             str(ck).encode(), entanglement_tag.encode()]
    return b"".join(lp(p) for p in parts)


# --- AES-256-GCM (parità con cryptography AESGCM / openssl PHP) --------------

def aes_gcm_decrypt(key: bytes, ciphertext_with_tag: bytes, nonce: bytes, aad: bytes) -> bytes:
    """Decifra ciphertext con tag IN CODA (formato di ``cryptography``: ct‖tag16).
    Solleva su autenticazione fallita."""
    if len(key) != 32:
        raise ValueError("chiave AES non di 32 byte")
    if len(nonce) != 12:
        raise ValueError("nonce GCM non di 12 byte")
    return AESGCM(key).decrypt(nonce, ciphertext_with_tag, aad)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
    """Cifra e ritorna ciphertext‖tag16 (usato dalla cache locale)."""
    if len(key) != 32:
        raise ValueError("chiave AES non di 32 byte")
    if len(nonce) != 12:
        raise ValueError("nonce GCM non di 12 byte")
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def new_nonce() -> bytes:
    import os
    return os.urandom(12)


# --- base64url senza padding -------------------------------------------------

def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --- Ed25519 — verifica licenze/revoche/status -------------------------------

def verify_token(public_key_pem: str, token: str) -> dict | None:
    """Verifica un token compatto ``payloadB64.sigB64`` (license/status/revocations).
    Ritorna il payload (dict) o None se invalido."""
    if not token or "." not in token:
        return None
    payload_b64, sig_b64 = token.split(".", 1)
    try:
        pub = load_pem_public_key(public_key_pem.encode("utf-8") if isinstance(public_key_pem, str)
                                  else public_key_pem)
        pub.verify(b64u_decode(sig_b64), payload_b64.encode("ascii"))
    except (InvalidSignature, ValueError, TypeError):
        return None
    try:
        payload = json.loads(b64u_decode(payload_b64))
    except (ValueError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None

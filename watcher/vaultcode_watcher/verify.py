"""Verifica di integrità contro il manifest SHA-256.

Confini NON negoziabili (§9, §3, §6):
  - Monitora SOLO i file elencati nel manifest (l'opera protetta). MAI il sistema
    del cliente, MAI file estranei.
  - Distingue **alterazione del core/attribuzione** (segnale reale) da
    **adattamento del layer libero** (diritto del licenziatario, 64-ter): per i
    sorgenti NON si confronta l'intero hash (il layer libero è modificabile);
    si verificano solo (a) integrità dei payload cifrati, (b) presenza/coerenza
    dell'intestazione di paternità, (c) presenza delle chiamate runtime del core.
  - Output = eventi con DATI MINIMI (path relativo, tipo, hash atteso/osservato).
    Mai il contenuto del codice.

Tipi di evento:
  payload_missing | payload_mismatch        → know-how cifrato rimosso/alterato
  attribution_removed | attribution_mismatch→ paternità (102-quinquies) intaccata
  core_fragment_removed                      → chiamata runtime del core eliminata
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .locate import FileLocator

# Tag di paternità in entrambi i dialetti:
#   PHP:    define('VAULTCODE_RIGHTS_TAG', '<hex>')
#   Python: VAULTCODE_RIGHTS_TAG = "<hex>"
_RIGHTS_RE = re.compile(r"""VAULTCODE_RIGHTS_TAG['"]?\s*[,=]\s*['"]([0-9a-fA-F]{64})['"]""")
# Chiamata runtime nei due dialetti: Runtime::fragment(  /  _vc.fragment(
_FRAG_CALL_PREFIX = r"(?:Runtime::|_vc\.)fragment"


def _has_core_call(text: str) -> bool:
    return "Runtime::fragment(" in text or "_vc.fragment(" in text


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _read_source_text(path: Path) -> str:
    """Legge un SORGENTE del cliente in modo tollerante. I marker che cerchiamo
    (tag esadecimale di paternità, chiamate ``fragment``) sono ASCII: un sorgente
    legacy non-UTF8 (es. PHP in cp1252/latin-1) NON deve far crashare il watcher
    né generare falsi positivi → si decodifica con ``errors="replace"``."""
    try:
        return path.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return ""


def load_manifest(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _expected_fragments(locate, payload_files: list[str]) -> list[tuple[str, str, int]]:
    out: list[tuple[str, str, int]] = []
    for rel in payload_files:
        p = locate(rel)
        if p is None or not p.is_file():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        module = data.get("module_id", "")
        for frag_id, frag in (data.get("fragments") or {}).items():
            out.append((module, frag_id, int(frag.get("ck_version", 0))))
    return out


def verify(root, manifest: dict) -> list[dict]:
    """Confronta lo stato su disco col manifest. Ritorna la lista (minima) di eventi.

    ``root`` può essere una singola directory o una **lista di alberi di ricerca**:
    ogni file del manifest è localizzato autonomamente (vedi ``locate.FileLocator``),
    così il monitoraggio funziona con qualsiasi layout del cliente — anche con i
    file distribuiti su cartelle diverse (es. app PHP + bot Python separati).
    """
    files: dict[str, str] = manifest.get("files", {})
    tag: str = manifest.get("entanglement_tag", "")
    events: list[dict] = []

    payload_files = [p for p in files if p.startswith("payloads/")]
    source_files = [p for p in files if not p.startswith("payloads/")]

    roots = list(root) if isinstance(root, (list, tuple)) else [root]
    locate = FileLocator(roots, list(files.keys())).locate

    # (a) integrità dei payload cifrati: devono essere byte-identici.
    for rel in payload_files:
        p = locate(rel)
        if p is None or not p.is_file():
            events.append({"path_relativo": rel, "tipo_evento": "payload_missing"})
            continue
        observed = sha256_file(p)
        if observed != files[rel]:
            events.append({"path_relativo": rel, "tipo_evento": "payload_mismatch",
                           "expected_hash": files[rel], "observed_hash": observed})

    # Testo concatenato dei sorgenti presenti (per ricerche di presenza).
    present_sources: dict[str, Path] = {}
    for rel in source_files:
        p = locate(rel)
        if p is not None and p.is_file():
            present_sources[rel] = p
    joined = ""
    for p in present_sources.values():
        joined += _read_source_text(p) + "\n"

    # (b) attribuzione (102-quinquies): nei sorgenti che contengono il core deve
    #     esserci VAULTCODE_RIGHTS_TAG e deve combaciare col manifest.
    for rel, p in present_sources.items():
        text = _read_source_text(p)
        if not _has_core_call(text):
            continue  # file senza core protetto: non si pretende l'header
        m = _RIGHTS_RE.search(text)
        if m is None:
            events.append({"path_relativo": rel, "tipo_evento": "attribution_removed"})
        elif tag and m.group(1).lower() != tag.lower():
            events.append({"path_relativo": rel, "tipo_evento": "attribution_mismatch",
                           "expected_hash": tag, "observed_hash": m.group(1)})

    # (c) core: ogni frammento atteso deve avere la sua chiamata runtime nei sorgenti.
    # Il 4° argomento (loop → memo, es. `, true`) è opzionale: la regex lo tollera.
    for module, frag, ck in _expected_fragments(locate, payload_files):
        pat = re.compile(_FRAG_CALL_PREFIX + r"\(\s*'" + re.escape(module) + r"'\s*,\s*'"
                         + re.escape(frag) + r"'\s*,\s*" + str(ck) + r"\b")
        if not pat.search(joined):
            events.append({"path_relativo": f"{module}/{frag}", "tipo_evento": "core_fragment_removed"})

    return events


def _installed_client_lib_version(root: Path) -> str:
    rt = root / "Runtime.php"
    if rt.is_file():
        m = re.search(r"const\s+VERSION\s*=\s*'([^']+)'",
                      rt.read_text(encoding="utf-8", errors="replace"))
        return m.group(1) if m else ""
    return ""


def verify_client_lib(client_lib_dir, manifest: dict) -> list[dict]:
    """Verifica la LIBRERIA CLIENT (runtime immutabile) contro gli hash canonici
    del manifest (``client_lib``). Modificare Runtime.php → mismatch → segnale.

    A differenza del layer libero del cliente, la libreria NON va modificata: qui
    il confronto è byte-identico. Eventi:
      client_lib_missing  → un file della libreria è stato rimosso
      client_lib_mismatch → un file della libreria è stato alterato

    VERSION-AWARE: se la libreria installata ha una VERSIONE diversa da quella di
    riferimento nel manifest (es. dopo un auto-update legittimo), il confronto
    byte-identico è atteso fallire → si SALTA (nessun falso positivo). Si verifica
    solo quando le versioni coincidono (lì un hash diverso = manomissione reale).
    """
    expected: dict = manifest.get("client_lib") or {}
    if not expected:
        return []
    root = Path(client_lib_dir)
    baseline_ver = str(manifest.get("client_lib_version") or "")
    installed_ver = _installed_client_lib_version(root)
    if baseline_ver and installed_ver and installed_ver != baseline_ver:
        return []  # versione diversa (update legittimo) → niente cross-check sugli hash
    events: list[dict] = []
    for name, want in sorted(expected.items()):
        p = root / name
        if not p.is_file():
            events.append({"path_relativo": f"client-lib/{name}", "tipo_evento": "client_lib_missing"})
            continue
        got = sha256_file(p)
        if got != want:
            events.append({"path_relativo": f"client-lib/{name}", "tipo_evento": "client_lib_mismatch",
                           "expected_hash": want, "observed_hash": got})
    return events

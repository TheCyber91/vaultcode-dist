"""Risoluzione AUTONOMA dei percorsi dei file del manifest.

Problema: il manifest elenca i file dell'opera con path RELATIVI (es.
``payloads/orders.vaultpayload.json`` o ``modules/x/core.php``), ma il cliente è
libero di disporre i file dove vuole sul proprio sistema, anche su **alberi
diversi** (es. l'app PHP in una cartella, i bot Python in un'altra). Un watcher
che cercasse ogni file solo in ``root/<rel>`` darebbe falsi ``*_missing`` appena
il layout reale non combacia col manifest.

Soluzione: dato uno o più **alberi di ricerca**, il locator trova ogni file del
manifest ovunque sia, con questa precedenza:
  1. percorso esatto ``root/<rel>`` (veloce, identico al comportamento storico);
  2. altrimenti indicizza ricorsivamente gli alberi e risolve per
     **suffisso del path relativo** (il più specifico) e, in mancanza, per
     **basename univoco**.

Confini (INVARIANTE §3/§9 — dati minimi, mai il sistema del cliente):
  - si indicizzano SOLO i file il cui basename compare nel manifest (l'opera
    protetta); ogni altro file del cliente è ignorato e mai letto;
  - il locator localizza, non legge: la lettura/hash la fa ``verify`` solo sui
    file effettivamente attesi.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

# Cartelle rumorose da NON attraversare: non contengono mai l'opera protetta e
# farebbero esplodere la scansione su progetti reali.
_PRUNE = {".git", ".hg", ".svn", "node_modules", "vendor", "__pycache__",
          ".venv", "venv", ".idea", ".vscode", "dist", "build", ".cache"}


class FileLocator:
    """Localizza i file del manifest su uno o più alberi di ricerca.

    L'indice ricorsivo è costruito **pigramente** al primo file non trovato al
    percorso esatto: nel caso comune (layout = manifest, un solo albero) non si
    paga alcuna scansione e il comportamento è identico a ``root/<rel>``.
    """

    def __init__(self, roots, manifest_rels) -> None:
        self.roots = [Path(r) for r in roots if str(r)]
        # Solo i basename attesi: l'indice non cataloga altro del cliente.
        self._wanted = {PurePosixPath(r.replace("\\", "/")).name for r in manifest_rels}
        self._index: dict[str, list[Path]] | None = None
        self._cache: dict[str, Path | None] = {}

    # --- ricerca esatta (fast path, retro-compatibile) ----------------------
    def _exact(self, rel: str) -> Path | None:
        relp = rel.replace("\\", "/")
        for root in self.roots:
            p = root / relp
            if p.is_file():
                return p
        return None

    # --- indice ricorsivo (costruito una sola volta, on-demand) --------------
    def _build_index(self) -> None:
        idx: dict[str, list[Path]] = {}
        for root in self.roots:
            if not root.is_dir():
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in _PRUNE]
                for fn in filenames:
                    if fn in self._wanted:
                        idx.setdefault(fn, []).append(Path(dirpath) / fn)
        self._index = idx

    def locate(self, rel: str) -> Path | None:
        """Percorso reale del file di manifest ``rel`` (o None se assente)."""
        if rel in self._cache:
            return self._cache[rel]
        p = self._exact(rel)
        if p is None:
            if self._index is None:
                self._build_index()
            relposix = rel.replace("\\", "/")
            name = PurePosixPath(relposix).name
            cands = self._index.get(name, []) if self._index else []
            if len(cands) == 1:
                p = cands[0]
            elif len(cands) > 1:
                # Disambigua: preferisci chi termina col path relativo del
                # manifest; a parità, il percorso più corto (deterministico).
                suffix = [c for c in cands if c.as_posix().endswith(relposix)]
                pool = suffix or cands
                p = sorted(pool, key=lambda c: (len(c.as_posix()), c.as_posix()))[0]
        self._cache[rel] = p
        return p

"""Risoluzione AUTONOMA dei percorsi dei file del manifest.

Problema: il manifest elenca i file dell'opera con path RELATIVI (es.
``payloads/orders.vaultpayload.json`` o ``modules/x/core.php``), ma il cliente è
libero di disporli dove vuole, anche su **alberi diversi** (app PHP in una cartella,
bot Python in altre — es. ``/opt/osm_bot`` e ``/var/www/html/sdi``). Un watcher che
cercasse ogni file solo in ``root/<rel>`` darebbe falsi ``*_missing`` appena il
layout reale non combacia.

Soluzione: il locator trova ogni file del manifest **ovunque sia**, con questa
precedenza:
  1. percorso esatto ``root/<rel>`` (veloce, identico al comportamento storico);
  2. indice ricorsivo degli **alberi di ricerca espliciti** (per suffisso/basename);
  3. **AUTODISCOVERY**: se ancora non trovato, il watcher *cerca da solo* l'albero
     di destinazione — indicizza gli alberi standard del server (``/var/www``,
     ``/opt``, ``/srv``, ``/usr/local``) e gli antenati dell'ancora (la cartella del
     manifest/config). Così non serve dirgli dove stanno i file.

Confini (INVARIANTE §3/§9 — dati minimi, mai il sistema del cliente):
  - si indicizzano SOLO i file il cui basename compare nel manifest (l'opera
    protetta); ogni altro file del cliente è ignorato e mai letto;
  - il locator localizza, non legge: la lettura/hash la fa ``verify`` solo sui file
    effettivamente attesi.
"""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath

# Cartelle rumorose da NON attraversare: non contengono mai l'opera protetta e
# farebbero esplodere la scansione su progetti reali.
_PRUNE = {".git", ".hg", ".svn", "node_modules", "vendor", "__pycache__",
          ".venv", "venv", ".idea", ".vscode", "dist", "build", ".cache",
          "cache", "proc", "sys", "dev", "tmp", "var/cache"}

# Alberi standard dei server dove vive il codice dei clienti (autodiscovery).
# Override con $VAULTCODE_SCAN_BASES (separati da os.pathsep).
_DEFAULT_BASES = ["/var/www", "/opt", "/srv", "/usr/local/share",
                  "/usr/local/lib", "/usr/local/bin"]


def _anchor_ancestors(anchor: str | None, levels: int = 4) -> list[str]:
    """Antenati della cartella dell'ancora (manifest/config): l'opera sta spesso
    sotto lo stesso albero di progetto della lib."""
    if not anchor:
        return []
    out = []
    d = os.path.dirname(os.path.abspath(anchor))
    for _ in range(levels):
        out.append(d)
        p = os.path.dirname(d)
        if p == d:
            break
        d = p
    return out


class FileLocator:
    """Localizza i file del manifest su alberi espliciti e, se serve, autodiscovery.

    Gli indici sono costruiti **pigramente**: nel caso comune (layout = manifest)
    si paga solo il fast-path ``root/<rel>``; l'indice ricorsivo e poi
    l'autodiscovery scattano solo quando un file non si trova prima.
    """

    def __init__(self, roots, manifest_rels, *, anchor: str | None = None,
                 autodiscover: bool = True) -> None:
        self.roots = [Path(r) for r in roots if str(r)]
        self._wanted = {PurePosixPath(str(r).replace("\\", "/")).name for r in manifest_rels}
        self._anchor = anchor
        self._autodiscover = autodiscover and os.environ.get("VAULTCODE_NO_AUTODISCOVER") not in ("1", "true", "yes")
        self._index: dict[str, list[Path]] = {}
        self._scanned: set[str] = set()       # dir già indicizzate (no doppioni)
        self._roots_indexed = False
        self._autodiscovered = False
        self._cache: dict[str, Path | None] = {}

    # --- ricerca esatta (fast path, retro-compatibile) ----------------------
    def _exact(self, rel: str) -> Path | None:
        relp = rel.replace("\\", "/")
        for root in self.roots:
            p = root / relp
            if p.is_file():
                return p
        return None

    # --- indicizzazione ricorsiva (incrementale) ----------------------------
    def _index_dirs(self, dirs) -> None:
        # genitori PRIMA dei figli: così una dir annidata in una già scansionata
        # viene saltata (niente walk doppi).
        resolved = []
        for d in dirs:
            try:
                resolved.append(Path(d).resolve())
            except (OSError, ValueError):
                continue
        for root in sorted(resolved, key=lambda r: len(str(r))):
            key = str(root)
            if key in self._scanned or not root.is_dir():
                continue
            # salta se già coperto da una dir antenata già scansionata
            if any(key.startswith(s + os.sep) for s in self._scanned):
                self._scanned.add(key)
                continue
            self._scanned.add(key)
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [x for x in dirnames if x not in _PRUNE and not x.startswith(".")]
                for fn in filenames:
                    if fn in self._wanted:
                        self._index.setdefault(fn, []).append(Path(dirpath) / fn)

    def _from_index(self, rel: str) -> Path | None:
        relposix = rel.replace("\\", "/")
        name = PurePosixPath(relposix).name
        cands = self._index.get(name, [])
        if not cands:
            return None
        if len(cands) == 1:
            return cands[0]
        suffix = [c for c in cands if c.as_posix().endswith(relposix)]
        pool = suffix or cands
        return sorted(pool, key=lambda c: (len(c.as_posix()), c.as_posix()))[0]

    def locate(self, rel: str) -> Path | None:
        """Percorso reale del file di manifest ``rel`` (o None se davvero assente)."""
        if rel in self._cache:
            return self._cache[rel]
        p = self._exact(rel)
        if p is None:
            if not self._roots_indexed:
                self._roots_indexed = True
                self._index_dirs(self.roots)
            p = self._from_index(rel)
        if p is None and self._autodiscover and not self._autodiscovered:
            # il watcher cerca DA SOLO l'albero: antenati dell'ancora + alberi server
            self._autodiscovered = True
            env = os.environ.get("VAULTCODE_SCAN_BASES")
            bases = env.split(os.pathsep) if env else (_anchor_ancestors(self._anchor) + _DEFAULT_BASES)
            self._index_dirs([b for b in bases if b and os.path.isdir(b)])
            p = self._from_index(rel)
        self._cache[rel] = p
        return p

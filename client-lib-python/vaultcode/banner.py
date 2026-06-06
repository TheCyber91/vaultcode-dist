"""Banner NON bloccante (INVARIANTE 1, art. 615-quinquies).

Emette un AVVISO quando un contesto non è verificato, ma lo script CONTINUA a
funzionare. Nessun blocco/uscita/eccezione propagata. Sink iniettabile (default:
logging su stderr; opzionale append su file). Parità con ``Banner.php``.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone

_log = logging.getLogger("vaultcode")


class Banner:
    def __init__(self, sink=None, log_file: str = ""):
        self._sink = sink
        self._log_file = log_file
        self._seen: set[str] = set()

    def _default_sink(self, msg: str) -> None:
        if self._log_file:
            try:
                with open(self._log_file, "a", encoding="utf-8") as fh:
                    fh.write(f"[{datetime.now(timezone.utc).isoformat()}] {msg}\n")
            except OSError:
                pass
        # sempre anche su logger/stderr, best-effort
        try:
            _log.warning(msg)
        except Exception:  # noqa: BLE001
            print(msg, file=sys.stderr)

    def notify(self, message: str) -> None:
        if message in self._seen:
            return
        self._seen.add(message)
        msg = f"[VaultCode] {message}"
        try:
            (self._sink or self._default_sink)(msg)
        except Exception:  # noqa: BLE001 - il banner non deve MAI rompere l'app
            pass
        # NB: nessun exit/raise. L'esecuzione prosegue.

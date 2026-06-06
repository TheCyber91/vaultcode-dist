"""Rilevazione anti-tamper (§11) — SOLO osservazione, mai reazione.

Rileva un debugger/ptrace agganciato al processo (Linux: TracerPid != 0 in
/proc/self/status). NON blocca, NON sabota: produce un segnale che il Runtime
invia come ALERT probatorio.

Scelta deliberata: NON si usa ``sys.gettrace()`` come segnale, perché coverage,
profiler, APM e debugger lo impostano legittimamente → genererebbe falsi
``debugger_rilevato`` (rumore negli alert dello studio). Si usa il solo TracerPid,
affidabile su Linux. Dove non applicabile (Windows/macOS) non emette nulla:
nessun falso positivo. Onestà (§3/§11): root aggira/spoofa; alza solo il costo.
"""

from __future__ import annotations

import os
import re


def tracer_pid_from_status(status_content: str) -> int:
    """Estrae TracerPid dal contenuto di /proc/self/status. 0 = nessun debugger."""
    m = re.search(r"^TracerPid:\s*(\d+)", status_content, re.MULTILINE)
    return int(m.group(1)) if m else 0


def detect() -> list[str]:
    """list di segnali (es. ['debugger_rilevato']); [] se nessuno."""
    status = "/proc/self/status"
    try:
        if os.path.isfile(status) and os.access(status, os.R_OK):
            with open(status, encoding="utf-8", errors="replace") as fh:
                if tracer_pid_from_status(fh.read()) > 0:
                    return ["debugger_rilevato"]
    except OSError:
        pass
    return []

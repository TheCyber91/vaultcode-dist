"""Costruzione del report di integrità — DATI MINIMI (§9, §6).

Trasmette solo: install_uuid, timestamp, e per ogni evento il path relativo, il
tipo e (per i payload) gli hash atteso/osservato. MAI il contenuto del codice.
"""

from __future__ import annotations


def build_report(*, install_uuid: str, events: list[dict], generated_at: str,
                 interval_min: int | None = None) -> dict:
    report = {
        "format": "vaultcode/integrity-report/v1",
        "install_uuid": install_uuid,
        "generated_at": generated_at,
        "ok": len(events) == 0,
        "events": events,  # già minimi (vedi verify.py)
    }
    # Intervallo di schedulazione (lo passa l'installer via --interval-min): il
    # server deriva la soglia di silenzio. Assente nei run manuali → default.
    if interval_min:
        report["interval_min"] = int(interval_min)
    return report

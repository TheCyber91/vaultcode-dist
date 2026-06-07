"""CLI del watcher: verifica l'integrità dell'opera protetta contro il manifest.

NON bloccante: non modifica nulla e non interrompe l'applicazione del cliente.
Produce un report (dati minimi) e, se configurato, lo invia all'autore.

Uso:
  vaultcode-watch --root ./app_protetta --manifest ./app_protetta/manifest.json \\
      [--out report.json] \\
      [--report-url https://...run.app --install-uuid <uuid> --install-secret <hex>]

Exit: 0 = nessuna alterazione; 2 = alterazioni rilevate (per alerting cron); il
codice cliente NON viene comunque toccato.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from vaultcode_watcher import report as report_mod
from vaultcode_watcher import sender, verify


def _run_update(args) -> int:
    """Auto-update (o update manuale forzato con --force). Mai bloccante."""
    from vaultcode_watcher import updater

    if not args.report_url:
        print("[update] serve --report-url", file=sys.stderr)
        return 2
    if not args.ed25519_public_key:
        print("[update] serve --ed25519-public-key (PEM della chiave pubblica autore)", file=sys.stderr)
        return 2
    try:
        pub = Path(args.ed25519_public_key).read_bytes()
    except OSError as exc:
        print(f"[update] chiave pubblica illeggibile: {exc}", file=sys.stderr)
        return 2

    targets = []
    if args.client_lib_dir:
        targets.append(("client-lib", args.client_lib_dir))
    if args.watcher_dir:
        targets.append(("watcher", args.watcher_dir))
    if not targets:
        print("[update] indica almeno --client-lib-dir e/o --watcher-dir", file=sys.stderr)
        return 2

    rc = 0
    for comp, tdir in targets:
        res = updater.update_component(args.report_url, comp, tdir, pub, force=args.force)
        status = res.get("status")
        if status == "updated":
            print(f"[update] {comp}: aggiornato {res.get('from')} -> {res.get('to')} ({res.get('files')} file)")
        elif status == "current":
            print(f"[update] {comp}: già aggiornato (v{res.get('version')})")
        else:
            print(f"[update] {comp}: ERRORE {res.get('error')}", file=sys.stderr)
            rc = 2
    return rc


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="vaultcode-watch")
    p.add_argument("--root", action="append", metavar="DIR",
                   help="directory dell'opera protetta (verifica). Ripetibile: più ALBERI "
                        "di ricerca. OPZIONALE: se omesso, il watcher cerca DA SOLO gli "
                        "alberi (autodiscovery: alberi standard del server + antenati del "
                        "manifest). Indicarlo serve solo a restringere/velocizzare la ricerca.")
    p.add_argument("--manifest", help="manifest.json di riferimento (verifica)")
    p.add_argument("--out", help="scrive il report JSON su questo file")
    p.add_argument("--client-lib-dir",
                   help="directory della libreria client PHP installata (la src/): "
                        "verifica che Runtime.php & co. non siano alterati; target dell'auto-update")
    p.add_argument("--report-url", help="key-server a cui inviare il report / scaricare gli update")
    p.add_argument("--install-uuid")
    p.add_argument("--interval-min", type=int, default=None,
                   help="intervallo (minuti) con cui questo watcher è SCHEDULATO. Lo imposta "
                        "l'installer: il server ne deriva la soglia di silenzio. Ometterlo nei "
                        "run manuali (resta la soglia di default generosa).")
    p.add_argument("--install-secret",
                   help="segreto per-installazione (hex) per la firma. PREFERIRE la variabile "
                        "d'ambiente VAULTCODE_INSTALL_SECRET: passarlo in riga di comando lo espone in 'ps'.")
    # --- auto-update delle risorse VaultCode ---
    p.add_argument("--update", action="store_true",
                   help="AGGIORNA le risorse VaultCode (client-lib e/o watcher) da bundle firmato")
    p.add_argument("--watcher-dir",
                   help="directory che CONTIENE vaultcode_watcher/ (target dell'auto-update del watcher)")
    p.add_argument("--ed25519-public-key",
                   help="file PEM della chiave pubblica dell'autore (verifica la firma dei bundle)")
    p.add_argument("--force", action="store_true",
                   help="riapplica l'update anche se la versione coincide (update manuale forzato)")
    p.add_argument("--auto-update", action="store_true",
                   help="durante la verifica, onora una richiesta di aggiornamento dell'autore "
                        "(coda comandi dallo studio); richiede --report-url/--install-secret/--ed25519-public-key")
    args = p.parse_args(argv)
    # Sicurezza: il segreto NON deve stare in argv (visibile in 'ps'). Se non passato
    # esplicitamente, si legge dall'ambiente (file env 600, systemd EnvironmentFile, ecc.).
    if not args.install_secret:
        args.install_secret = os.environ.get("VAULTCODE_INSTALL_SECRET") or None

    if args.update:
        return _run_update(args)

    if not args.manifest:
        p.error("--manifest è obbligatorio (tranne con --update)")

    manifest = verify.load_manifest(args.manifest)
    install_uuid = args.install_uuid or manifest.get("install_uuid", "")
    # --root opzionale: se assente, autodiscovery ancorata al manifest.
    events = verify.verify(args.root, manifest, anchor=args.manifest)
    if args.client_lib_dir:
        events += verify.verify_client_lib(args.client_lib_dir, manifest)
    rep = report_mod.build_report(
        install_uuid=install_uuid, events=events,
        generated_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        interval_min=args.interval_min,
    )

    if args.out:
        Path(args.out).write_text(json.dumps(rep, indent=2), encoding="utf-8")

    if events:
        print(f"[watcher] {len(events)} alterazione/i rilevata/e:")
        for e in events:
            print(f"  - {e['tipo_evento']}: {e['path_relativo']}")
    else:
        print("[watcher] integrità OK: nessuna alterazione del core/attribuzione.")

    if args.report_url and install_uuid and args.install_secret:
        try:
            resp = sender.send_report(args.report_url, install_uuid=install_uuid,
                                      install_secret_hex=args.install_secret, report=rep)
            print(f"[watcher] report inviato all'autore: {resp}")
        except Exception as exc:  # noqa: BLE001 - l'invio non deve far fallire il monitoraggio
            print(f"[watcher] invio report fallito (non bloccante): {exc}", file=sys.stderr)

    # Coda comandi: se l'autore ha richiesto un auto-update dallo studio, il
    # watcher lo legge dal /status FIRMATO e lo applica ora (pull, non push).
    if args.auto_update:
        _honor_update_request(args, install_uuid)

    return 2 if events else 0


def _honor_update_request(args, install_uuid: str) -> None:
    """Controlla la 'coda comandi' (update_requested nel /status firmato) e, se
    presente, forza l'auto-update di client-lib e/o watcher. Mai bloccante."""
    if not (args.report_url and install_uuid and args.install_secret and args.ed25519_public_key):
        return
    try:
        from vaultcode_watcher import updater
        pub = Path(args.ed25519_public_key).read_bytes()
        status = updater.fetch_status(args.report_url, install_uuid, args.install_secret, pub)
        if not status or not status.get("update_requested"):
            return
        print("[watcher] richiesta di aggiornamento dall'autore: applico...")
        targets = []
        if args.client_lib_dir:
            targets.append(("client-lib", args.client_lib_dir))
        if args.watcher_dir:
            targets.append(("watcher", args.watcher_dir))
        applied = False
        for comp, tdir in targets:
            res = updater.update_component(args.report_url, comp, tdir, pub, force=True)
            print(f"[watcher] {comp}: {res.get('status')} "
                  f"{res.get('to') or res.get('error') or ''}".rstrip())
            if res.get("status") == "updated":
                applied = True
        # Conferma al server → azzera la richiesta nello studio.
        if applied:
            updater.ack_update(args.report_url, install_uuid, args.install_secret)
            print("[watcher] richiesta di aggiornamento confermata (azzerata).")
    except Exception as exc:  # noqa: BLE001 - mai bloccante
        print(f"[watcher] auto-update su richiesta fallito (non bloccante): {exc}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())

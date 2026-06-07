#!/usr/bin/env bash
# =============================================================================
# VaultCode — installer one-command (VPS / server Linux, anche Docker)
# -----------------------------------------------------------------------------
# Installa in un colpo solo:
#   - libreria client PHP        (lib/src/*.php)         -> $APP/$LIBSUBDIR/src
#   - bootstrap.php (auto-init)  (lib/bootstrap.php)     -> $APP/$LIBSUBDIR
#   - payloads + manifest + config (dal pacchetto studio) -> $APP/$LIBSUBDIR
#   - estensione nativa .so      (match versione PHP, opzionale)
#   - watcher Python             (vaultcode_watcher)     -> $WATCHERDIR
#   - schedulazione watcher      (systemd timer ogni 2 min, fallback cron)
#   - self-test                  (un run del watcher + report)
#
# La libreria e il watcher (GENERICI, senza segreti) si scaricano dal repo
# pubblico "vaultcode-dist". Il pacchetto per-installazione (payloads/manifest/
# config, CON i segreti) lo fornisci tu (download dallo studio).
#
# NON modifica la logica dell'app del cliente. Nessun meccanismo distruttivo
# (INVARIANTE 1). BOOTSTRAP AUTOMATICO: i file protetti includono da soli
# $LIBSUBDIR/bootstrap.php (lo cercano risalendo da __DIR__) → il runtime si
# inizializza SENZA toccare core.php/l'entrypoint (sopravvive agli update).
# (--insert-bootstrap <file> resta come opzione per agganciarlo a un entrypoint.)
#
# Uso tipico:
#   curl -fsSL https://raw.githubusercontent.com/TheCyber91/vaultcode-dist/main/install.sh \
#     | sudo bash -s -- --package ./vaultcode-progetto.zip --app /var/www/html
#
# Disinstalla:
#   sudo bash install.sh --uninstall --app /var/www/html
# =============================================================================
set -euo pipefail

# --- Sorgente dei componenti generici (repo pubblico) ------------------------
DIST_REPO="${VAULTCODE_DIST_REPO:-TheCyber91/vaultcode-dist}"
DIST_REF="${VAULTCODE_DIST_REF:-main}"

# --- Default (override via flag) ---------------------------------------------
APP=""
PACKAGE=""
LIBSUBDIR="lib/vaultcode"
WATCHERDIR="/opt/vaultcode"
INTERVAL_MIN=2
WEB_USER=""
INSTALL_NATIVE=1
DO_SCHEDULE=1
CLOUDRUN=0
INSERT_BOOTSTRAP=""
DO_UNINSTALL=0
PURGE=0
LOCAL_DIST=""        # usa una cartella dist locale invece di scaricarla (dev/offline)

KEY_SERVER_URL=""
INSTALL_UUID=""
INSTALL_SECRET=""

log()  { printf '\033[1;36m[vaultcode]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[vaultcode][!]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[vaultcode][x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,40p' "$0" 2>/dev/null || true
  cat <<EOF

Opzioni:
  --package PATH|URL   pacchetto studio (.zip o cartella) con payloads/ manifest.json vaultcode.config.json
  --app DIR            web root dell'app del cliente (es. /var/www/html)   [obbligatorio]
  --lib-subdir DIR     sottocartella libreria sotto --app                  (default: $LIBSUBDIR)
  --watcher-dir DIR    dove installare il watcher                          (default: $WATCHERDIR)
  --interval-min N     ogni quanti minuti gira il watcher                  (default: $INTERVAL_MIN)
  --web-user USER      utente del web server per i permessi cache         (default: auto)
  --ref REF            branch/tag del repo dist da scaricare              (default: $DIST_REF)
  --local-dist DIR     usa una cartella dist locale (no download)
  --no-native          non installare l'estensione nativa .so
  --no-schedule        non schedulare il watcher
  --cloudrun           modalità Cloud Run (niente scheduler; update via redeploy)
  --insert-bootstrap F inserisce la riga Runtime::init nel file di bootstrap F (con marcatore)
  --uninstall          rimuove schedulazione + watcher (lib/config restano salvo --purge)
  --purge              con --uninstall: rimuove anche libreria, config e segreto
  -h, --help           questo aiuto
EOF
}

# --- Parse argomenti ---------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --package)          PACKAGE="${2:-}"; shift 2;;
    --app)              APP="${2:-}"; shift 2;;
    --lib-subdir)       LIBSUBDIR="${2:-}"; shift 2;;
    --watcher-dir)      WATCHERDIR="${2:-}"; shift 2;;
    --interval-min)     INTERVAL_MIN="${2:-}"; shift 2;;
    --web-user)         WEB_USER="${2:-}"; shift 2;;
    --ref)              DIST_REF="${2:-}"; shift 2;;
    --local-dist)       LOCAL_DIST="${2:-}"; shift 2;;
    --no-native)        INSTALL_NATIVE=0; shift;;
    --no-schedule)      DO_SCHEDULE=0; shift;;
    --cloudrun)         CLOUDRUN=1; shift;;
    --insert-bootstrap) INSERT_BOOTSTRAP="${2:-}"; shift 2;;
    --uninstall)        DO_UNINSTALL=1; shift;;
    --purge)            PURGE=1; shift;;
    -h|--help)          usage; exit 0;;
    *) err "opzione sconosciuta: $1 (usa --help)";;
  esac
done

[ "$(id -u)" -eq 0 ] || err "esegui come root (sudo): servono permessi per estensione/systemd/cron."
[ -n "$APP" ] || err "manca --app (web root dell'app)."
LIBDIR="$APP/$LIBSUBDIR"

# --- helper: leggere un campo dalla config JSON (jq -> python3 -> grep) -------
json_get() { # $1=file $2=key
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg k "$2" '.[$k] // empty' "$1"
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2],"") or "")' "$1" "$2"
  else
    grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)".*/\1/'
  fi
}

# =============================================================================
# DISINSTALLAZIONE
# =============================================================================
if [ "$DO_UNINSTALL" -eq 1 ]; then
  log "Disinstallazione…"
  # trova l'uuid dalla config installata (se c'è) per individuare unit/env
  UUID=""
  [ -f "$LIBDIR/vaultcode.config.json" ] && UUID="$(json_get "$LIBDIR/vaultcode.config.json" install_uuid)"
  if command -v systemctl >/dev/null 2>&1 && [ -n "$UUID" ]; then
    systemctl disable --now "vaultcode-watch@${UUID}.timer" 2>/dev/null || true
    rm -f "/etc/systemd/system/vaultcode-watch@.service" "/etc/systemd/system/vaultcode-watch@.timer" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
  fi
  [ -n "$UUID" ] && rm -f "/etc/cron.d/vaultcode-${UUID}" 2>/dev/null || true
  log "schedulazione rimossa."
  if [ "$PURGE" -eq 1 ]; then
    rm -rf "$WATCHERDIR" 2>/dev/null || true
    [ -n "$UUID" ] && rm -f "/etc/vaultcode/${UUID}.env" 2>/dev/null || true
    rm -rf "$LIBDIR" 2>/dev/null || true
    warn "PURGE: rimossi watcher, segreto e libreria. (payloads/manifest/config inclusi)"
  else
    log "watcher e libreria lasciati al loro posto (usa --purge per rimuoverli)."
  fi
  log "Fatto."
  exit 0
fi

[ -n "$PACKAGE" ] || err "manca --package (pacchetto studio con payloads/manifest/config)."

# =============================================================================
# 0) Pre-flight
# =============================================================================
command -v php >/dev/null 2>&1 || warn "php non trovato: la libreria gira solo dentro un'app PHP (8.1/8.2/8.3)."
command -v python3 >/dev/null 2>&1 || err "python3 non trovato: serve per il watcher (3.11+)."

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# =============================================================================
# 1) Risolvi il pacchetto per-installazione (zip/url/cartella)
# =============================================================================
PKGDIR=""
case "$PACKAGE" in
  http://*|https://*) log "scarico il pacchetto…"; curl -fsSL "$PACKAGE" -o "$WORK/pkg.zip"; PACKAGE="$WORK/pkg.zip";;
esac
if [ -d "$PACKAGE" ]; then
  PKGDIR="$PACKAGE"
elif [ -f "$PACKAGE" ]; then
  mkdir -p "$WORK/pkg"; ( cd "$WORK/pkg" && unzip -oq "$PACKAGE" ); PKGDIR="$WORK/pkg"
else
  err "pacchetto non trovato: $PACKAGE"
fi
[ -f "$PKGDIR/manifest.json" ] || err "il pacchetto non contiene manifest.json"
[ -d "$PKGDIR/payloads" ]     || err "il pacchetto non contiene payloads/"
[ -f "$PKGDIR/vaultcode.config.json" ] || err "il pacchetto non contiene vaultcode.config.json (config per-installazione)"

# leggi i campi che servono allo scheduler/self-test
KEY_SERVER_URL="$(json_get "$PKGDIR/vaultcode.config.json" key_server_url)"
INSTALL_UUID="$(json_get "$PKGDIR/vaultcode.config.json" install_uuid)"
INSTALL_SECRET="$(json_get "$PKGDIR/vaultcode.config.json" install_secret_hex)"
[ -n "$INSTALL_UUID" ] || err "config priva di install_uuid"
[ -n "$KEY_SERVER_URL" ] || warn "config priva di key_server_url: il watcher non potrà riportare."

# =============================================================================
# 2) Procura libreria + watcher (repo dist pubblico, o cartella locale)
# =============================================================================
if [ -n "$LOCAL_DIST" ]; then
  [ -d "$LOCAL_DIST/lib/src" ] || err "--local-dist non valido (manca lib/src)"
  DIST="$LOCAL_DIST"
else
  log "scarico libreria+watcher da $DIST_REPO@$DIST_REF…"
  curl -fsSL "https://codeload.github.com/$DIST_REPO/tar.gz/refs/heads/$DIST_REF" -o "$WORK/dist.tgz" \
    || err "download del repo dist fallito ($DIST_REPO@$DIST_REF)"
  mkdir -p "$WORK/dist"; tar -xzf "$WORK/dist.tgz" -C "$WORK/dist" --strip-components=1
  DIST="$WORK/dist"
fi
[ -d "$DIST/lib/src" ] || err "dist senza lib/src"
[ -d "$DIST/watcher/vaultcode_watcher" ] || err "dist senza watcher/vaultcode_watcher"

# utente web (per i permessi della cache)
if [ -z "$WEB_USER" ]; then
  for u in www-data apache nginx http; do id "$u" >/dev/null 2>&1 && WEB_USER="$u" && break; done
fi
[ -n "$WEB_USER" ] || WEB_USER="root"

# =============================================================================
# 3) Installa libreria + payloads + manifest + config
# =============================================================================
log "installo la libreria in $LIBDIR…"
mkdir -p "$LIBDIR"
rm -rf "$LIBDIR/src"; cp -r "$DIST/lib/src" "$LIBDIR/src"
# bootstrap.php: i file protetti lo cercano risalendo da __DIR__ e lo includono da
# soli → il runtime si inizializza SENZA toccare l'entrypoint (core.php & co.).
if [ -f "$DIST/lib/bootstrap.php" ]; then cp "$DIST/lib/bootstrap.php" "$LIBDIR/bootstrap.php"; fi
rm -rf "$LIBDIR/payloads"; cp -r "$PKGDIR/payloads" "$LIBDIR/payloads"
cp "$PKGDIR/manifest.json" "$LIBDIR/manifest.json"
cp "$PKGDIR/vaultcode.config.json" "$LIBDIR/vaultcode.config.json"
mkdir -p "$LIBDIR/cache"
chown -R "$WEB_USER":"$WEB_USER" "$LIBDIR/cache" 2>/dev/null || true
chmod 600 "$LIBDIR/vaultcode.config.json"

# patcha i path assoluti nella config (payload_dir/cache_path/status_cache_path)
if command -v python3 >/dev/null 2>&1; then
  python3 - "$LIBDIR" <<'PY'
import json, sys, os
libdir = sys.argv[1]
cfg = os.path.join(libdir, "vaultcode.config.json")
c = json.load(open(cfg))
c["payload_dir"]       = os.path.join(libdir, "payloads")
c["cache_path"]        = os.path.join(libdir, "cache", "ck_cache.json")
c["status_cache_path"] = os.path.join(libdir, "cache", "status_cache.json")
json.dump(c, open(cfg, "w"), indent=2)
print("[vaultcode] config: path assoluti impostati")
PY
  chmod 600 "$LIBDIR/vaultcode.config.json"
fi

# =============================================================================
# 3-bis) Requisiti dei moduli NATIVI (Nuitka): il .so è legato a versione Python +
# piattaforma. Verifica la compatibilità e, se manca, INSTALLA il Python richiesto.
# =============================================================================
if command -v python3 >/dev/null 2>&1; then
  NMAN="$LIBDIR/manifest.json"
  NEED_PY="$(python3 -c 'import json,sys;print((json.load(open(sys.argv[1])).get("native") or {}).get("python",""))' "$NMAN" 2>/dev/null || true)"
  if [ -n "$NEED_PY" ]; then
    NEED_PLAT="$(python3 -c 'import json,sys;print((json.load(open(sys.argv[1])).get("native") or {}).get("platform",""))' "$NMAN" 2>/dev/null || true)"
    HAVE_PLAT="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
    log "moduli nativi nel pacchetto → richiesto Python ${NEED_PY} / ${NEED_PLAT:-?}"
    if [ -n "$NEED_PLAT" ] && [ "$NEED_PLAT" != "$HAVE_PLAT" ]; then
      err "moduli nativi per ${NEED_PLAT}, ma questo host è ${HAVE_PLAT}: serve un pacchetto ricompilato per questa piattaforma."
    fi
    if command -v "python${NEED_PY}" >/dev/null 2>&1; then
      log "Python ${NEED_PY} già presente: $(command -v python${NEED_PY})"
    else
      warn "Python ${NEED_PY} assente → installo…"
      if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y >/dev/null 2>&1 || true
        if ! apt-get install -y "python${NEED_PY}" "python${NEED_PY}-venv" >/dev/null 2>&1; then
          # Ubuntu datati: serve il PPA deadsnakes
          apt-get install -y software-properties-common >/dev/null 2>&1 || true
          add-apt-repository -y ppa:deadsnakes/ppa >/dev/null 2>&1 || true
          apt-get update -y >/dev/null 2>&1 || true
          apt-get install -y "python${NEED_PY}" "python${NEED_PY}-venv" >/dev/null 2>&1 \
            || warn "non sono riuscito a installare Python ${NEED_PY}: installalo a mano (i moduli nativi lo richiedono)."
        fi
      else
        warn "gestore pacchetti non apt: installa Python ${NEED_PY} a mano (i moduli nativi lo richiedono)."
      fi
      command -v "python${NEED_PY}" >/dev/null 2>&1 && log "Python ${NEED_PY} installato: $(command -v python${NEED_PY})"
    fi
    # verifica che il client + il .so si importino col Python richiesto
    if command -v "python${NEED_PY}" >/dev/null 2>&1; then
      "python${NEED_PY}" -c 'import cryptography' 2>/dev/null \
        || "python${NEED_PY}" -m pip install --quiet cryptography 2>/dev/null || true
      warn "Esegui i tuoi script/bot Python con 'python${NEED_PY}' (carica il modulo nativo + la libreria vaultcode)."
    fi
  fi
fi

# =============================================================================
# 4) Estensione nativa (opzionale, match versione PHP)
# =============================================================================
if [ "$INSTALL_NATIVE" -eq 1 ] && command -v php >/dev/null 2>&1; then
  PHPV="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || true)"
  SO="$DIST/lib/native/dist/webdl_protect-php${PHPV}-linux-x86_64.so"
  if [ -n "$PHPV" ] && [ -f "$SO" ]; then
    EXTDIR="$(php -i 2>/dev/null | sed -n 's/^extension_dir => //p' | awk '{print $1}')"
    if [ -n "$EXTDIR" ] && [ -d "$EXTDIR" ]; then
      cp "$SO" "$EXTDIR/webdl_protect.so"
      INIDIR="/etc/php/${PHPV}/mods-available"
      if [ -d "$INIDIR" ]; then
        echo "extension=webdl_protect.so" > "$INIDIR/webdl_protect.ini"
        command -v phpenmod >/dev/null 2>&1 && phpenmod webdl_protect 2>/dev/null || true
      else
        # distro non-Debian: prova la conf.d generica
        CONFD="$(php -i 2>/dev/null | sed -n 's/^Scan this dir for additional .ini files => //p' | head -1)"
        [ -n "$CONFD" ] && [ -d "$CONFD" ] && echo "extension=webdl_protect.so" > "$CONFD/webdl_protect.ini" || true
      fi
      systemctl reload "php${PHPV}-fpm" 2>/dev/null || systemctl reload apache2 2>/dev/null || true
      php -m 2>/dev/null | grep -qi webdl_protect && log "estensione nativa attiva (php $PHPV)" \
        || warn "estensione copiata ma non ancora attiva: ricarica il web server."
    else
      warn "extension_dir non rilevato: salto la nativa (fallback puro-PHP, non bloccante)."
    fi
  else
    warn "nessuna .so per php ${PHPV:-?}: fallback puro-PHP (non bloccante)."
  fi
fi

# =============================================================================
# 5) Watcher + chiave pubblica + dipendenza cryptography
# =============================================================================
log "installo il watcher in $WATCHERDIR…"
mkdir -p "$WATCHERDIR"
rm -rf "$WATCHERDIR/vaultcode_watcher"; cp -r "$DIST/watcher/vaultcode_watcher" "$WATCHERDIR/vaultcode_watcher"
# chiave pubblica per verificare i bundle di auto-update: dalla config
PUBPEM="$(json_get "$LIBDIR/vaultcode.config.json" ed25519_public_key_pem)"
if [ -n "$PUBPEM" ]; then
  printf '%b' "$PUBPEM" > "$WATCHERDIR/vaultcode_pub.pem"
elif [ -f "$DIST/vaultcode_pub.pem" ]; then
  cp "$DIST/vaultcode_pub.pem" "$WATCHERDIR/vaultcode_pub.pem"
else
  warn "chiave pubblica non trovata nella config: l'auto-update sarà disattivato."
fi
# cryptography (solo per l'auto-update / firma)
if ! python3 -c 'import cryptography' 2>/dev/null; then
  log "installo python 'cryptography'…"
  python3 -m pip install --quiet cryptography 2>/dev/null \
    || pip3 install --quiet cryptography 2>/dev/null \
    || warn "pip non disponibile: il watcher funziona, ma senza auto-update finché non installi 'cryptography'."
fi

# =============================================================================
# 6) Schedulazione (systemd timer ogni N min, fallback cron)
# =============================================================================
PUBARG=""
[ -f "$WATCHERDIR/vaultcode_pub.pem" ] && PUBARG="--auto-update --ed25519-public-key $WATCHERDIR/vaultcode_pub.pem"
# NB: il segreto NON è in riga di comando (sarebbe visibile in 'ps'): il watcher
# lo legge da $VAULTCODE_INSTALL_SECRET (file env 600 / systemd EnvironmentFile).
# --interval-min comunica al server la cadenza schedulata: la soglia di silenzio
# viene auto-derivata (≈4×) → sempre coerente con il cron, niente falsi positivi.
WCMD="python3 -m vaultcode_watcher.cli \
--root $APP --manifest $LIBDIR/manifest.json \
--client-lib-dir $LIBDIR/src --watcher-dir $WATCHERDIR \
--report-url $KEY_SERVER_URL --install-uuid $INSTALL_UUID \
--interval-min $INTERVAL_MIN $PUBARG"

# segreto in file env 600 (MAI nel crontab/unit in chiaro)
mkdir -p /etc/vaultcode
ENVF="/etc/vaultcode/${INSTALL_UUID}.env"
umask 077; printf 'VAULTCODE_INSTALL_SECRET=%s\n' "$INSTALL_SECRET" > "$ENVF"; chmod 600 "$ENVF"
mkdir -p /var/log/vaultcode

if [ "$CLOUDRUN" -eq 1 ]; then
  warn "modalità Cloud Run: NIENTE scheduler (FS immutabile). Aggiornamenti = redeploy immagine."
  warn "Ricorda nello studio: ambiente di deploy = Cloud Run (niente check 'watcher silente')."
elif [ "$DO_SCHEDULE" -eq 0 ]; then
  warn "schedulazione saltata (--no-schedule). Comando watcher:"; echo "  $WCMD"
elif command -v systemctl >/dev/null 2>&1; then
  log "schedulo via systemd timer (ogni ${INTERVAL_MIN} min)…"
  cat > /etc/systemd/system/vaultcode-watch@.service <<UNIT
[Unit]
Description=VaultCode watcher (%i)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
EnvironmentFile=/etc/vaultcode/%i.env
WorkingDirectory=$WATCHERDIR
ExecStart=/usr/bin/env $WCMD
UNIT
  cat > /etc/systemd/system/vaultcode-watch@.timer <<UNIT
[Unit]
Description=VaultCode watcher timer (%i)
[Timer]
OnBootSec=1min
OnUnitActiveSec=${INTERVAL_MIN}min
AccuracySec=15s
Persistent=true
[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now "vaultcode-watch@${INSTALL_UUID}.timer"
  log "timer attivo: vaultcode-watch@${INSTALL_UUID}.timer"
else
  log "systemd assente → schedulo via cron (*/${INTERVAL_MIN})…"
  cat > "/etc/cron.d/vaultcode-${INSTALL_UUID}" <<CRON
SHELL=/bin/bash
*/${INTERVAL_MIN} * * * * root set -a; . $ENVF; cd $WATCHERDIR && $WCMD >> /var/log/vaultcode/${INSTALL_UUID}.log 2>&1
CRON
  chmod 644 "/etc/cron.d/vaultcode-${INSTALL_UUID}"
  log "cron installato: /etc/cron.d/vaultcode-${INSTALL_UUID}"
fi

# =============================================================================
# 7) Self-test (un run del watcher subito)
# =============================================================================
log "self-test: eseguo il watcher una volta…"
set +e
( cd "$WATCHERDIR" && VAULTCODE_INSTALL_SECRET="$INSTALL_SECRET" \
  python3 -m vaultcode_watcher.cli --root "$APP" --manifest "$LIBDIR/manifest.json" \
  --client-lib-dir "$LIBDIR/src" --watcher-dir "$WATCHERDIR" \
  --report-url "$KEY_SERVER_URL" --install-uuid "$INSTALL_UUID" --interval-min "$INTERVAL_MIN" )
ST=$?
set -e
[ "$ST" -eq 0 ] && log "self-test OK." || warn "self-test ha restituito codice $ST (controlla i log)."

# =============================================================================
# 8) Promemoria finali (bootstrap + studio)
# =============================================================================
BOOTLINE="require '$LIBDIR/src/Runtime.php'; \\VaultCode\\Runtime::init(\\VaultCode\\Config::fromJsonFile('$LIBDIR/vaultcode.config.json'));"
if [ -n "$INSERT_BOOTSTRAP" ] && [ -f "$INSERT_BOOTSTRAP" ]; then
  if grep -q "VaultCode\\\\Runtime::init" "$INSERT_BOOTSTRAP"; then
    log "bootstrap già presente in $INSERT_BOOTSTRAP"
  else
    cp "$INSERT_BOOTSTRAP" "$INSERT_BOOTSTRAP.vcbak"
    printf '\n// >>> VaultCode bootstrap (non rimuovere)\n%s\n// <<< VaultCode\n' "$BOOTLINE" >> "$INSERT_BOOTSTRAP"
    log "bootstrap inserito in $INSERT_BOOTSTRAP (backup .vcbak)"
  fi
fi

cat <<EOF

============================================================
 VaultCode installato.
============================================================
 App:        $APP
 Libreria:   $LIBDIR/src
 Payloads:   $LIBDIR/payloads
 Config:     $LIBDIR/vaultcode.config.json  (chmod 600)
 Watcher:    $WATCHERDIR  (ogni ${INTERVAL_MIN} min)
 Segreto:    $ENVF  (chmod 600)
 Bootstrap:  $LIBDIR/bootstrap.php  (AUTO — incluso dai file protetti)

 BOOTSTRAP AUTOMATICO: i file protetti includono da soli $LIBDIR/bootstrap.php
 (lo cercano risalendo le cartelle). NON serve toccare core.php / l'entrypoint del
 gestionale → la protezione sopravvive agli update. (Opzionale: --insert-bootstrap
 <file> per agganciarlo anche a un entrypoint, ma di norma non serve.)

 NELLO STUDIO (pagina progetto → specifiche):
   - ambiente di deploy = VPS / server (o Docker)
   - soglia silenzio watcher: lascia VUOTO → è AUTO-derivata dalla cadenza del cron
     (${INTERVAL_MIN} min → soglia ~$((INTERVAL_MIN * 4)) min). Il distacco del watcher
     viene rilevato in pochi minuti senza falsi positivi. Imposta un valore solo per forzare un override.

 Verifiche:
   - badge ⚠ si auto-inietta se l'integrità non torna
   - nativo attivo?   php -m | grep webdl_protect
   - log watcher:     journalctl -u 'vaultcode-watch@*' -n 30   (o /var/log/vaultcode/${INSTALL_UUID}.log)
EOF

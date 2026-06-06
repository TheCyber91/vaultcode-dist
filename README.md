# VaultCode — installer one-command

`install.sh` installa l'intera protezione su un **VPS / server Linux** (anche
Docker self-hosted) in un solo comando: libreria PHP, payloads/manifest/config,
estensione nativa, watcher e **schedulazione automatica** (systemd timer ogni
2 min, fallback cron), con self-test finale.

## Cosa serve
- Il **pacchetto per-installazione** dallo studio: `.zip` (o cartella) con
  `payloads/`, `manifest.json`, `vaultcode.config.json`.
- **PHP 8.1/8.2/8.3** e **Python 3.11+** sul server.
- Privilegi **root** (estensione PHP, systemd/cron).

> Libreria e watcher (generici, **senza segreti**) vengono scaricati dal repo
> pubblico `vaultcode-dist`. Il pacchetto con i segreti lo fornisci tu.

## Installazione
```bash
curl -fsSL https://raw.githubusercontent.com/TheCyber91/vaultcode-dist/main/install.sh \
  | sudo bash -s -- --package ./vaultcode-progetto.zip --app /var/www/html
```
Opzioni utili: `--interval-min N`, `--watcher-dir DIR`, `--no-native`,
`--cloudrun`, `--insert-bootstrap <file-bootstrap>`. Vedi `install.sh --help`.

## Dopo l'installazione
1. **Una riga** nel bootstrap dell'app (l'installer la stampa; NON la cabliamo
   noi per scelta anti-rimozione):
   ```php
   require '/var/www/html/lib/vaultcode/src/Runtime.php';
   \VaultCode\Runtime::init(\VaultCode\Config::fromJsonFile('/var/www/html/lib/vaultcode/vaultcode.config.json'));
   ```
2. Nello **studio** (pagina progetto → specifiche): `ambiente di deploy` = VPS/
   Docker, `soglia silenzio watcher` ≈ **4× l'intervallo** (es. watcher 2 min →
   soglia 8 min: distacco rilevato entro pochi minuti).

## Aggiornamenti
Il watcher schedulato fa **auto-update** firmato (onora anche il pulsante
"🔄 Forza aggiornamento" dello studio). Per re-installare/aggiornare la lib basta
ri-eseguire `install.sh` (idempotente).

## Disinstallazione
```bash
sudo bash install.sh --uninstall --app /var/www/html       # rimuove schedulazione+watcher
sudo bash install.sh --uninstall --purge --app /var/www/html  # rimuove anche lib/config/segreto
```

## Cloud Run
Su Cloud Run **non** si usa l'installer/watcher: FS immutabile, niente cron.
Includi la lib nell'immagine, aggiorna con un **redeploy**, e nello studio imposta
`ambiente di deploy = Cloud Run`. Vedi `docs/INTEGRAZIONE-DEPLOY-VPS.md` §9.

## Sicurezza
- `vaultcode.config.json`, `install_secret`, `license_token` = segreti → `chmod 600`.
- Il segreto del watcher sta in `/etc/vaultcode/<uuid>.env` (600) e viene passato
  via **variabile d'ambiente**, mai in riga di comando (niente esposizione in `ps`).
- `vaultcode_pub.pem` NON è segreta (verifica i bundle di update).
- Risposta alla manomissione: **probatoria** (badge/alert/PDF firmato), mai
  distruttiva (INVARIANTE 1).

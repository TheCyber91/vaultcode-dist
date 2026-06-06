<?php
declare(strict_types=1);

namespace VaultCode;

/**
 * Facciata runtime: implementa il contratto v1 usato dal codice protetto
 *
 *     eval(\VaultCode\Runtime::fragment('module','frag',ck));
 *
 * Restituisce il codice PHP decifrato del frammento. Cascata di fallback (§5):
 *   primario (key-server, con retry) → cache locale (TTL/grace) → banner.
 * Il banner è NON bloccante: in caso di indisponibilità ritorna stringa vuota
 * (eval no-op) e il software continua (INVARIANTE 1).
 *
 * Entanglement: l'AAD usa il tag di paternità preso dalla costante
 * VAULTCODE_RIGHTS_TAG (iniettata in chiaro nel sorgente). Rimuoverla impedisce
 * di ricostruire l'AAD → la decifratura fallisce: conseguenza naturale, non un
 * kill-switch.
 */
final class Runtime
{
    /** Versione della libreria client (riportata al key-server via /status,
     *  usata dallo studio per "aggiornata?" e dall'auto-update). */
    public const VERSION = '1.0.0';

    private static ?Runtime $instance = null;
    /** Flag: buffer d'output per l'iniezione automatica del badge già armato. */
    private static bool $autoBadgeArmed = false;

    private Config $cfg;
    private KeyServerInterface $ks;
    private ?Cache $cache;
    private Banner $banner;
    /** @var callable():array rilevatore anti-tamper (iniettabile per i test) */
    private $tamperDetector;
    private bool $tamperChecked = false;
    /** @var array<string,array> payload per modulo, caricati on-demand */
    private array $payloads = [];
    /** @var array<string,string>|null mappa chiavi di escrow ("module:ck:frag"→hex), lazy */
    private ?array $escrow = null;
    /** @var array<string,string> cache per-richiesta del testo decifrato (solo frammenti loop) */
    private array $fragmentCache = [];
    /**
     * Segnali di VIOLAZIONE integrità/licenza accumulati nel processo (per il
     * badge visibile al cliente). NB: i problemi di sola DISPONIBILITÀ (server
     * irraggiungibile, uso cache) NON entrano qui: disponibilità ≠ manomissione.
     * @var list<string>
     */
    private array $integrityWarnings = [];
    /** Stato d'integrità confermato dal server (null = non ancora determinato). */
    private ?bool $serverCompromised = null;
    private bool $serverStatusChecked = false;

    public function __construct(Config $cfg, ?KeyServerInterface $ks = null,
                                ?Cache $cache = null, ?Banner $banner = null,
                                ?callable $tamperDetector = null)
    {
        $this->cfg = $cfg;
        $this->ks = $ks ?? new KeyServerClient($cfg);
        if ($cache === null && $cfg->cachePath !== '' && $cfg->installSecret !== '') {
            $cache = new Cache($cfg->cachePath, Cache::deriveKey($cfg->installSecret));
        }
        $this->cache = $cache;
        $this->banner = $banner ?? new Banner($this->defaultBannerSink());
        $this->tamperDetector = $tamperDetector ?? static fn(): array => Sentinel::detect();
    }

    /**
     * Sink di default del banner. Se è configurato `banner_log_file`, i messaggi
     * vengono APPESI a quel file (facile da trovare/tail-are sul server del
     * cliente) oltre che mandati all'error_log di PHP. Altrimenti: solo error_log.
     * Sempre best-effort e non bloccante (INVARIANTE 1).
     */
    private function defaultBannerSink(): ?callable
    {
        $file = $this->cfg->bannerLogFile;
        if ($file === '') {
            return null; // Banner userà il default: error_log()
        }
        return static function (string $msg) use ($file): void {
            @file_put_contents($file, '[' . date('c') . "] $msg\n", FILE_APPEND | LOCK_EX);
            error_log($msg);
        };
    }

    /**
     * Rilevazione anti-tamper (§11), una sola volta per processo. Per ogni
     * segnale: alert probatorio all'autore + banner. NON bloccante, NON
     * distruttiva, e NON nega la chiave (il licenziatario può ispezionare il
     * proprio server, 64-ter): è solo un segnale.
     */
    private function tamperCheckOnce(): void
    {
        if ($this->tamperChecked) {
            return;
        }
        $this->tamperChecked = true;
        foreach (($this->tamperDetector)() as $signal) {
            $this->tamper("segnale anti-tamper rilevato: {$signal} (registrato; software attivo)");
            $this->ks->postTamper($signal, null);
        }
    }

    /**
     * Registra un segnale di VIOLAZIONE integrità/licenza: lo accumula per il
     * badge visibile al cliente E lo manda al banner (log/sink). NON bloccante,
     * NON distruttivo (INVARIANTE 1): è solo un AVVISO.
     */
    private function tamper(string $message): void
    {
        if (!in_array($message, $this->integrityWarnings, true)) {
            $this->integrityWarnings[] = $message;
        }
        $this->banner->notify($message);
    }

    // --- stato d'integrità visibile al cliente (badge ⚠) ---------------------

    /** @return list<string> segnali di violazione raccolti in questo processo. */
    public static function integrityWarnings(): array
    {
        return self::$instance !== null ? self::$instance->integrityWarnings : [];
    }

    /** true se è caricato il runtime nativo (estensione webdl_protect). */
    public static function nativeActive(): bool
    {
        return function_exists('webdl_decrypt');
    }

    /**
     * true se è stato rilevato almeno un segnale di violazione, OPPURE se il
     * key-server conferma che questa installazione è segnalata (badge affidabile
     * su QUALUNQUE pagina, anche senza eseguire porzioni). Disponibilità del
     * server irrilevante: in caso di irraggiungibilità si usa l'ultimo stato noto.
     */
    public static function isCompromised(): bool
    {
        if (self::$instance === null) {
            return false;
        }
        self::$instance->ensureServerStatus();
        return self::$instance->integrityWarnings !== []
            || self::$instance->serverCompromised === true;
    }

    /**
     * Determina (una volta per processo) lo stato d'integrità confermato dal
     * server, con cache su file FIRMATA (non falsificabile editando il file) e
     * TTL. Best-effort: se il server è irraggiungibile si tiene l'ultimo stato
     * noto (disponibilità ≠ cambio di stato). Mai bloccante.
     */
    private function ensureServerStatus(): void
    {
        if ($this->serverStatusChecked) {
            return;
        }
        $this->serverStatusChecked = true;
        try {
            $now = time();
            $ttl = max(0, $this->cfg->statusTtlSeconds);
            $file = $this->cfg->statusCachePath;

            // 1) cache su file: token firmato + fetched_at. Se fresca e valida → usala.
            if ($file !== '' && is_file($file)) {
                $cached = json_decode((string)@file_get_contents($file), true);
                if (is_array($cached) && isset($cached['token'], $cached['fetched_at'])) {
                    $payload = Crypto::verifyToken($this->cfg->ed25519PublicKeyPem, (string)$cached['token']);
                    if ($payload !== null
                        && (string)($payload['install_uuid'] ?? '') === $this->cfg->installUuid) {
                        // ultimo stato noto (anche se stale: fallback se il fetch fallisce)
                        $this->serverCompromised = ((string)($payload['integrity'] ?? 'ok') === 'alert');
                        if (($now - (int)$cached['fetched_at']) <= $ttl) {
                            return; // fresca → niente fetch
                        }
                    }
                }
            }

            // 2) fetch dal server (best-effort). Ok → aggiorna + cache firmata.
            //    KO → si tiene l'ultimo stato noto impostato sopra.
            $payload = $this->ks->fetchStatus();
            if ($payload !== null) {
                $this->serverCompromised = ((string)($payload['integrity'] ?? 'ok') === 'alert');
                if ($file !== '' && isset($payload['_token'])) {
                    @file_put_contents(
                        $file,
                        (string)json_encode(['token' => (string)$payload['_token'], 'fetched_at' => $now]),
                        LOCK_EX
                    );
                }
            }
        } catch (\Throwable $e) {
            // Lo stato è un di più: un suo errore non deve mai rompere il render.
        }
    }

    /**
     * Esegue il controllo anti-tamper §11 (debugger) senza decifrare alcun
     * frammento: utile per mostrare il badge anche in pagine che non usano il
     * core protetto. La manomissione dei file (paternità/payload) resta rilevata
     * naturalmente quando il frammento corrispondente viene eseguito.
     */
    public static function scan(): void
    {
        if (self::$instance !== null) {
            self::$instance->tamperCheckOnce();
        }
    }

    /**
     * Restituisce un BADGE HTML visibile (triangolo ⚠ + tooltip) SE è stata
     * rilevata una violazione di integrità/licenza, altrimenti stringa vuota.
     * L'integratore lo stampa dove vuole (tipicamente nel footer/area admin):
     *
     *     <?= \VaultCode\Runtime::integrityBadge() ?>
     *
     * Autoconsistente (stili inline) e NON bloccante: avvisa, non interrompe.
     */
    public static function integrityBadge(?string $label = null, ?string $tooltip = null): string
    {
        if (!self::isCompromised()) {
            return '';
        }
        $label   = $label ?? 'Integrità licenza compromessa';
        $tooltip = $tooltip ?? 'VaultCode — Rilevata una possibile manomissione del sistema di licenza/'
            . 'integrità di questo software. Il programma continua a funzionare regolarmente. '
            . 'Si raccomanda di contattare il fornitore del software.';
        $l = htmlspecialchars($label, ENT_QUOTES);
        $t = htmlspecialchars($tooltip, ENT_QUOTES);

        // Stili CRITICI INLINE + !important: il badge resta visibile anche dentro
        // temi/Bootstrap modificati (es. AdminLTE/OpenSTAManager) che ridefiniscono
        // span/display/colori/visibility. Niente dipendenza da classi del tema.
        $pill = 'position:relative !important;display:inline-flex !important;align-items:center !important;'
              . 'gap:6px !important;background:#7f1d1d !important;color:#fff !important;'
              . 'font:600 12px/1.2 system-ui,sans-serif !important;padding:6px 12px !important;'
              . 'border-radius:999px !important;cursor:help !important;vertical-align:middle !important;'
              . 'white-space:nowrap !important;text-decoration:none !important;text-transform:none !important;'
              . 'letter-spacing:normal !important;margin:0 !important;opacity:1 !important;'
              . 'visibility:visible !important;outline:none;box-shadow:0 0 0 0 rgba(239,68,68,.55);'
              . 'animation:vc-pulse 1.6s infinite;';
        $tri = 'font-size:14px !important;line-height:1 !important;color:#fff !important;';
        return
            '<span class="vc-badge" style="' . $pill . '" tabindex="0" role="alert" aria-label="' . $t . '" title="' . $t . '">'
            . '<span style="' . $tri . '">&#9888;</span>'
            . '<span style="color:#fff !important">' . $l . '</span>'
            . '<span class="vc-tip">' . $t . '</span></span>'
            . '<style>'
            // Ancorato a DESTRA del badge: cresce verso sinistra → non sborda dal
            // bordo destro dello schermo (il badge sta in basso a destra).
            . '.vc-badge .vc-tip{position:absolute !important;bottom:140% !important;right:0 !important;'
            . 'left:auto !important;transform:none !important;width:max-content !important;'
            . 'max-width:min(320px,90vw) !important;background:#0b1220 !important;color:#e2e8f0 !important;'
            . 'border:1px solid #ef4444 !important;border-radius:8px !important;padding:9px 12px !important;'
            . 'font:400 12px/1.5 system-ui,sans-serif !important;white-space:normal !important;'
            . 'word-break:break-word !important;text-align:left !important;'
            . 'box-shadow:0 8px 24px rgba(0,0,0,.45);z-index:2147483647 !important;display:none !important}'
            . '.vc-badge:hover .vc-tip,.vc-badge:focus .vc-tip{display:block !important}'
            . '@keyframes vc-pulse{0%{box-shadow:0 0 0 0 rgba(239,68,68,.55)}'
            . '70%{box-shadow:0 0 0 8px rgba(239,68,68,0)}100%{box-shadow:0 0 0 0 rgba(239,68,68,0)}}'
            . '</style>';
    }

    /**
     * Attiva l'iniezione AUTOMATICA del badge nelle pagine HTML (in basso a
     * destra), senza dover chiamare integrityBadge() nei template. Apre un
     * buffer d'output con un handler che inietta il badge prima di </body> SOLO
     * se la risposta è HTML e l'installazione è compromessa. Idempotente.
     */
    public static function autoBadge(): void
    {
        if (self::$autoBadgeArmed || PHP_SAPI === 'cli') {
            return;
        }
        self::$autoBadgeArmed = true;
        // 1) iniezione "pulita" prima di </body> quando il framework lascia
        //    flushare il buffer.
        ob_start([self::class, 'obHandler']);
        // 2) fallback ROBUSTO: a fine richiesta (sempre eseguito) emette il badge
        //    se l'handler non ha potuto agire — es. framework che cattura l'output
        //    con ob_get_clean() (AdminLTE/OpenSTAManager). Così il badge è emesso
        //    dal runtime VaultCode, senza toccare i file dell'app ospite.
        register_shutdown_function([self::class, 'shutdownBadge']);
    }

    /**
     * Fallback di fine richiesta. Se il nostro buffer è ancora attivo sarà
     * l'handler a iniettare (non duplica); altrimenti emette il badge come box
     * fisso. Solo risposte HTML, solo se compromesso. Mai solleva.
     */
    public static function shutdownBadge(): void
    {
        try {
            // Il nostro buffer è ancora nello stack? → ci penserà obHandler.
            foreach (ob_get_status(true) as $b) {
                if (isset($b['name']) && strpos((string)$b['name'], 'obHandler') !== false) {
                    return;
                }
            }
            $badge = self::integrityBadge();
            if ($badge === '' || !self::responseIsHtml()) {
                return;
            }
            echo '<div style="position:fixed !important;right:16px !important;bottom:16px !important;'
                . 'z-index:2147483647 !important">' . $badge . '</div>';
        } catch (\Throwable $e) {
            // mai rompere l'output del cliente (INVARIANTE 1)
        }
    }

    /** Vero se la risposta è (o si assume) HTML: non sporcare JSON/AJAX/download. */
    private static function responseIsHtml(): bool
    {
        if (!function_exists('headers_list')) {
            return true;
        }
        foreach (headers_list() as $h) {
            if (stripos($h, 'content-type:') === 0) {
                return stripos($h, 'text/html') !== false;
            }
        }
        return true; // nessun Content-Type esplicito → default text/html
    }

    /**
     * Handler del buffer d'output (lo richiama ob_start). Delega a injectBadge().
     * Nota: funziona solo se il buffer viene FLUSHATO; se il framework cattura la
     * pagina con ob_get_clean() il callback non scatta → usa injectBadge() al
     * punto di output, o il badge manuale nel footer.
     */
    public static function obHandler(string $buffer): string
    {
        return self::injectBadge($buffer);
    }

    /**
     * Inietta il badge (contenitore fisso, prima di </body>) in una stringa HTML
     * e la ritorna. Utile per i framework che producono la pagina come STRINGA:
     *
     *     echo \VaultCode\Runtime::injectBadge($htmlPagina);
     *
     * No-op se non è HTML o se l'installazione è integra. Mai solleva.
     */
    public static function injectBadge(string $html): string
    {
        try {
            if (!self::looksLikeHtml($html)) {
                return $html;
            }
            $badge = self::integrityBadge();
            if ($badge === '') {
                return $html;
            }
            $box = '<div style="position:fixed;right:16px;bottom:16px;z-index:2147483647">' . $badge . '</div>';
            $pos = stripos($html, '</body>');
            return $pos !== false
                ? substr($html, 0, $pos) . $box . substr($html, $pos)
                : $html . $box;
        } catch (\Throwable $e) {
            return $html; // mai rompere l'output del cliente (INVARIANTE 1)
        }
    }

    /** Euristica prudente: inietta solo in risposte HTML, mai in JSON/download. */
    private static function looksLikeHtml(string $buffer): bool
    {
        foreach (headers_list() as $h) {
            if (stripos($h, 'content-type:') === 0) {
                return stripos($h, 'text/html') !== false;
            }
        }
        return stripos($buffer, '</body>') !== false || stripos($buffer, '<html') !== false;
    }

    // --- bootstrap statico (il codice protetto chiama il metodo statico) -----

    /**
     * Bootstrap. $bannerSink (opzionale) instrada i messaggi del banner dove
     * vuoi (es. una pagina admin, Slack, un file): se omesso si usa
     * banner_log_file della config, o l'error_log di PHP.
     */
    public static function init(Config $cfg, ?callable $bannerSink = null): void
    {
        self::$instance = new self($cfg, null, null, $bannerSink !== null ? new Banner($bannerSink) : null);
        if ($cfg->badgeAutoDisplay) {
            self::autoBadge();
        }
    }
    public static function setInstance(Runtime $r): void { self::$instance = $r; }

    public static function fragment(string $module, string $frag, int $ck, bool $memo = false): string
    {
        if (self::$instance === null) {
            error_log('[VaultCode] Runtime non inizializzato: chiamare Runtime::init()');
            return '';
        }
        return self::$instance->getFragment($module, $frag, $ck, $memo);
    }

    // --- logica d'istanza ----------------------------------------------------

    private function rightsTag(): string
    {
        if (defined('VAULTCODE_RIGHTS_TAG')) { return (string)constant('VAULTCODE_RIGHTS_TAG'); }
        return $this->cfg->rightsTag;
    }

    private function loadPayload(string $module): ?array
    {
        if (isset($this->payloads[$module])) { return $this->payloads[$module]; }
        $path = rtrim($this->cfg->payloadDir, '/\\') . DIRECTORY_SEPARATOR . "$module.vaultpayload.json";
        if (!is_file($path)) { return null; }
        $data = json_decode((string)file_get_contents($path), true);
        if (!is_array($data)) { return null; }
        return $this->payloads[$module] = $data;
    }

    /** Ottiene la chiave PER-FRAMMENTO (hex) via cascata: server → cache. null se nessuna. */
    private function resolveContentKey(string $module, int $ck, string $frag): ?string
    {
        $now = time();
        // 1) primario, con retry. Si richiede SOLO la chiave di questa porzione.
        for ($i = 0; $i < max(1, $this->cfg->retries); $i++) {
            try {
                $resp = $this->ks->fetchKey($module, $ck, $frag);
            } catch (\Throwable $e) {
                continue; // problema di DISPONIBILITÀ → si riprova, poi cache (§5)
            }
            $status = (string)($resp['status'] ?? '');
            if ($status === 'granted' && !empty($resp['content_key'])) {
                $hex = (string)$resp['content_key'];
                $win = (string)($resp['window'] ?? '');
                if ($this->cache) { $this->cache->put($module, $ck, $frag, $hex, $win, $now); }
                return $hex;
            }
            // Risposta definitiva di non-autorizzazione: violazione del sistema di licenza.
            $this->tamper("contesto non autorizzato per {$module}/{$frag} (" . ($resp['reason'] ?? $status) . ')');
            break;
        }
        // 2) cache locale (anche stale, entro il grace) → resilienza.
        if ($this->cache) {
            $entry = $this->cache->get($module, $ck, $frag);
            if ($entry !== null) {
                $age = $now - (int)($entry['fetched_at'] ?? 0);
                if ($age <= $this->cfg->graceSeconds) {
                    if ($age > $this->cfg->ttlSeconds) {
                        $this->banner->notify("server irraggiungibile: uso cache locale per {$module}/{$frag}");
                    }
                    return (string)$entry['content_key_hex'];
                }
            }
        }
        // 3) ESCROW / permanent unlock (offline): ultimo anello, se il key-server
        //    è sparito. Mai prendere in ostaggio il cliente (INVARIANTE 7).
        $ek = $this->escrowKey($module, $ck, $frag);
        if ($ek !== null) {
            return $ek;
        }
        return null;
    }

    /** Carica e verifica (una volta) il bundle di escrow firmato. */
    private function ensureEscrow(): void
    {
        if ($this->escrow !== null) {
            return;
        }
        $this->escrow = [];
        $path = $this->cfg->escrowPath;
        if ($path === '' || !is_file($path)) {
            return;
        }
        $token = trim((string)file_get_contents($path));
        $payload = Crypto::verifyToken($this->cfg->ed25519PublicKeyPem, $token);
        if ($payload === null) {
            $this->tamper('escrow: firma non valida (ignorato)');
            return;
        }
        if ((string)($payload['install_uuid'] ?? '') !== $this->cfg->installUuid) {
            $this->tamper('escrow: per un\'altra installazione (ignorato)');
            return;
        }
        $keys = $payload['keys'] ?? null;
        $this->escrow = is_array($keys) ? $keys : [];
    }

    private function escrowKey(string $module, int $ck, string $frag): ?string
    {
        $this->ensureEscrow();
        $k = $this->escrow["$module:$ck:$frag"] ?? null;
        return is_string($k) ? $k : null;
    }

    public function getFragment(string $module, string $frag, int $ck, bool $memo = false): string
    {
        $this->tamperCheckOnce();  // §11: rileva e SEGNALA (non blocca, non nega la chiave)
        // Frammenti loop=1: una sola fetch+decifratura per richiesta (memoizza il
        // TESTO decifrato, mai la chiave). Senza loop, comportamento invariato.
        $cacheKey = $module . ':' . $frag . ':' . $ck;
        if ($memo && isset($this->fragmentCache[$cacheKey])) {
            return $this->fragmentCache[$cacheKey];
        }
        $payload = $this->loadPayload($module);
        if ($payload === null || !isset($payload['fragments'][$frag])) {
            $this->tamper("payload mancante per {$module}/{$frag}");
            return '';
        }
        $entry = $payload['fragments'][$frag];

        $hex = $this->resolveContentKey($module, $ck, $frag);
        if ($hex === null) {
            $this->banner->notify("contesto non verificato: {$module}/{$frag} non eseguito (software comunque attivo)");
            return '';
        }

        $tag = $this->rightsTag();
        if ($tag === '') {
            $this->tamper('informazioni di paternità assenti (VAULTCODE_RIGHTS_TAG): decifratura non possibile');
            return '';
        }

        // Chiave PER-FRAMMENTO materializzata SOLO ora; azzerata subito dopo l'uso
        // (sodium_memzero) → in RAM c'è al massimo una chiave alla volta (opzione B).
        $key = (string)hex2bin($hex);
        try {
            $aad = Crypto::aadFor($module, $frag, $ck, $tag);
            $plain = Crypto::aesGcmDecrypt(
                $key,
                (string)base64_decode((string)$entry['ciphertext']),
                (string)base64_decode((string)$entry['nonce']),
                $aad
            );
            if ($memo && $plain !== '') {
                $this->fragmentCache[$cacheKey] = $plain;  // solo il testo, mai la chiave
            }
            return $plain;
        } catch (\Throwable $e) {
            $this->tamper("decifratura fallita per {$module}/{$frag} (paternità alterata?)");
            return '';
        } finally {
            if (function_exists('sodium_memzero')) {
                try { sodium_memzero($key); } catch (\SodiumException $e) { /* best-effort */ }
            }
        }
    }

    /**
     * Controllo revoche (da invocare periodicamente, §5). Ritorna true se la
     * licenza di QUESTA installazione risulta revocata, ed emette il banner.
     */
    public function isLicenseRevoked(): bool
    {
        $revoked = $this->ks->fetchRevocations();
        if ($revoked === null) { return false; } // non verificabile → non blocca
        $payload = Crypto::verifyToken($this->cfg->ed25519PublicKeyPem, $this->cfg->licenseToken);
        $licenseId = $payload['license_id'] ?? null;
        if ($licenseId !== null && in_array((string)$licenseId, $revoked, true)) {
            $this->tamper("licenza {$licenseId} revocata");
            return true;
        }
        return false;
    }
}

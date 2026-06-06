<?php
declare(strict_types=1);

namespace VaultCode;

/**
 * Configurazione del client, generata in fase di provisioning/consegna.
 *
 * I valori sensibili (install_secret, license_token) sono provisionati DALL'AUTORE
 * alla consegna: il client NON deriva nulla dal master secret (che non possiede).
 * La chiave pubblica Ed25519 NON è un segreto (serve a verificare revoche/licenze).
 */
final class Config
{
    public string $installUuid;
    /** @var string install_secret in BYTES grezzi (per la firma HMAC). */
    public string $installSecret;
    public string $licenseToken;
    public string $keyServerUrl;
    public string $ed25519PublicKeyPem;
    /**
     * Pin TLS della chiave pubblica del key-server (formato curl
     * "sha256//BASE64[;sha256//BASE64]"). Se impostato, la connessione viene
     * rifiutata se la chiave pubblica TLS non combacia (anti-MITM/redirect verso
     * un key-server fasullo). '' = nessun pin. NON bloccante: un mismatch degrada
     * alla cascata (cache/escrow/banner). Difesa in profondità: le risposte
     * firmate Ed25519 (/status,/revocations,/release) restano comunque la difesa
     * primaria contro un server contraffatto.
     */
    public string $keyServerPin = '';

    /** Directory dei *.vaultpayload.json prodotti dal protect-tool. */
    public string $payloadDir;
    /** File di cache locale (cifrata+firmata). '' = cache disabilitata. */
    public string $cachePath = '';
    /** Tag di paternità (entanglement). Se '' si usa la costante VAULTCODE_RIGHTS_TAG. */
    public string $rightsTag = '';
    /** File del bundle di escrow (permanent unlock offline). '' = assente. */
    public string $escrowPath = '';
    /**
     * File dove scrivere (in append) i messaggi del banner NON bloccante, così
     * sono facili da trovare sul server del cliente. '' = solo error_log di PHP.
     */
    public string $bannerLogFile = '';
    /**
     * File di cache (token firmato) dello STATO d'integrità "server-confermato"
     * per il badge cliente. '' = nessuna cache cross-richiesta (interroga il
     * server ad ogni render del badge). Consigliato impostarlo (dir scrivibile).
     */
    public string $statusCachePath = '';
    /** Ogni quanti secondi rinfrescare lo stato d'integrità dal server (badge). */
    public int $statusTtlSeconds = 300;
    /**
     * Se true (DEFAULT), il badge d'integrità viene emesso automaticamente dal
     * runtime nelle pagine HTML (in basso a destra), SENZA toccare i file
     * dell'applicazione ospite. Bound a Runtime::init(): disattivarlo equivale a
     * disattivare VaultCode (elusione). Solo risposte HTML, solo se compromesso.
     */
    public bool $badgeAutoDisplay = true;

    public int $ttlSeconds = 3600;        // TTL cache (corto: il blocco degrada in fretta, §4)
    public int $graceSeconds = 604800;    // grace prima del banner se irraggiungibile (7 giorni)
    public int $clockSkewSeconds = 300;   // tolleranza clock per la cache
    public int $retries = 5;              // tentativi verso il primario (fallback a cascata, §5)
    public float $timeout = 10.0;         // timeout per richiesta (s)

    public static function fromArray(array $a): self
    {
        $c = new self();
        $c->installUuid         = (string)($a['install_uuid'] ?? '');
        $secretHex              = (string)($a['install_secret_hex'] ?? '');
        $c->installSecret       = $secretHex !== '' ? (string)hex2bin($secretHex) : '';
        $c->licenseToken        = (string)($a['license_token'] ?? '');
        $c->keyServerUrl        = rtrim((string)($a['key_server_url'] ?? ''), '/');
        $c->ed25519PublicKeyPem = (string)($a['ed25519_public_key_pem'] ?? '');
        $c->keyServerPin        = (string)($a['key_server_pin'] ?? '');
        $c->payloadDir          = (string)($a['payload_dir'] ?? '');
        $c->cachePath           = (string)($a['cache_path'] ?? '');
        $c->rightsTag           = (string)($a['rights_tag'] ?? '');
        $c->escrowPath          = (string)($a['escrow_path'] ?? '');
        $c->bannerLogFile       = (string)($a['banner_log_file'] ?? '');
        $c->statusCachePath     = (string)($a['status_cache_path'] ?? '');
        $c->badgeAutoDisplay    = (bool)($a['badge_auto_display'] ?? true);
        foreach (['ttl_seconds' => 'ttlSeconds', 'grace_seconds' => 'graceSeconds',
                  'clock_skew_seconds' => 'clockSkewSeconds', 'retries' => 'retries',
                  'status_ttl_seconds' => 'statusTtlSeconds'] as $k => $prop) {
            if (isset($a[$k])) { $c->$prop = (int)$a[$k]; }
        }
        if (isset($a['timeout'])) { $c->timeout = (float)$a['timeout']; }
        return $c;
    }

    public static function fromJsonFile(string $path): self
    {
        $data = json_decode((string)file_get_contents($path), true);
        if (!is_array($data)) {
            throw new \RuntimeException("config non valida: $path");
        }
        return self::fromArray($data);
    }
}

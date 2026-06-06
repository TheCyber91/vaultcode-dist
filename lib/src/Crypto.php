<?php
declare(strict_types=1);

namespace VaultCode;

/**
 * Primitive crittografiche del client — DEVONO combaciare con key-server e
 * protect-tool (Python). Solo estensioni standard: openssl (AES-256-GCM),
 * sodium (Ed25519), hash (HMAC-SHA256). Nessuna primitiva custom (INVARIANTE 6).
 *
 * Schemi/domini congelati sul wire (identici a key-server/protect-tool):
 *   - firma richiesta:  "vaultcode/req-sig/v1"   (hmac_auth.build_canonical_message)
 *   - AAD frammento:    "vaultcode/frag-aad/v1"  (bundle.aad_for)
 */
final class Crypto
{
    private const SIG_SCHEME = 'vaultcode/req-sig/v1';
    private const AAD_DOMAIN  = 'vaultcode/frag-aad/v1';

    /** Length-prefix uint32 big-endian + payload (domain separation). */
    public static function lp(string $s): string
    {
        return pack('N', strlen($s)) . $s;
    }

    // --- Firma richieste HMAC-SHA256 (parità con key-server hmac_auth) -------

    public static function buildCanonicalMessage(
        string $method, string $path, string $installUuid,
        string $nonce, string $timestamp, string $body
    ): string {
        $parts = [self::SIG_SCHEME, strtoupper($method), $path, $installUuid, $nonce, $timestamp, $body];
        $out = '';
        foreach ($parts as $p) { $out .= self::lp($p); }
        return $out;
    }

    /** HMAC-SHA256 esadecimale minuscolo. $installSecret in BYTES grezzi. */
    public static function computeSignature(string $installSecret, string $canonicalMessage): string
    {
        return hash_hmac('sha256', $canonicalMessage, $installSecret);
    }

    // --- AAD del frammento (parità con protect-tool bundle.aad_for) ----------

    public static function aadFor(string $module, string $frag, int $ck, string $entanglementTag): string
    {
        $parts = [self::AAD_DOMAIN, $module, $frag, (string)$ck, $entanglementTag];
        $out = '';
        foreach ($parts as $p) { $out .= self::lp($p); }
        return $out;
    }

    // --- AES-256-GCM (parità con cryptography AESGCM) ------------------------

    /**
     * Decifra ciphertext con tag IN CODA (formato di cryptography: ct‖tag16).
     * $key 32 byte, $nonce 12 byte. Solleva su autenticazione fallita.
     */
    public static function aesGcmDecrypt(string $key, string $ciphertextWithTag, string $nonce, string $aad): string
    {
        if (strlen($key) !== 32)   { throw new \InvalidArgumentException('chiave AES non di 32 byte'); }
        if (strlen($nonce) !== 12) { throw new \InvalidArgumentException('nonce GCM non di 12 byte'); }
        if (strlen($ciphertextWithTag) < 16) { throw new \RuntimeException('ciphertext troppo corto'); }
        // Runtime nativo (estensione webdl_protect): decifratura in codice
        // compilato + zeroing. Se assente o non decifra, FALLBACK a openssl puro:
        // una .so mancante/difettosa non rompe mai la decifratura (INVARIANTE 7).
        if (function_exists('webdl_decrypt')) {
            $native = webdl_decrypt($key, $ciphertextWithTag, $nonce, $aad);
            if (is_string($native)) { return $native; }
        }
        $tag  = substr($ciphertextWithTag, -16);
        $body = substr($ciphertextWithTag, 0, -16);
        $pt = openssl_decrypt($body, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
        if ($pt === false) {
            throw new \RuntimeException('decifratura AES-GCM fallita (tag/aad non validi)');
        }
        return $pt;
    }

    /**
     * Cifra con AES-256-GCM e restituisce ciphertext‖tag16 (formato cryptography).
     * Usato dalla cache locale (cifrata e autenticata).
     */
    public static function aesGcmEncrypt(string $key, string $plaintext, string $nonce, string $aad = ''): string
    {
        if (strlen($key) !== 32)   { throw new \InvalidArgumentException('chiave AES non di 32 byte'); }
        if (strlen($nonce) !== 12) { throw new \InvalidArgumentException('nonce GCM non di 12 byte'); }
        $tag = '';
        $ct = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, 16);
        if ($ct === false) { throw new \RuntimeException('cifratura AES-GCM fallita'); }
        return $ct . $tag;
    }

    /** Nonce casuale a 96 bit per AES-GCM. */
    public static function newNonce(): string
    {
        return random_bytes(12);
    }

    // --- base64url senza padding --------------------------------------------

    public static function b64uDecode(string $s): string
    {
        $s = strtr($s, '-_', '+/');
        $pad = strlen($s) % 4;
        if ($pad) { $s .= str_repeat('=', 4 - $pad); }
        return base64_decode($s, true);
    }

    // --- Ed25519 (sodium) — verifica licenze/revoche -------------------------

    /** Estrae la chiave pubblica Ed25519 grezza (32 byte) da un PEM SPKI. */
    public static function ed25519RawFromPem(string $pem): string
    {
        if (!preg_match('/-----BEGIN PUBLIC KEY-----(.+?)-----END PUBLIC KEY-----/s', $pem, $m)) {
            throw new \InvalidArgumentException('PEM pubblica non valido');
        }
        $der = base64_decode(preg_replace('/\s+/', '', $m[1]), true);
        if ($der === false || strlen($der) < 32) {
            throw new \InvalidArgumentException('DER pubblica non valido');
        }
        return substr($der, -32); // SPKI Ed25519: la chiave grezza sono gli ultimi 32 byte
    }

    /**
     * Verifica un token compatto "payloadB64.sigB64" (come license/revocation
     * del key-server). Ritorna il payload decodificato (array) o null se invalido.
     */
    public static function verifyToken(string $publicKeyPem, string $token): ?array
    {
        $dot = strpos($token, '.');
        if ($dot === false) { return null; }
        $payloadB64 = substr($token, 0, $dot);
        $sigB64     = substr($token, $dot + 1);
        $raw = self::ed25519RawFromPem($publicKeyPem);
        try {
            $ok = sodium_crypto_sign_verify_detached(self::b64uDecode($sigB64), $payloadB64, $raw);
        } catch (\SodiumException $e) {
            return null;
        }
        if (!$ok) { return null; }
        $payload = json_decode(self::b64uDecode($payloadB64), true);
        return is_array($payload) ? $payload : null;
    }
}

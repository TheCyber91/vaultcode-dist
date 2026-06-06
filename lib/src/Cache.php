<?php
declare(strict_types=1);

namespace VaultCode;

/**
 * Cache locale delle content key — CIFRATA e AUTENTICATA (AES-256-GCM: il tag
 * fa anche da firma, impedisce cache poisoning). §5.
 *
 * File su disco = nonce(12) ‖ ciphertext‖tag. Il contenuto è una mappa
 * "module:ck" → {content_key_hex, window, fetched_at}. La freschezza (TTL) è
 * decisa dal chiamante (Runtime) confrontando fetched_at con now: questo
 * permette il fallback "stale entro il grace" se il server è irraggiungibile.
 */
final class Cache
{
    private const AAD = 'vaultcode/cache/v1';

    private string $path;
    private string $key; // 32 byte

    public function __construct(string $path, string $key)
    {
        $this->path = $path;
        $this->key = $key;
    }

    /** Deriva la chiave di cache dal segreto per-installazione (deterministica). */
    public static function deriveKey(string $installSecret): string
    {
        return substr(hash('sha256', $installSecret . 'vaultcode/cache-key/v1', true), 0, 32);
    }

    private function load(): array
    {
        if ($this->path === '' || !is_file($this->path)) { return []; }
        $blob = (string)file_get_contents($this->path);
        if (strlen($blob) < 13) { return []; }
        $nonce = substr($blob, 0, 12);
        $ct = substr($blob, 12);
        try {
            $json = Crypto::aesGcmDecrypt($this->key, $ct, $nonce, self::AAD);
        } catch (\Throwable $e) {
            return []; // cache corrotta/manomessa → ignorata (verrà riscritta)
        }
        $data = json_decode($json, true);
        return is_array($data) ? $data : [];
    }

    private function save(array $data): void
    {
        if ($this->path === '') { return; }
        $nonce = Crypto::newNonce();
        $ct = Crypto::aesGcmEncrypt($this->key, json_encode($data), $nonce, self::AAD);
        $dir = dirname($this->path);
        if (!is_dir($dir)) { @mkdir($dir, 0700, true); }
        file_put_contents($this->path, $nonce . $ct, LOCK_EX);
        @chmod($this->path, 0600);
    }

    /** @return array{content_key_hex:string,window:string,fetched_at:int}|null */
    public function get(string $module, int $ck, string $frag): ?array
    {
        $data = $this->load();
        $entry = $data["$module:$ck:$frag"] ?? null;
        return is_array($entry) ? $entry : null;
    }

    public function put(string $module, int $ck, string $frag, string $contentKeyHex, string $window, int $now): void
    {
        $data = $this->load();
        $data["$module:$ck:$frag"] = [
            'content_key_hex' => $contentKeyHex,
            'window' => $window,
            'fetched_at' => $now,
        ];
        $this->save($data);
    }
}

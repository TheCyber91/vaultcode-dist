<?php
declare(strict_types=1);

namespace VaultCode;

/**
 * Client HTTP del key-server: firma HMAC per-installazione + nonce + timestamp
 * (anti-replay), su TLS. Verifica la lista revoche firmata Ed25519.
 */
final class KeyServerClient implements KeyServerInterface
{
    private Config $cfg;

    public function __construct(Config $cfg)
    {
        $this->cfg = $cfg;
    }

    private function signedHeaders(string $method, string $path, string $body): array
    {
        $nonce = bin2hex(random_bytes(16));
        $ts = (string)time();
        $msg = Crypto::buildCanonicalMessage($method, $path, $this->cfg->installUuid, $nonce, $ts, $body);
        $sig = Crypto::computeSignature($this->cfg->installSecret, $msg);
        return [
            'Content-Type: application/json',
            'X-Install-UUID: ' . $this->cfg->installUuid,
            'X-Nonce: ' . $nonce,
            'X-Timestamp: ' . $ts,
            'X-Signature: ' . $sig,
        ];
    }

    /** @return array{code:int,body:string} */
    private function http(string $method, string $path, array $headers, string $body): array
    {
        $ch = curl_init($this->cfg->keyServerUrl . $path);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => (int)ceil($this->cfg->timeout),
            CURLOPT_POSTFIELDS => $method === 'POST' ? $body : null,
        ]);
        // Pinning TLS della chiave pubblica del key-server (anti-MITM/redirect).
        // Un mismatch fa fallire curl → cascata non bloccante (INVARIANTE 7).
        if ($this->cfg->keyServerPin !== '') {
            curl_setopt($ch, CURLOPT_PINNEDPUBLICKEY, $this->cfg->keyServerPin);
        }
        $resp = curl_exec($ch);
        if ($resp === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new \RuntimeException("trasporto verso il key-server fallito: $err");
        }
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return ['code' => $code, 'body' => (string)$resp];
    }

    public function fetchKey(string $module, int $ck, string $frag): array
    {
        // Opzione B: si richiede la chiave della SOLA porzione (frag_id).
        $body = json_encode([
            'module_id' => $module,
            'ck_version' => $ck,
            'frag_id' => $frag,
            'license_token' => $this->cfg->licenseToken,
        ]);
        $headers = $this->signedHeaders('POST', '/key', $body);
        $r = $this->http('POST', '/key', $headers, $body);
        $data = json_decode($r['body'], true);
        if (!is_array($data)) {
            throw new \RuntimeException("risposta /key non valida (HTTP {$r['code']})");
        }
        $data['_http'] = $r['code'];
        return $data;
    }

    public function postTamper(string $tipo, ?string $dettaglio): void
    {
        $body = json_encode(['tipo' => $tipo, 'dettaglio' => $dettaglio]);
        try {
            $this->http('POST', '/tamper', $this->signedHeaders('POST', '/tamper', $body), $body);
        } catch (\Throwable $e) {
            // Reporting non bloccante: si ignora l'errore (INVARIANTE 7).
        }
    }

    public function fetchStatus(): ?array
    {
        // Riporta la versione della libreria → lo studio sa se è aggiornata.
        $body = json_encode(['client_version' => Runtime::VERSION]);
        try {
            $r = $this->http('POST', '/status', $this->signedHeaders('POST', '/status', $body), $body);
        } catch (\Throwable $e) {
            return null; // disponibilità: il chiamante terrà l'ultimo stato noto
        }
        $data = json_decode($r['body'], true);
        if (!is_array($data) || !isset($data['signed_status'])) { return null; }
        $token = (string)$data['signed_status'];
        $payload = Crypto::verifyToken($this->cfg->ed25519PublicKeyPem, $token);
        if ($payload === null) { return null; }                       // firma non valida → ignora
        if (($payload['type'] ?? '') !== 'vaultcode/status/v1') { return null; }
        if (($payload['install_uuid'] ?? '') !== $this->cfg->installUuid) { return null; }
        $payload['_token'] = $token;                                   // per la cache firmata lato Runtime
        return $payload;
    }

    public function fetchRevocations(): ?array
    {
        try {
            $r = $this->http('GET', '/revocations', ['Accept: application/json'], '');
        } catch (\Throwable $e) {
            return null;
        }
        $data = json_decode($r['body'], true);
        if (!is_array($data) || !isset($data['signed_document'])) { return null; }
        $payload = Crypto::verifyToken($this->cfg->ed25519PublicKeyPem, (string)$data['signed_document']);
        if ($payload === null || !isset($payload['revoked'])) { return null; }
        $ids = [];
        foreach ((array)$payload['revoked'] as $rev) {
            if (isset($rev['license_id'])) { $ids[] = (string)$rev['license_id']; }
        }
        return $ids;
    }
}

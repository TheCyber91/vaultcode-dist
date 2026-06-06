<?php
declare(strict_types=1);

namespace VaultCode;

/**
 * Rilevazione anti-tamper (§11) — SOLO osservazione, mai reazione.
 *
 * Rileva segnali come un debugger/ptrace agganciato al processo (su Linux:
 * TracerPid != 0 in /proc/self/status). NON blocca, NON sabota, NON riavvia
 * (INVARIANTE 1, art. 615-quinquies): produce un segnale che il Runtime invia
 * come ALERT probatorio all'autore.
 *
 * Onestà (§3/§11): un attaccante con root e competenza aggira/spoofa il check;
 * serve ad alzare il costo per profili poco skillati. Best-effort e
 * multipiattaforma: dove non applicabile (es. Windows) non emette falsi positivi.
 */
final class Sentinel
{
    /** Estrae TracerPid dal contenuto di /proc/self/status. 0 = nessun debugger. */
    public static function tracerPidFromStatus(string $statusContent): int
    {
        if (preg_match('/^TracerPid:\s*(\d+)/m', $statusContent, $m)) {
            return (int)$m[1];
        }
        return 0;
    }

    /** @return list<string> segnali rilevati (es. 'debugger_rilevato'); [] se nessuno. */
    public static function detect(): array
    {
        $traced = false;
        // Runtime nativo (webdl_protect): anti-debug in codice compilato.
        if (function_exists('webdl_antidebug')) {
            try { $traced = (bool)webdl_antidebug(); } catch (\Throwable $e) { /* best-effort */ }
        }
        // Fallback/union: TracerPid da /proc/self/status (puro PHP).
        if (!$traced) {
            $status = '/proc/self/status';
            if (@is_readable($status)) {
                $content = (string)@file_get_contents($status);
                if (self::tracerPidFromStatus($content) > 0) {
                    $traced = true;
                }
            }
        }
        return $traced ? ['debugger_rilevato'] : [];
    }
}

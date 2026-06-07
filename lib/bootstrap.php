<?php
/**
 * VaultCode — bootstrap del runtime di protezione (NON bloccante, idempotente).
 *
 * Auto-incluso dai file protetti (header iniettato dal protect-tool): carica le
 * classi del runtime e inizializza VaultCode UNA volta per richiesta, SENZA
 * toccare l'entrypoint dell'applicazione ospite (niente modifica di core.php & co.).
 * Così la protezione **sopravvive agli update** del gestionale.
 *
 * Risolve tutto rispetto a __DIR__ (la cartella della libreria): va posizionato
 * accanto a `src/` e a `vaultcode.config.json` (layout standard: lib/vaultcode/).
 * I path RELATIVI nella config vengono ancorati a questa stessa cartella (vedi
 * Config::fromJsonFile), quindi funziona ovunque sia installato.
 */
if (!defined('VAULTCODE_BOOTSTRAPPED')) {
    define('VAULTCODE_BOOTSTRAPPED', true);
    try {
        $vc_dir = __DIR__;
        $vc_config = $vc_dir . '/vaultcode.config.json';
        if (is_file($vc_config)) {
            if (!class_exists('\\VaultCode\\Runtime')) {
                foreach (['Crypto', 'Config', 'Banner', 'Cache', 'Sentinel',
                          'KeyServerInterface', 'KeyServerClient', 'Runtime'] as $vc_c) {
                    $vc_f = $vc_dir . '/src/' . $vc_c . '.php';
                    if (is_file($vc_f)) { require_once $vc_f; }
                }
            }
            if (class_exists('\\VaultCode\\Runtime')) {
                \VaultCode\Runtime::init(\VaultCode\Config::fromJsonFile($vc_config));
            }
        }
    } catch (\Throwable $vc_e) {
        // Non bloccante (INVARIANTE 1): un bootstrap fallito non deve rompere l'app.
        error_log('[VaultCode] bootstrap: ' . $vc_e->getMessage());
    }
}

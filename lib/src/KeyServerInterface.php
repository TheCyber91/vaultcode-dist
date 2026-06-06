<?php
declare(strict_types=1);

namespace VaultCode;

/**
 * Astrazione del key-server (iniettabile → testabile senza rete).
 */
interface KeyServerInterface
{
    /**
     * Richiede la content key per (install, module, ck). Ritorna la risposta
     * decodificata (es. ['status'=>'granted','content_key'=>hex,'window'=>...]).
     * Solleva in caso di errore di TRASPORTO (rete/timeout).
     *
     * @return array<string,mixed>
     */
    public function fetchKey(string $module, int $ck, string $frag): array;

    /**
     * Lista (verificata Ed25519) dei license_id revocati, o null se non
     * disponibile/non verificabile.
     *
     * @return list<string>|null
     */
    public function fetchRevocations(): ?array;

    /**
     * Invia un alert anti-tamper (§11) all'autore. Best-effort/non bloccante:
     * un fallimento non deve interrompere l'applicazione del cliente.
     */
    public function postTamper(string $tipo, ?string $dettaglio): void;

    /**
     * Stato d'integrità FIRMATO dell'installazione (per il badge cliente
     * "server-confermato"). Ritorna il payload verificato
     * (['integrity'=>'ok'|'alert', ..., '_token'=>signed]) o null se non
     * disponibile/non verificabile. NON solleva per problemi di disponibilità.
     *
     * @return array<string,mixed>|null
     */
    public function fetchStatus(): ?array;
}

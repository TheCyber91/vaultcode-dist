<?php
declare(strict_types=1);

namespace VaultCode;

/**
 * Banner NON bloccante (INVARIANTE 1, §6 art. 615-quinquies).
 *
 * Quando un contesto non è verificato (server irraggiungibile oltre il grace,
 * licenza non valida, ecc.) si emette un AVVISO, ma il software CONTINUA a
 * funzionare. Nessun blocco, nessuna cancellazione, nessun sabotaggio.
 *
 * Il sink è iniettabile (default: error_log) per integrarsi con il logging del
 * cliente senza interrompere l'esecuzione.
 */
final class Banner
{
    /** @var callable */
    private $sink;
    /** @var array<string,bool> dedup per messaggio nella stessa richiesta */
    private array $seen = [];

    public function __construct(?callable $sink = null)
    {
        $this->sink = $sink ?? static function (string $msg): void { error_log($msg); };
    }

    public function notify(string $message): void
    {
        if (isset($this->seen[$message])) { return; }
        $this->seen[$message] = true;
        ($this->sink)("[VaultCode] $message");
        // NB: nessun exit/die/throw. L'esecuzione prosegue.
    }
}

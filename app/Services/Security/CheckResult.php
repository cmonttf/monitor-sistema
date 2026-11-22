<?php

namespace App\Services\Security;

use App\Enums\CheckStatus;

/**
 * Resultado inmutable de un chequeo de seguridad.
 *
 * @package App\Services\Security
 */
final readonly class CheckResult
{
    /**
     * Información adicional (paquetes, puertos, fechas...), siempre como lista.
     *
     * @var list<string>
     */
    public array $details;

    /**
     * @param CheckStatus  $status  Estado del chequeo.
     * @param string  $message  Resumen en una línea.
     * @param array<array-key, string>  $details  Información adicional; se reindexa como lista.
     */
    public function __construct(
        public CheckStatus $status,
        public string $message,
        array $details = [],
    ) {
        $this->details = array_values($details);
    }

    /**
     * @param  array<array-key, string>  $details
     * @return self
     */
    public static function ok(string $message, array $details = []): self
    {
        return new self(CheckStatus::Ok, $message, $details);
    }

    /**
     * @param  array<array-key, string>  $details
     * @return self
     */
    public static function warning(string $message, array $details = []): self
    {
        return new self(CheckStatus::Warning, $message, $details);
    }

    /**
     * @param  array<array-key, string>  $details
     * @return self
     */
    public static function critical(string $message, array $details = []): self
    {
        return new self(CheckStatus::Critical, $message, $details);
    }

    /**
     * @param  array<array-key, string>  $details
     * @return self
     */
    public static function unknown(string $message, array $details = []): self
    {
        return new self(CheckStatus::Unknown, $message, $details);
    }
}

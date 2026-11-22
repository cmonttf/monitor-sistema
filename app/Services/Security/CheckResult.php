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
     * @param  CheckStatus  $status  Estado del chequeo.
     * @param  string  $message  Resumen en una línea.
     * @param  list<string>  $details  Información adicional (paquetes, puertos, fechas...).
     */
    public function __construct(
        public CheckStatus $status,
        public string $message,
        public array $details = [],
    ) {}

    /**
     * @param  list<string>  $details
     * @return self
     */
    public static function ok(string $message, array $details = []): self
    {
        return new self(CheckStatus::Ok, $message, $details);
    }

    /**
     * @param  list<string>  $details
     * @return self
     */
    public static function warning(string $message, array $details = []): self
    {
        return new self(CheckStatus::Warning, $message, $details);
    }

    /**
     * @param  list<string>  $details
     * @return self
     */
    public static function critical(string $message, array $details = []): self
    {
        return new self(CheckStatus::Critical, $message, $details);
    }

    /**
     * @param  list<string>  $details
     * @return self
     */
    public static function unknown(string $message, array $details = []): self
    {
        return new self(CheckStatus::Unknown, $message, $details);
    }
}

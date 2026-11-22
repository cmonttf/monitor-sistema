<?php

namespace App\Services\Security;

use App\Enums\CheckStatus;

/**
 * Resultado inmutable de un chequeo de seguridad.
 *
 * @package App\Services\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
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
     * Pasos para solucionar el problema detectado, en orden.
     *
     * @var list<FixStep>
     */
    public array $fix;

    /**
     * Crea el resultado de un chequeo.
     *
     * @param CheckStatus                $status  Estado del chequeo.
     * @param string                     $message Resumen en una línea.
     * @param array<array-key, string>   $details Información adicional; se reindexa como lista.
     * @param array<array-key, FixStep>  $fix     Pasos para solucionarlo; se reindexan como lista.
     */
    public function __construct(
        public CheckStatus $status,
        public string $message,
        array $details = [],
        array $fix = [],
    ) {
        $this->details = array_values($details);
        $this->fix = array_values($fix);
    }

    /**
     * Crea un resultado correcto.
     *
     * @param string                   $message Resumen en una línea.
     * @param array<array-key, string> $details Información adicional.
     *
     * @return self Resultado con estado ok.
     */
    public static function ok(string $message, array $details = []): self
    {
        return new self(CheckStatus::Ok, $message, $details);
    }

    /**
     * Crea un resultado de advertencia.
     *
     * @param string                    $message Resumen en una línea.
     * @param array<array-key, string>  $details Información adicional.
     * @param array<array-key, FixStep> $fix     Pasos para solucionarlo.
     *
     * @return self Resultado con estado warning.
     */
    public static function warning(string $message, array $details = [], array $fix = []): self
    {
        return new self(CheckStatus::Warning, $message, $details, $fix);
    }

    /**
     * Crea un resultado crítico.
     *
     * @param string                    $message Resumen en una línea.
     * @param array<array-key, string>  $details Información adicional.
     * @param array<array-key, FixStep> $fix     Pasos para solucionarlo.
     *
     * @return self Resultado con estado critical.
     */
    public static function critical(string $message, array $details = [], array $fix = []): self
    {
        return new self(CheckStatus::Critical, $message, $details, $fix);
    }

    /**
     * Crea un resultado sin datos.
     *
     * @param string                    $message Resumen en una línea.
     * @param array<array-key, string>  $details Información adicional.
     * @param array<array-key, FixStep> $fix     Pasos para instalar o habilitar lo que falta.
     *
     * @return self Resultado con estado unknown.
     */
    public static function unknown(string $message, array $details = [], array $fix = []): self
    {
        return new self(CheckStatus::Unknown, $message, $details, $fix);
    }
}

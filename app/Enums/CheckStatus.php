<?php

namespace App\Enums;

/**
 * Estado resultante de un chequeo de seguridad.
 *
 * @package App\Enums
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
enum CheckStatus: string
{
    case Ok = 'ok';
    case Warning = 'warning';
    case Critical = 'critical';
    case Unknown = 'unknown';

    /**
     * Etiqueta legible en español.
     *
     * @return string
     */
    public function label(): string
    {
        return match ($this) {
            self::Ok => 'Al día',
            self::Warning => 'Atención',
            self::Critical => 'Crítico',
            self::Unknown => 'Sin datos',
        };
    }

    /**
     * Peso usado para determinar el estado global (mayor es peor).
     *
     * @return int
     */
    public function severity(): int
    {
        return match ($this) {
            self::Ok => 0,
            self::Unknown => 1,
            self::Warning => 2,
            self::Critical => 3,
        };
    }
}

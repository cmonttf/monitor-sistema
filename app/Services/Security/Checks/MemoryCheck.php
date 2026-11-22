<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;
use App\Services\Security\ResourceSampler;

/**
 * Uso de la memoria RAM y del área de intercambio (swap).
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class MemoryCheck implements SecurityCheck
{
    /**
     * Porcentaje de RAM usada a partir del cual se muestra una advertencia.
     */
    public const int WARNING_PERCENT = 85;

    /**
     * Porcentaje de RAM usada a partir del cual el estado es crítico.
     */
    public const int CRITICAL_PERCENT = 95;

    /**
     * Porcentaje de swap usada a partir del cual se muestra una advertencia.
     */
    public const int SWAP_WARNING_PERCENT = 80;

    /**
     * Recibe el lector de uso de recursos.
     *
     * @param ResourceSampler $resources Lector de memoria y discos.
     */
    public function __construct(private ResourceSampler $resources)
    {
    }

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Memoria RAM';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Recursos';
    }

    /**
     * Calcula el porcentaje de RAM usada: desde 85 % es advertencia y desde 95 % es crítico.
     * También advierte si la swap supera el 80 %, señal de que la RAM no alcanza.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $memory = $this->resources->memory();

        if ($memory === null) {
            return CheckResult::unknown('No se pudo leer el uso de memoria.');
        }

        $usedPercent = $memory['used'] / $memory['total'] * 100;
        $swapPercent = $memory['swap_total'] > 0 ? $memory['swap_used'] / $memory['swap_total'] * 100 : 0;
        $format = ResourceSampler::formatBytes(...);

        $details = [
            'Total: ' . $format($memory['total']),
            'En uso: ' . $format($memory['used']) . ' (' . round($usedPercent) . ' %)',
            'Disponible: ' . $format($memory['available']),
            'Caché del sistema (se libera si hace falta): ' . $format($memory['cached']),
            $memory['swap_total'] > 0
                ? 'Swap: ' . $format($memory['swap_used']) . ' de ' . $format($memory['swap_total'])
                    . ' (' . round($swapPercent) . ' %)'
                : 'Swap: no configurada',
        ];

        $message = 'Quedan ' . $format($memory['available']) . ' disponibles de ' . $format($memory['total'])
            . ' (' . round($usedPercent) . ' % en uso).';

        return match (true) {
            $usedPercent >= self::CRITICAL_PERCENT => CheckResult::critical($message, $details, $this->fixSteps()),
            $usedPercent >= self::WARNING_PERCENT => CheckResult::warning($message, $details, $this->fixSteps()),
            $swapPercent >= self::SWAP_WARNING_PERCENT => CheckResult::warning(
                'La swap está al ' . round($swapPercent) . ' %: la RAM no alcanza para lo que tienes abierto.',
                $details,
                $this->fixSteps()
            ),
            default => CheckResult::ok($message, $details),
        };
    }

    /**
     * Pasos para liberar memoria.
     *
     * @return list<FixStep> Pasos de solución.
     */
    private function fixSteps(): array
    {
        return [
            FixStep::command(
                'Identifica los procesos que más memoria usan.',
                'ps -eo pid,comm,%mem,rss --sort=-%mem | head -n 15'
            ),
            FixStep::note('Cierra las aplicaciones y pestañas del navegador que no estés usando.'),
            FixStep::note('Si la memoria se agota a menudo, considera ampliar la RAM del equipo.'),
        ];
    }
}

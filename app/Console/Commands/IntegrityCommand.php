<?php

namespace App\Console\Commands;

use App\Services\Security\IntegrityBaseline;
use App\Services\Security\IntegritySnapshot;
use App\Services\Security\SecurityMonitor;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;

/**
 * Muestra los cambios en los elementos vigilados por el monitor de integridad y, con --accept, los acepta
 * como nueva línea base.
 *
 * @package App\Console\Commands
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
#[Signature('monitor:integrity {--accept : Acepta el estado actual como nueva línea base}')]
#[Description('Muestra los cambios en archivos críticos y permite aceptarlos como nueva línea base')]
class IntegrityCommand extends Command
{
    /**
     * Lista los cambios respecto de la línea base y, si se pide, guarda el estado actual.
     *
     * @param IntegritySnapshot $snapshot Toma de huellas de los elementos vigilados.
     * @param IntegrityBaseline $baseline Línea base aceptada.
     * @param SecurityMonitor   $monitor  Monitor, para que el panel muestre el nuevo estado.
     *
     * @return int Código de salida.
     */
    public function handle(IntegritySnapshot $snapshot, IntegrityBaseline $baseline, SecurityMonitor $monitor): int
    {
        $current = $snapshot->capture();
        $saved = $baseline->load();

        if ($saved !== null) {
            $changes = IntegrityBaseline::compare($current, $saved['entries']);
            $rows = [
                ...array_map(fn (string $name): array => ['Modificado', $name], $changes['changed']),
                ...array_map(fn (string $name): array => ['Nuevo', $name], $changes['added']),
                ...array_map(fn (string $name): array => ['Eliminado', $name], $changes['removed']),
            ];

            $rows === []
                ? $this->components->info('No hay cambios desde la línea base.')
                : $this->table(['Cambio', 'Elemento'], $rows);
        }

        if (! $this->option('accept')) {
            if ($saved !== null) {
                $this->components->info('Para aceptar estos cambios: php artisan monitor:integrity --accept');
            }

            return self::SUCCESS;
        }

        $baseline->save($current);
        $monitor->forgetCachedReport();
        $this->components->info('Línea base actualizada con ' . count($current) . ' elementos.');

        return self::SUCCESS;
    }
}

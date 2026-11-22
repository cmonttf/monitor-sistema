<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;
use Illuminate\Support\Str;

/**
 * Paquetes Snap con actualizaciones pendientes.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class SnapUpdatesCheck extends SystemCheck
{
    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Aplicaciones Snap';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Actualizaciones';
    }

    /**
     * Consulta `snap refresh --list` y advierte si hay aplicaciones Snap con actualizaciones pendientes.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('snap')) {
            return CheckResult::unknown('Snap no está instalado.', [], [
                FixStep::note('No es necesario si no usas aplicaciones Snap.'),
                FixStep::command('Para instalarlo.', 'sudo apt install snapd'),
            ]);
        }

        $result = $this->system->run(['snap', 'refresh', '--list'], 30);

        if ($result->failed()) {
            return CheckResult::unknown('No se pudo consultar Snap.', [trim($result->errorOutput())]);
        }

        $lines = array_values(array_filter(explode("\n", trim($result->output()))));

        if ($lines === [] || ! str_starts_with($lines[0], 'Name')) {
            return CheckResult::ok('Todas las aplicaciones Snap están actualizadas.');
        }

        $snaps = array_map(fn (string $line): string => Str::before($line, ' '), array_slice($lines, 1));

        return CheckResult::warning(count($snaps) . ' aplicaciones Snap pendientes de actualizar.', $snaps, [
                FixStep::command('Actualiza todas las aplicaciones Snap.', 'sudo snap refresh'),
                FixStep::note(
                    'Si una aplicación está abierta, Snap puede posponer su actualización: ciérrala y repite el '
                        . 'comando.'
                ),
            ]);
    }
}

<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use Illuminate\Support\Str;

/**
 * Paquetes Snap con actualizaciones pendientes.
 *
 * @package App\Services\Security\Checks
 */
class SnapUpdatesCheck extends SystemCheck
{
    public function name(): string
    {
        return 'Aplicaciones Snap';
    }

    public function category(): string
    {
        return 'Actualizaciones';
    }

    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('snap')) {
            return CheckResult::unknown('Snap no está instalado.');
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

        return CheckResult::warning(count($snaps).' aplicaciones Snap pendientes de actualizar.', $snaps);
    }
}

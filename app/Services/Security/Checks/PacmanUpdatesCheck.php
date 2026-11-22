<?php

namespace App\Services\Security\Checks;

use App\Enums\LinuxFamily;
use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;
use App\Services\Security\Platform;

/**
 * Paquetes pendientes de actualizar en Arch y derivadas, con `checkupdates` (pacman-contrib), que consulta
 * los repositorios sin modificar la base de datos del sistema.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class PacmanUpdatesCheck extends SystemCheck
{
    /**
     * Código de salida de `checkupdates` cuando no hay actualizaciones.
     */
    private const int NO_UPDATES_EXIT_CODE = 2;

    /**
     * Cantidad máxima de paquetes listados en los detalles de la tarjeta.
     */
    private const int MAX_LISTED = 25;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Paquetes del sistema (pacman)';
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
     * Aplica sólo a la familia Arch.
     *
     * @param Platform $platform Plataforma en la que corre el monitor.
     *
     * @return bool true en Arch y derivadas.
     */
    public function supports(Platform $platform): bool
    {
        return $platform->isLinux(LinuxFamily::Arch);
    }

    /**
     * Advertencia si hay paquetes pendientes. Arch no distingue actualizaciones de seguridad: se actualiza
     * todo el sistema a la vez.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('checkupdates')) {
            return CheckResult::unknown('Falta checkupdates para consultar las actualizaciones.', [], [
                $this->platform->installStep('Instala pacman-contrib, que incluye checkupdates.', 'pacman-contrib'),
            ]);
        }

        $result = $this->system->run(['checkupdates'], 120);

        if ($result->exitCode() === self::NO_UPDATES_EXIT_CODE) {
            return CheckResult::ok('Todos los paquetes están actualizados.');
        }

        if ($result->failed()) {
            return CheckResult::unknown(
                'No se pudo consultar las actualizaciones.',
                array_filter([trim($result->errorOutput())])
            );
        }

        $packages = array_values(array_filter(array_map(
            fn (string $line): string => strtok(trim($line), ' ') ?: '',
            explode("\n", trim($result->output()))
        )));

        if ($packages === []) {
            return CheckResult::ok('Todos los paquetes están actualizados.');
        }

        $details = array_slice($packages, 0, self::MAX_LISTED);

        if (count($packages) > self::MAX_LISTED) {
            $details[] = '… y ' . (count($packages) - self::MAX_LISTED) . ' más';
        }

        return CheckResult::warning(count($packages) . ' paquetes pendientes de actualizar.', $details, [
            FixStep::command('Actualiza todo el sistema.', 'sudo pacman -Syu'),
            FixStep::note(
                'Antes de actualizar, revisa las noticias de archlinux.org por si requieren intervención manual.'
            ),
        ]);
    }
}

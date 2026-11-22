<?php

namespace App\Services\Security\Checks;

use App\Services\Security\Platform;
use App\Services\Security\SystemInspector;

/**
 * Base para los chequeos que inspeccionan el sistema operativo. Por defecto aplican a cualquier Linux;
 * los chequeos de una familia concreta o de Windows sobrescriben supports().
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
abstract class SystemCheck implements SecurityCheck
{
    /**
     * Recibe el acceso al sistema operativo y la plataforma detectada.
     *
     * @param SystemInspector $system   Acceso a comandos y archivos del sistema.
     * @param Platform        $platform Plataforma en la que corre el monitor.
     */
    public function __construct(protected SystemInspector $system, protected Platform $platform)
    {
    }

    /**
     * Aplica a cualquier distribución Linux.
     *
     * @param Platform $platform Plataforma en la que corre el monitor.
     *
     * @return bool true en Linux.
     */
    public function supports(Platform $platform): bool
    {
        return $platform->isLinux();
    }
}

<?php

namespace App\Services\Security\Checks;

use App\Services\Security\Platform;

/**
 * Base para los chequeos de Windows, que consultan el sistema con Windows PowerShell sin privilegios
 * de administrador.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
abstract class WindowsCheck extends SystemCheck
{
    /**
     * Aplica sólo a Windows.
     *
     * @param Platform $platform Plataforma en la que corre el monitor.
     *
     * @return bool true en Windows.
     */
    public function supports(Platform $platform): bool
    {
        return $platform->isWindows();
    }
}

<?php

namespace App\Services\Security\Checks;

use App\Services\Security\SystemInspector;

/**
 * Base para los chequeos que inspeccionan el sistema operativo.
 *
 * @package App\Services\Security\Checks
 */
abstract class SystemCheck implements SecurityCheck
{
    /**
     * @param SystemInspector  $system  Acceso a comandos y archivos del sistema.
     */
    public function __construct(protected SystemInspector $system)
    {
    }
}

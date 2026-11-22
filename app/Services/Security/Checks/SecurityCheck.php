<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\Platform;

/**
 * Contrato de un chequeo de seguridad mostrado en el monitor.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
interface SecurityCheck
{
    /**
     * Nombre visible del chequeo.
     *
     * @return string
     */
    public function name(): string;

    /**
     * Categoría con la que se agrupa en el panel.
     *
     * @return string
     */
    public function category(): string;

    /**
     * Ejecuta el chequeo.
     *
     * @return CheckResult
     */
    public function run(): CheckResult;

    /**
     * Indica si el chequeo aplica a la plataforma; los que no aplican no se muestran.
     *
     * @param Platform $platform Plataforma en la que corre el monitor.
     *
     * @return bool true si el chequeo debe ejecutarse.
     */
    public function supports(Platform $platform): bool;
}

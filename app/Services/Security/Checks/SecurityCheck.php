<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Contrato de un chequeo de seguridad mostrado en el monitor.
 *
 * @package App\Services\Security\Checks
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
}

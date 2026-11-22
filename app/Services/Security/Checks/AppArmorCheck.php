<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Módulo de control de acceso obligatorio AppArmor.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class AppArmorCheck extends SystemCheck
{
    /**
     * Parámetro del kernel que vale "Y" cuando AppArmor está habilitado.
     */
    private const string PARAMETER = '/sys/module/apparmor/parameters/enabled';

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'AppArmor';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Sistema';
    }

    /**
     * Lee el parámetro del kernel de AppArmor; si no está habilitado el estado es crítico.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $value = trim($this->system->readFile(self::PARAMETER) ?? '');

        if ($value === 'Y') {
            return CheckResult::ok('AppArmor está habilitado en el kernel.');
        }

        return CheckResult::critical('AppArmor está deshabilitado.');
    }
}

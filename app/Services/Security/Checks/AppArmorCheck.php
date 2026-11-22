<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Módulo de control de acceso obligatorio AppArmor.
 *
 * @package App\Services\Security\Checks
 */
class AppArmorCheck extends SystemCheck
{
    private const string PARAMETER = '/sys/module/apparmor/parameters/enabled';

    public function name(): string
    {
        return 'AppArmor';
    }

    public function category(): string
    {
        return 'Sistema';
    }

    public function run(): CheckResult
    {
        $value = trim($this->system->readFile(self::PARAMETER) ?? '');

        if ($value === 'Y') {
            return CheckResult::ok('AppArmor está habilitado en el kernel.');
        }

        return CheckResult::critical('AppArmor está deshabilitado.');
    }
}

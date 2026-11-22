<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Estado del cortafuegos UFW.
 *
 * @package App\Services\Security\Checks
 */
class FirewallCheck extends SystemCheck
{
    private const string CONFIG = '/etc/ufw/ufw.conf';

    public function name(): string
    {
        return 'Cortafuegos (UFW)';
    }

    public function category(): string
    {
        return 'Protección';
    }

    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('ufw')) {
            return CheckResult::critical('No hay cortafuegos UFW instalado.', ['sudo apt install ufw && sudo ufw enable']);
        }

        $isEnabled = preg_match('/^\s*ENABLED\s*=\s*yes/mi', $this->system->readFile(self::CONFIG) ?? '') === 1;
        $serviceState = $this->system->serviceState('ufw');

        if ($isEnabled && $serviceState === 'active') {
            return CheckResult::ok('El cortafuegos está activo.');
        }

        return CheckResult::critical('El cortafuegos está desactivado.', ["Servicio: {$serviceState}", 'Activar con: sudo ufw enable']);
    }
}

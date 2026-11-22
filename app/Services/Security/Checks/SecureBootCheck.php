<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Estado del arranque seguro UEFI.
 *
 * @package App\Services\Security\Checks
 */
class SecureBootCheck extends SystemCheck
{
    public function name(): string
    {
        return 'Arranque seguro (Secure Boot)';
    }

    public function category(): string
    {
        return 'Sistema';
    }

    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('mokutil')) {
            return CheckResult::unknown('mokutil no está instalado.');
        }

        $output = $this->system->run(['mokutil', '--sb-state'])->output();

        return match (true) {
            str_contains($output, 'SecureBoot enabled') => CheckResult::ok('Secure Boot está activado.'),
            str_contains($output, 'SecureBoot disabled') => CheckResult::warning('Secure Boot está desactivado.'),
            default => CheckResult::unknown('No se pudo determinar el estado de Secure Boot.', array_filter([trim($output)])),
        };
    }
}

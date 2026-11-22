<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Servicio que descarga las firmas de ClamAV (freshclam).
 *
 * @package App\Services\Security\Checks
 */
class AntivirusUpdaterCheck extends SystemCheck
{
    public function name(): string
    {
        return 'Actualizador del antivirus';
    }

    public function category(): string
    {
        return 'Protección';
    }

    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('freshclam')) {
            return CheckResult::unknown('freshclam no está instalado.');
        }

        $state = $this->system->serviceState('clamav-freshclam');

        return match ($state) {
            'active' => CheckResult::ok('El servicio freshclam está funcionando.'),
            'failed' => CheckResult::critical('El servicio freshclam falló; las firmas no se actualizan.', [
                'Diagnóstico: journalctl -u clamav-freshclam -n 30',
                'Reiniciar: sudo systemctl restart clamav-freshclam',
            ]),
            default => CheckResult::warning("El servicio freshclam no está activo ({$state}).", [
                'Activar: sudo systemctl enable --now clamav-freshclam',
            ]),
        };
    }
}

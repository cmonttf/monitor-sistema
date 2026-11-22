<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Servicio de escaneo en segundo plano de ClamAV (clamd).
 *
 * @package App\Services\Security\Checks
 */
class AntivirusDaemonCheck extends SystemCheck
{
    public function name(): string
    {
        return 'Escáner del antivirus (clamd)';
    }

    public function category(): string
    {
        return 'Protección';
    }

    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('clamd')) {
            return CheckResult::unknown('clamav-daemon no está instalado.');
        }

        $state = $this->system->serviceState('clamav-daemon');

        return match ($state) {
            'active' => CheckResult::ok('El escáner clamd está funcionando.'),
            'activating' => CheckResult::ok('El escáner clamd está cargando las firmas.'),
            'failed' => CheckResult::critical('El escáner clamd falló y no está escaneando.', [
                'Diagnóstico: journalctl -u clamav-daemon -n 30',
                'Reiniciar: sudo systemctl reset-failed clamav-daemon && sudo systemctl restart clamav-daemon',
            ]),
            default => CheckResult::warning("El escáner clamd no está activo ({$state}).", [
                'Activar: sudo systemctl enable --now clamav-daemon',
            ]),
        };
    }
}

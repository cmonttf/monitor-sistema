<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Servicio que descarga las firmas de ClamAV (freshclam).
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class AntivirusUpdaterCheck extends SystemCheck
{
    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Actualizador del antivirus';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Protección';
    }

    /**
     * Revisa el servicio clamav-freshclam: activo es correcto, fallido es crítico y detenido es una advertencia.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
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

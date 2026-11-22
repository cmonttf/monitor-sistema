<?php

namespace App\Services\Security\Checks;

use App\Enums\LinuxFamily;
use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

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
            return CheckResult::unknown('freshclam no está instalado.', [], [
                $this->platform->installStep(
                    'Instala el actualizador de firmas de ClamAV.',
                    $this->platform->family === LinuxFamily::RedHat ? 'clamav-update' : 'clamav-freshclam'
                ),
            ]);
        }

        $state = $this->system->serviceState('clamav-freshclam');

        return match ($state) {
            'active' => CheckResult::ok('El servicio freshclam está funcionando.'),
            'failed' => CheckResult::critical('El servicio freshclam falló; las firmas no se actualizan.', [], [
                FixStep::command('Revisa por qué falló.', 'journalctl -u clamav-freshclam -n 30'),
                FixStep::command(
                    'Reinícialo.',
                    'sudo systemctl reset-failed clamav-freshclam && sudo systemctl restart clamav-freshclam'
                ),
            ]),
            default => CheckResult::warning("El servicio freshclam no está activo ({$state}).", [], [
                FixStep::command(
                    'Actívalo y haz que arranque con el equipo.',
                    'sudo systemctl enable --now clamav-freshclam'
                ),
            ]),
        };
    }
}

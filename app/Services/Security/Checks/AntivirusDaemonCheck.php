<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Servicio de escaneo en segundo plano de ClamAV (clamd).
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class AntivirusDaemonCheck extends SystemCheck
{
    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Escáner del antivirus (clamd)';
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
     * Revisa el servicio clamav-daemon: activo o cargando firmas es correcto, fallido es crítico
     * y detenido es una advertencia.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('clamd')) {
            return CheckResult::unknown('clamav-daemon no está instalado.', [], [
                FixStep::note('Sólo es necesario para escanear en segundo plano con clamdscan.'),
                FixStep::command('Para instalarlo.', 'sudo apt install clamav-daemon'),
            ]);
        }

        $state = $this->system->serviceState('clamav-daemon');

        return match ($state) {
            'active' => CheckResult::ok('El escáner clamd está funcionando.'),
            'activating' => CheckResult::ok('El escáner clamd está cargando las firmas.'),
            'failed' => CheckResult::critical('El escáner clamd falló y no está escaneando.', [], [
                FixStep::command(
                    'Revisa por qué falló (un error de «database integrity» indica firmas dañadas o antiguas).',
                    'journalctl -u clamav-daemon -n 30'
                ),
                FixStep::command(
                    'Reinícialo.',
                    'sudo systemctl reset-failed clamav-daemon && sudo systemctl restart clamav-daemon'
                ),
            ]),
            default => CheckResult::warning("El escáner clamd no está activo ({$state}).", [], [
                FixStep::command(
                    'Actívalo y haz que arranque con el equipo (usa unos 1 GB de RAM).',
                    'sudo systemctl enable --now clamav-daemon clamav-daemon.socket'
                ),
                FixStep::note(
                    'Si no escaneas en segundo plano, puedes dejarlo desactivado: las firmas se siguen actualizando.'
                ),
            ]),
        };
    }
}

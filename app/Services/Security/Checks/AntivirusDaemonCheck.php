<?php

namespace App\Services\Security\Checks;

use App\Enums\LinuxFamily;
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
     * Revisa el servicio del escáner (clamav-daemon, o clamd@scan en Fedora/RHEL): activo o cargando
     * firmas es correcto, fallido es crítico
     * y detenido es una advertencia.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('clamd')) {
            return CheckResult::unknown('El escáner clamd no está instalado.', [], [
                FixStep::note('Sólo es necesario para escanear en segundo plano con clamdscan.'),
                $this->platform->installStep('Para instalarlo.', match ($this->platform->family) {
                    LinuxFamily::RedHat => 'clamd',
                    LinuxFamily::Arch => 'clamav',
                    default => 'clamav-daemon',
                }),
            ]);
        }

        $service = $this->platform->family === LinuxFamily::RedHat ? 'clamd@scan' : 'clamav-daemon';
        $state = $this->system->serviceState($service);

        return match ($state) {
            'active' => CheckResult::ok('El escáner clamd está funcionando.'),
            'activating' => CheckResult::ok('El escáner clamd está cargando las firmas.'),
            'failed' => CheckResult::critical('El escáner clamd falló y no está escaneando.', [], [
                FixStep::command(
                    'Revisa por qué falló (un error de «database integrity» indica firmas dañadas o antiguas).',
                    "journalctl -u {$service} -n 30"
                ),
                FixStep::command(
                    'Reinícialo.',
                    "sudo systemctl reset-failed {$service} && sudo systemctl restart {$service}"
                ),
            ]),
            default => CheckResult::warning("El escáner clamd no está activo ({$state}).", [], [
                FixStep::command(
                    'Actívalo y haz que arranque con el equipo (usa unos 1 GB de RAM).',
                    $service === 'clamav-daemon'
                        ? 'sudo systemctl enable --now clamav-daemon clamav-daemon.socket'
                        : "sudo systemctl enable --now {$service}"
                ),
                FixStep::note(
                    'Si no escaneas en segundo plano, puedes dejarlo desactivado: las firmas se siguen actualizando.'
                ),
            ]),
        };
    }
}

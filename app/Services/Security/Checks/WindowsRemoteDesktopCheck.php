<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Escritorio remoto (RDP) de Windows y su autenticación a nivel de red (NLA).
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class WindowsRemoteDesktopCheck extends WindowsCheck
{
    /**
     * Lee si se aceptan conexiones de escritorio remoto y si exigen autenticación a nivel de red.
     */
    private const string SCRIPT = <<<'PS'
        $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        $server = Get-ItemProperty $base -ErrorAction SilentlyContinue
        $rdp = Get-ItemProperty "$base\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue
        [pscustomobject]@{ denyConnections = $server.fDenyTSConnections; networkLevelAuth = $rdp.UserAuthentication }
        PS;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Escritorio remoto (RDP)';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Red';
    }

    /**
     * Correcto si está desactivado; advertencia si está activo con NLA y crítico si está activo sin NLA.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $data = $this->system->powershell(self::SCRIPT);

        if ($data === null) {
            return CheckResult::unknown('No se pudo leer la configuración de escritorio remoto.');
        }

        if ((int) ($data['denyConnections'] ?? 1) === 1) {
            return CheckResult::ok('El escritorio remoto está desactivado.');
        }

        $steps = [
            FixStep::command('Abre la configuración de escritorio remoto.', 'start ms-settings:remotedesktop'),
            FixStep::note('Si no necesitas entrar a este equipo a distancia, desactívalo.'),
        ];

        if ((int) ($data['networkLevelAuth'] ?? 0) !== 1) {
            return CheckResult::critical(
                'El escritorio remoto está activo sin autenticación a nivel de red (NLA).',
                [],
                [
                    ...$steps,
                    FixStep::note(
                        'Si lo necesitas, activa «Requerir que los equipos usen la autenticación a nivel de red».'
                    ),
                ]
            );
        }

        return CheckResult::warning('El escritorio remoto está activo.', [], $steps);
    }
}

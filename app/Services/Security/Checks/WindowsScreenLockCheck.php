<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Bloqueo automático de la sesión de Windows por inactividad: política de inactividad del equipo o
 * protector de pantalla con contraseña.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class WindowsScreenLockCheck extends WindowsCheck
{
    /**
     * Lee el protector de pantalla del usuario y la política de inactividad del equipo.
     */
    private const string SCRIPT = <<<'PS'
        $desktop = Get-ItemProperty 'HKCU:\Control Panel\Desktop' -ErrorAction SilentlyContinue
        $policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $policy = Get-ItemProperty $policyPath -ErrorAction SilentlyContinue
        [pscustomobject]@{
            saverActive = [string]$desktop.ScreenSaveActive
            saverSecure = [string]$desktop.ScreenSaverIsSecure
            saverTimeout = [string]$desktop.ScreenSaveTimeOut
            inactivityTimeout = $policy.InactivityTimeoutSecs
        }
        PS;

    /**
     * Segundos máximos de inactividad recomendados antes de bloquear la sesión.
     */
    private const int MAX_IDLE_SECONDS = 900;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Bloqueo de pantalla';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Sistema';
    }

    /**
     * Correcto si la política de inactividad o el protector de pantalla con contraseña bloquean la sesión
     * en 15 minutos o menos; advertencia en otro caso.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $data = $this->system->powershell(self::SCRIPT);

        if ($data === null) {
            return CheckResult::unknown('No se pudo leer la configuración de bloqueo.');
        }

        $policySeconds = (int) ($data['inactivityTimeout'] ?? 0);

        if ($policySeconds > 0 && $policySeconds <= self::MAX_IDLE_SECONDS) {
            return CheckResult::ok(
                'La sesión se bloquea tras ' . intdiv($policySeconds, 60)
                    . ' minutos de inactividad (política del equipo).'
            );
        }

        $saverSeconds = (int) ($data['saverTimeout'] ?? 0);
        $isSaverLocking = ($data['saverActive'] ?? '') === '1' && ($data['saverSecure'] ?? '') === '1';

        if ($isSaverLocking && $saverSeconds > 0 && $saverSeconds <= self::MAX_IDLE_SECONDS) {
            return CheckResult::ok(
                'La sesión se bloquea tras ' . intdiv($saverSeconds, 60) . ' minutos con el protector de pantalla.'
            );
        }

        $message = $isSaverLocking
            ? 'La sesión se bloquea tras ' . intdiv($saverSeconds, 60) . ' minutos; se recomienda 15 o menos.'
            : 'No hay un bloqueo automático de la sesión por inactividad.';

        return CheckResult::warning($message, [], [
            FixStep::command('Abre la configuración del protector de pantalla.', 'control desk.cpl,,@screensaver'),
            FixStep::note(
                'Elige un protector, define 5 a 10 minutos y marca «Mostrar la pantalla de inicio de sesión al '
                . 'reanudar».'
            ),
            FixStep::note('Al alejarte del equipo, bloquéalo con Win+L.'),
        ]);
    }
}

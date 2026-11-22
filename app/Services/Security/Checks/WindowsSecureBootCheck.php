<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Arranque seguro UEFI en Windows, leído del registro sin permisos de administrador.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class WindowsSecureBootCheck extends WindowsCheck
{
    /**
     * Lee UEFISecureBootEnabled; la clave no existe en equipos con BIOS heredada.
     */
    private const string SCRIPT = <<<'PS'
        $value = $null
        try {
            $state = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction Stop
            $value = $state.UEFISecureBootEnabled
        } catch {}
        [pscustomobject]@{ enabled = $value }
        PS;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Arranque seguro (Secure Boot)';
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
     * Correcto si está activado, advertencia si está desactivado y sin datos si no se pudo leer.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $enabled = $this->system->powershell(self::SCRIPT)['enabled'] ?? null;

        return match ($enabled === null ? null : (int) $enabled) {
            1 => CheckResult::ok('Secure Boot está activado.'),
            0 => CheckResult::warning('Secure Boot está desactivado.', [], [
                FixStep::note(
                    'Reinicia y entra a la configuración UEFI/BIOS (normalmente con F2, F10, F12 o Supr al encender).'
                ),
                FixStep::note('Activa «Secure Boot» en la sección de seguridad o arranque, guarda y reinicia.'),
            ]),
            default => CheckResult::unknown(
                'No se pudo leer el estado de Secure Boot (puede ser un equipo con BIOS heredada).',
                [],
                [
                    FixStep::command(
                        'Revísalo en Información del sistema, en «Estado de arranque seguro».',
                        'msinfo32'
                    ),
                ]
            ),
        };
    }
}

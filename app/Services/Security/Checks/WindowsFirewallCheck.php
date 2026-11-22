<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Perfiles del Firewall de Windows (dominio, privado y público).
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class WindowsFirewallCheck extends WindowsCheck
{
    /**
     * Lee cada perfil del firewall: si está activo y su acción por defecto para el tráfico entrante.
     */
    private const string SCRIPT = <<<'PS'
        [pscustomobject]@{
            profiles = @(Get-NetFirewallProfile | ForEach-Object {
                [pscustomobject]@{
                    name = [string]$_.Name
                    enabled = ([string]$_.Enabled -eq 'True')
                    inbound = [string]$_.DefaultInboundAction
                }
            })
        }
        PS;

    /**
     * Nombres en español de los perfiles del firewall.
     */
    private const array PROFILE_NAMES = ['Domain' => 'Dominio', 'Private' => 'Privado', 'Public' => 'Público'];

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Firewall de Windows';
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
     * Crítico si algún perfil está desactivado; advertencia si alguno permite el tráfico entrante por defecto.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $data = $this->system->powershell(self::SCRIPT);
        $profiles = $data['profiles'] ?? [];

        if ($profiles === []) {
            return CheckResult::unknown('No se pudo consultar el Firewall de Windows.');
        }

        $label = fn (array $profile): string => self::PROFILE_NAMES[$profile['name']] ?? (string) $profile['name'];
        $details = array_map(
            fn (array $profile): string => 'Perfil ' . $label($profile) . ': ' . (
                $profile['enabled'] ? 'activo' : 'desactivado'
            ),
            $profiles
        );
        $disabled = array_map($label, array_filter($profiles, fn (array $profile): bool => ! $profile['enabled']));
        $allowing = array_map(
            $label,
            array_filter($profiles, fn (array $profile): bool => ($profile['inbound'] ?? '') === 'Allow')
        );

        if ($disabled !== []) {
            return CheckResult::critical(
                'El firewall está desactivado en el perfil ' . implode(', ', $disabled) . '.',
                $details,
                [
                    FixStep::command('Abre la configuración del firewall.', 'start windowsdefender://network'),
                    FixStep::note(
                        'Activa el «Firewall de Microsoft Defender» en cada red (requiere permisos de administrador).'
                    ),
                ]
            );
        }

        if ($allowing !== []) {
            return CheckResult::warning(
                'El perfil ' . implode(', ', $allowing) . ' permite conexiones entrantes por defecto.',
                $details,
                [
                    FixStep::command(
                        'Bloquea por defecto las conexiones entrantes (PowerShell como administrador).',
                        'Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block'
                    ),
                ]
            );
        }

        return CheckResult::ok('El firewall está activo en todos los perfiles.', $details);
    }
}

<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Puertos TCP de Windows escuchando fuera de la interfaz local y el programa que los usa.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class WindowsOpenPortsCheck extends WindowsCheck
{
    /**
     * Lista las conexiones TCP en escucha con su proceso y si el firewall está activo en todos los perfiles.
     */
    private const string SCRIPT = <<<'PS'
        [pscustomobject]@{
            listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
                [pscustomobject]@{
                    address = [string]$_.LocalAddress
                    port = [int]$_.LocalPort
                    process = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
                }
            })
            firewallEnabled = (@(Get-NetFirewallProfile | Where-Object { [string]$_.Enabled -ne 'True' }).Count -eq 0)
        }
        PS;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Puertos abiertos a la red';
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
     * Advertencia si hay puertos expuestos y el firewall no está activo en todos los perfiles; si lo está,
     * los lista como filtrados por sus reglas.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $data = $this->system->powershell(self::SCRIPT);

        if ($data === null) {
            return CheckResult::unknown('No se pudo listar los puertos.');
        }

        $exposed = [];

        foreach ($data['listeners'] ?? [] as $listener) {
            $address = (string) ($listener['address'] ?? '');

            if (str_starts_with($address, '127.') || $address === '::1') {
                continue;
            }

            $exposed[(int) $listener['port']] = "{$listener['port']}/tcp — " . (
                $listener['process'] ?? 'proceso desconocido'
            );
        }

        ksort($exposed);
        $details = array_values($exposed);

        if ($details === []) {
            return CheckResult::ok('Ningún servicio escucha fuera del equipo.');
        }

        if (! ($data['firewallEnabled'] ?? false)) {
            return CheckResult::warning(
                count($details) . ' puertos escuchan en la red con el firewall desactivado en algún perfil.',
                $details,
                [
                    FixStep::command(
                        'Abre la configuración del firewall y actívalo en todas las redes.',
                        'start windowsdefender://network'
                    ),
                    FixStep::note('Desinstala o desactiva los programas de la lista que no reconozcas.'),
                ]
            );
        }

        return CheckResult::ok(
            count($details) . ' servicios escuchan en la red; el firewall de Windows los filtra según sus reglas.',
            $details
        );
    }
}

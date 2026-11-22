<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Intentos fallidos de inicio de sesión en Windows (evento 4625 del registro de Seguridad) en las últimas
 * 24 horas. Leer ese registro requiere permisos de administrador; sin ellos, el chequeo queda sin datos.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class WindowsLoginFailuresCheck extends WindowsCheck
{
    /**
     * Lee los eventos 4625 de las últimas 24 horas; distingue «sin eventos» de «sin permiso».
     */
    private const string SCRIPT = <<<'PS'
        $filter = @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddHours(-24) }
        try {
            $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | ForEach-Object {
                $data = @{}
                ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
                [pscustomobject]@{ user = $data['TargetUserName']; ip = $data['IpAddress'] }
            })
            [pscustomobject]@{ readable = $true; failures = $events }
        } catch {
            $noEvents = $_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'
            [pscustomobject]@{ readable = $noEvents; failures = @() }
        }
        PS;

    /**
     * Intentos fallidos desde un mismo origen a partir de los cuales se considera fuerza bruta.
     */
    public const int BRUTE_FORCE_ATTEMPTS = 5;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Intentos de inicio de sesión';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Detección de ataques';
    }

    /**
     * Crítico si un origen acumula 5 o más fallos; advertencia con fallos aislados; sin datos si no hay
     * permiso para leer el registro de Seguridad.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $data = $this->system->powershell(self::SCRIPT, 60);

        if (! ($data['readable'] ?? false)) {
            return CheckResult::unknown('Leer los inicios de sesión fallidos requiere permisos de administrador.', [], [
                FixStep::command('Abre el Visor de eventos como administrador.', 'eventvwr.msc'),
                FixStep::note('En «Registros de Windows» > «Seguridad», filtra por el id. de evento 4625.'),
            ]);
        }

        $sources = [];

        foreach ($data['failures'] ?? [] as $failure) {
            $ip = in_array(
                $failure['ip'] ?? '-',
                ['-', '', '127.0.0.1', '::1'],
                true
            ) ? 'local' : (string) $failure['ip'];
            $sources[$ip]['count'] = ($sources[$ip]['count'] ?? 0) + 1;
            $sources[$ip]['users'][(string) ($failure['user'] ?? '?')] = true;
        }

        uasort($sources, fn (array $a, array $b): int => $b['count'] <=> $a['count']);
        $details = array_map(
            fn (string $ip, array $source): string => "{$ip}: {$source['count']} fallidos (usuarios: "
                . implode(', ', array_slice(array_keys($source['users']), 0, 5)) . ')',
            array_keys($sources),
            $sources
        );

        foreach ($sources as $ip => $source) {
            if ($source['count'] >= self::BRUTE_FORCE_ATTEMPTS) {
                return CheckResult::critical(
                    "Posible ataque de fuerza bruta: {$source['count']} intentos fallidos desde {$ip}.",
                    $details,
                    [
                        FixStep::note(
                            'Si el origen es remoto, desactiva el escritorio remoto si no lo usas y bloquea la IP en '
                            . 'el firewall.'
                        ),
                        FixStep::note(
                            'Activa el bloqueo de cuenta tras varios intentos en «Directiva de seguridad local» '
                            . '(secpol.msc).'
                        ),
                    ]
                );
            }
        }

        if ($sources !== []) {
            return CheckResult::warning(
                array_sum(array_column($sources, 'count')) . ' intentos fallidos de inicio de sesión en 24 horas.',
                $details
            );
        }

        return CheckResult::ok('Sin intentos fallidos de inicio de sesión en las últimas 24 horas.');
    }
}

<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Conexiones entrantes bloqueadas por el Firewall de Windows en las últimas 24 horas, leídas de su
 * registro (pfirewall.log): detecta escaneos de puertos. El registro de bloqueos viene desactivado y su
 * archivo suele requerir permisos de administrador.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class WindowsBlockedConnectionsCheck extends WindowsCheck
{
    /**
     * Indica si algún perfil registra los bloqueos y lee las líneas DROP entrantes del último día.
     */
    private const string SCRIPT = <<<'PS'
        $logging = @(Get-NetFirewallProfile | Where-Object { [string]$_.LogBlocked -eq 'True' }).Count -gt 0
        $path = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log'
        $since = (Get-Date).AddHours(-24).ToString('yyyy-MM-dd HH:mm:ss')
        try {
            $lines = @(Get-Content -LiteralPath $path -Tail 20000 -ErrorAction Stop |
                Where-Object { $_ -match ' DROP ' -and $_ -match 'RECEIVE' -and $_.Substring(0, 19) -ge $since })
            [pscustomobject]@{ logging = $logging; readable = $true; lines = $lines }
        } catch {
            [pscustomobject]@{ logging = $logging; readable = $false; lines = @() }
        }
        PS;

    /**
     * Puertos distintos probados por un mismo origen a partir de los cuales se considera un escaneo.
     */
    public const int SCAN_DISTINCT_PORTS = 10;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Escaneos y conexiones bloqueadas';
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
     * Crítico si un origen probó 10 o más puertos distintos; sin datos si el registro está desactivado o
     * no se puede leer.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $data = $this->system->powershell(self::SCRIPT, 60);

        if (! ($data['logging'] ?? false)) {
            return CheckResult::unknown('El Firewall de Windows no registra las conexiones bloqueadas.', [], [
                FixStep::command(
                    'Activa el registro de bloqueos (PowerShell como administrador).',
                    'Set-NetFirewallProfile -All -LogBlocked True'
                ),
            ]);
        }

        if (! ($data['readable'] ?? false)) {
            return CheckResult::unknown('Leer el registro del firewall requiere permisos de administrador.', [], [
                FixStep::note('Ábrelo como administrador en %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log.'),
            ]);
        }

        $sources = [];

        foreach ($data['lines'] ?? [] as $line) {
            $fields = preg_split('/\s+/', trim((string) $line)) ?: [];

            if (count($fields) >= 8 && ctype_digit($fields[7])) {
                $sources[$fields[4]]['count'] = ($sources[$fields[4]]['count'] ?? 0) + 1;
                $sources[$fields[4]]['ports'][(int) $fields[7]] = true;
            }
        }

        uasort($sources, fn (array $a, array $b): int => $b['count'] <=> $a['count']);
        $details = array_map(
            fn (
                string $ip,
                array $source
            ): string => "{$ip}: {$source['count']} bloqueadas, " . count($source['ports']) . ' puertos',
            array_keys($sources),
            $sources
        );

        foreach ($sources as $ip => $source) {
            if (count($source['ports']) >= self::SCAN_DISTINCT_PORTS) {
                return CheckResult::critical(
                    "Escaneo de puertos desde {$ip}: probó " . count($source['ports']) . ' puertos distintos.',
                    $details,
                    [
                        FixStep::command(
                            "Bloquea {$ip} en el firewall (PowerShell como administrador).",
                            "New-NetFirewallRule -DisplayName 'Bloquear {$ip}' -Direction Inbound "
                                . "-RemoteAddress {$ip} -Action Block"
                        ),
                        FixStep::note(
                            'Si la IP es de tu red local, identifica qué equipo es: puede estar comprometido.'
                        ),
                    ]
                );
            }
        }

        $total = array_sum(array_column($sources, 'count'));

        return CheckResult::ok(
            $total === 0
                ? 'El firewall no bloqueó conexiones entrantes en las últimas 24 horas.'
                : "El firewall bloqueó {$total} conexiones en 24 horas, sin patrones de escaneo.",
            $details
        );
    }
}

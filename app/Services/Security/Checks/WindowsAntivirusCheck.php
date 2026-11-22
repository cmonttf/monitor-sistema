<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Antivirus de Windows: productos registrados en el Centro de seguridad y, si es Microsoft Defender,
 * su protección en tiempo real y la antigüedad de sus firmas.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class WindowsAntivirusCheck extends WindowsCheck
{
    /**
     * Lista los antivirus del Centro de seguridad (productState codifica si está activo y al día) y,
     * si está disponible, el estado de Microsoft Defender.
     */
    private const string SCRIPT = <<<'PS'
        $query = @{
            Namespace = 'root/SecurityCenter2'
            ClassName = 'AntivirusProduct'
            ErrorAction = 'SilentlyContinue'
        }
        $products = @(Get-CimInstance @query |
            ForEach-Object { [pscustomobject]@{ name = $_.displayName; state = [int]$_.productState } })
        $defender = $null
        try {
            $status = Get-MpComputerStatus -ErrorAction Stop
            $defender = [pscustomobject]@{
                enabled = [bool]$status.AntivirusEnabled
                realTime = [bool]$status.RealTimeProtectionEnabled
                signatureAge = [int]$status.AntivirusSignatureAge
                signatureUpdated = $status.AntivirusSignatureLastUpdated.ToString('o')
            }
        } catch {}
        [pscustomobject]@{ products = $products; defender = $defender }
        PS;

    /**
     * Días de antigüedad de las firmas de Defender a partir de los cuales se muestra una advertencia.
     */
    private const int WARNING_DAYS = 2;

    /**
     * Días de antigüedad de las firmas de Defender a partir de los cuales el estado es crítico.
     */
    private const int CRITICAL_DAYS = 7;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Antivirus';
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
     * Crítico si no hay ningún antivirus activo o Defender no protege en tiempo real; según la antigüedad
     * de las firmas, advertencia o crítico.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $data = $this->system->powershell(self::SCRIPT);

        if ($data === null) {
            return CheckResult::unknown(
                'No se pudo consultar el Centro de seguridad de Windows.',
                [],
                $this->openSecurityStep()
            );
        }

        $products = array_map(fn (array $product): array => [
            'name' => (string) ($product['name'] ?? 'Antivirus'),
            ...self::decodeProductState((int) ($product['state'] ?? 0)),
        ], $data['products'] ?? []);
        $active = array_values(array_filter($products, fn (array $product): bool => $product['enabled']));
        $details = array_map(
            fn (array $product): string => $product['name'] . ': ' . ($product['enabled'] ? 'activo' : 'inactivo')
                . ($product['upToDate'] ? ', firmas al día' : ', firmas desactualizadas'),
            $products
        );

        if ($active === []) {
            return CheckResult::critical('No hay ningún antivirus activo.', $details, [
                ...$this->openSecurityStep(),
                FixStep::note('Activa «Protección en tiempo real» en «Protección contra virus y amenazas».'),
            ]);
        }

        $defender = $data['defender'] ?? null;
        $usesDefender = is_array($defender) && ($defender['enabled'] ?? false);

        if ($usesDefender) {
            return $this->evaluateDefender($defender, $details);
        }

        if (! $active[0]['upToDate']) {
            return CheckResult::warning("Las firmas de {$active[0]['name']} están desactualizadas.", $details, [
                FixStep::note("Abre {$active[0]['name']} y busca actualizaciones de firmas."),
            ]);
        }

        return CheckResult::ok("{$active[0]['name']} está activo y al día.", $details);
    }

    /**
     * Decodifica productState del Centro de seguridad: el segundo byte indica si el producto está activo
     * (0x10 o 0x11) y el tercero si sus firmas están al día (0x00).
     *
     * @param int $state Valor de productState.
     *
     * @return array{enabled: bool, upToDate: bool} Estado decodificado.
     */
    public static function decodeProductState(int $state): array
    {
        $hex = sprintf('%06x', $state);

        return [
            'enabled' => in_array(substr($hex, 2, 2), ['10', '11'], true),
            'upToDate' => substr($hex, 4, 2) === '00',
        ];
    }

    /**
     * Evalúa la protección en tiempo real y las firmas de Microsoft Defender.
     *
     * @param array<string, mixed> $defender Estado de Get-MpComputerStatus.
     * @param list<string>         $details  Detalles ya calculados de los productos.
     *
     * @return CheckResult Resultado del chequeo.
     */
    private function evaluateDefender(array $defender, array $details): CheckResult
    {
        $age = (int) ($defender['signatureAge'] ?? 0);
        $details[] = 'Firmas de Defender: ' . ($age === 0 ? 'de hoy' : "de hace {$age} días");

        if (! ($defender['realTime'] ?? false)) {
            return CheckResult::critical(
                'La protección en tiempo real de Microsoft Defender está desactivada.',
                $details,
                [
                    ...$this->openSecurityStep(),
                    FixStep::note(
                        'En «Protección contra virus y amenazas» > «Administrar la configuración», '
                        . 'activa «Protección en tiempo real».'
                    ),
                ]
            );
        }

        $updateSteps = [
            FixStep::command(
                'Descarga las firmas de Defender ahora (PowerShell).',
                '& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -SignatureUpdate'
            ),
            FixStep::note(
                'O en Seguridad de Windows > «Protección contra virus y amenazas» > «Buscar actualizaciones».'
            ),
        ];

        return match (true) {
            $age > self::CRITICAL_DAYS => CheckResult::critical(
                "Las firmas de Defender tienen {$age} días de antigüedad.",
                $details,
                $updateSteps
            ),
            $age > self::WARNING_DAYS => CheckResult::warning(
                "Las firmas de Defender tienen {$age} días de antigüedad.",
                $details,
                $updateSteps
            ),
            default => CheckResult::ok('Microsoft Defender está activo y con firmas al día.', $details),
        };
    }

    /**
     * Paso para abrir Seguridad de Windows.
     *
     * @return list<FixStep> Paso de solución.
     */
    private function openSecurityStep(): array
    {
        return [FixStep::command('Abre Seguridad de Windows.', 'start windowsdefender:')];
    }
}

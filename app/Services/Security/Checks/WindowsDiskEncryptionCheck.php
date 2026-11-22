<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Cifrado BitLocker de las unidades locales, leído sin permisos de administrador a través de la
 * propiedad System.Volume.BitLockerProtection del Explorador.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class WindowsDiskEncryptionCheck extends WindowsCheck
{
    /**
     * Lee el estado de protección de BitLocker de cada unidad local fija.
     */
    private const string SCRIPT = <<<'PS'
        $shell = New-Object -ComObject Shell.Application
        [pscustomobject]@{
            system = $env:SystemDrive
            drives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
                $folder = $shell.NameSpace($_.DeviceID + '\')
                [pscustomobject]@{
                    drive = $_.DeviceID
                    protection = $folder.Self.ExtendedProperty('System.Volume.BitLockerProtection')
                }
            })
        }
        PS;

    /**
     * Valores de System.Volume.BitLockerProtection que indican una unidad protegida o en proceso de cifrado.
     */
    private const array PROTECTED_VALUES = [1, 3, 6];

    /**
     * Descripción de cada valor de System.Volume.BitLockerProtection.
     */
    private const array PROTECTION_LABELS = [
        1 => 'cifrada',
        2 => 'sin cifrar',
        3 => 'cifrándose',
        4 => 'descifrándose',
        5 => 'protección suspendida',
        6 => 'cifrada (bloqueada)',
        8 => 'esperando activación',
    ];

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Cifrado de disco (BitLocker)';
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
     * Correcto si la unidad del sistema está cifrada; advertencia si está sin cifrar, con la protección
     * suspendida o esperando activación; sin datos si la edición de Windows no informa el estado.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $data = $this->system->powershell(self::SCRIPT);
        $drives = $data['drives'] ?? [];

        if ($drives === []) {
            return CheckResult::unknown('No se pudo consultar el estado de BitLocker.', [], $this->steps());
        }

        $details = array_map(
            fn (array $drive): string => $drive['drive'] . ' — '
                . (self::PROTECTION_LABELS[(int) ($drive['protection'] ?? 0)] ?? 'sin información de BitLocker'),
            $drives
        );
        $systemDrive = array_values(
            array_filter($drives, fn (array $drive): bool => $drive['drive'] === ($data['system'] ?? 'C:'))
        )[0]
            ?? $drives[0];
        $protection = isset($systemDrive['protection']) ? (int) $systemDrive['protection'] : null;

        if ($protection === null || ! isset(self::PROTECTION_LABELS[$protection])) {
            return CheckResult::unknown(
                'Esta edición de Windows no informa el estado de BitLocker sin permisos de administrador.',
                $details,
                [FixStep::command('Revísalo como administrador.', 'manage-bde -status'), ...$this->steps()]
            );
        }

        if (in_array($protection, self::PROTECTED_VALUES, true)) {
            return CheckResult::ok(
                "La unidad del sistema ({$systemDrive['drive']}) está cifrada con BitLocker.",
                $details
            );
        }

        return CheckResult::warning(
            "La unidad del sistema ({$systemDrive['drive']}) está " . self::PROTECTION_LABELS[$protection] . '.',
            $details,
            $this->steps()
        );
    }

    /**
     * Pasos para activar el cifrado.
     *
     * @return list<FixStep> Pasos de solución.
     */
    private function steps(): array
    {
        return [
            FixStep::command('Abre la configuración de BitLocker.', 'control /name Microsoft.BitLockerDriveEncryption'),
            FixStep::note('En Windows Home, busca «Cifrado de dispositivo» en Configuración > Privacidad y seguridad.'),
            FixStep::note(
                'Guarda la clave de recuperación en tu cuenta Microsoft o en un lugar seguro fuera del equipo.'
            ),
        ];
    }
}

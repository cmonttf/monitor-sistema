<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Reinicio pendiente en Windows para completar actualizaciones.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class WindowsRebootCheck extends WindowsCheck
{
    /**
     * Revisa las claves del registro que Windows crea cuando una actualización necesita reiniciar
     * y la fecha del último arranque.
     */
    private const string SCRIPT = <<<'PS'
        $base = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion'
        [pscustomobject]@{
            windowsUpdate = Test-Path "$base\WindowsUpdate\Auto Update\RebootRequired"
            servicing = Test-Path "$base\Component Based Servicing\RebootPending"
            lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')
        }
        PS;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Reinicio pendiente';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Actualizaciones';
    }

    /**
     * Advertencia si Windows Update o el servicio de componentes esperan un reinicio.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $data = $this->system->powershell(self::SCRIPT);

        if ($data === null) {
            return CheckResult::unknown('No se pudo consultar si hay un reinicio pendiente.');
        }

        $details = empty($data['lastBoot']) ? [] : ['Último arranque: ' . date(
            'd-m-Y H:i',
            (int) strtotime($data['lastBoot'])
        )];

        if (($data['windowsUpdate'] ?? false) || ($data['servicing'] ?? false)) {
            return CheckResult::warning('Windows necesita reiniciarse para completar actualizaciones.', $details, [
                FixStep::note('Guarda tu trabajo y reinicia desde Inicio > Inicio/Apagado > «Actualizar y reiniciar».'),
            ]);
        }

        return CheckResult::ok('No hay reinicios pendientes.', $details);
    }
}

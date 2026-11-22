<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Actualizaciones pendientes de Windows Update, distinguiendo las de seguridad.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class WindowsUpdateCheck extends WindowsCheck
{
    /**
     * Busca las actualizaciones no instaladas con la API de Windows Update. Una actualización es de
     * seguridad si pertenece a la categoría «Security Updates» (identificador fijo, independiente del
     * idioma) o tiene severidad MSRC.
     */
    private const string SCRIPT = <<<'PS'
        $securityCategory = '0fa1201d-4330-4fa8-8ae9-b877473b6441'
        $session = New-Object -ComObject Microsoft.Update.Session
        $search = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $lastInstall = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate
        [pscustomobject]@{
            updates = @($search.Updates | ForEach-Object {
                $isSecurity = [bool]($_.Categories | Where-Object { $_.CategoryID -eq $securityCategory })
                [pscustomobject]@{ title = $_.Title; security = ($isSecurity -or [bool]$_.MsrcSeverity) }
            })
            lastInstall = if ($lastInstall) { ([datetime]$lastInstall).ToString('o') } else { $null }
        }
        PS;

    /**
     * Cantidad máxima de actualizaciones listadas en los detalles de la tarjeta.
     */
    private const int MAX_LISTED = 15;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Windows Update';
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
     * Crítico si hay actualizaciones de seguridad pendientes, advertencia si sólo hay otras. La búsqueda
     * puede tardar y requiere conexión a internet.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $data = $this->system->powershell(self::SCRIPT, 180);

        if ($data === null) {
            return CheckResult::unknown(
                'No se pudo consultar Windows Update (revisa la conexión a internet).',
                [],
                $this->steps()
            );
        }

        $updates = $data['updates'] ?? [];
        $security = array_filter($updates, fn (array $update): bool => (bool) ($update['security'] ?? false));
        $details = array_map(
            fn (array $update): string => (($update['security'] ?? false) ? '🔒 ' : '') . ($update['title'] ?? ''),
            array_slice($updates, 0, self::MAX_LISTED)
        );

        if (count($updates) > self::MAX_LISTED) {
            $details[] = '… y ' . (count($updates) - self::MAX_LISTED) . ' más';
        }

        if (! empty($data['lastInstall'])) {
            $details[] = 'Última instalación correcta: ' . date('d-m-Y H:i', (int) strtotime($data['lastInstall']));
        }

        if ($security !== []) {
            return CheckResult::critical(
                count($security) . ' actualizaciones de seguridad pendientes (' . count($updates) . ' en total).',
                $details,
                $this->steps()
            );
        }

        if ($updates !== []) {
            return CheckResult::warning(count($updates) . ' actualizaciones pendientes.', $details, $this->steps());
        }

        return CheckResult::ok('Windows está actualizado.', $details);
    }

    /**
     * Pasos para instalar las actualizaciones.
     *
     * @return list<FixStep> Pasos de solución.
     */
    private function steps(): array
    {
        return [
            FixStep::command('Abre Windows Update (en PowerShell o en Win+R).', 'start ms-settings:windowsupdate'),
            FixStep::note('Presiona «Buscar actualizaciones», instala todo y reinicia si lo pide.'),
        ];
    }
}

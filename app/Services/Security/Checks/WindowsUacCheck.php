<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Control de cuentas de usuario (UAC) de Windows.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class WindowsUacCheck extends WindowsCheck
{
    /**
     * Lee la política de UAC: si está habilitado y cómo pide confirmación a los administradores.
     */
    private const string SCRIPT = <<<'PS'
        $policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $policy = Get-ItemProperty $policyPath -ErrorAction SilentlyContinue
        [pscustomobject]@{ enableLua = $policy.EnableLUA; adminPrompt = $policy.ConsentPromptBehaviorAdmin }
        PS;

    /**
     * Valor de ConsentPromptBehaviorAdmin que eleva privilegios sin preguntar.
     */
    private const int ELEVATE_WITHOUT_PROMPT = 0;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Control de cuentas de usuario (UAC)';
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
     * Crítico si UAC está deshabilitado; advertencia si eleva privilegios sin preguntar.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $data = $this->system->powershell(self::SCRIPT);

        if ($data === null || ! isset($data['enableLua'])) {
            return CheckResult::unknown('No se pudo leer la configuración de UAC.');
        }

        $steps = [
            FixStep::command('Abre la configuración de UAC.', 'UserAccountControlSettings'),
            FixStep::note(
                'Deja el control en el nivel predeterminado («Notificarme sólo cuando las aplicaciones intenten '
                . 'realizar cambios»).'
            ),
        ];

        if ((int) $data['enableLua'] !== 1) {
            return CheckResult::critical('El Control de cuentas de usuario está deshabilitado.', [], [
                ...$steps,
                FixStep::note('Reinicia el equipo para aplicar el cambio.'),
            ]);
        }

        if (isset($data['adminPrompt']) && (int) $data['adminPrompt'] === self::ELEVATE_WITHOUT_PROMPT) {
            return CheckResult::warning('UAC eleva privilegios sin pedir confirmación.', [], $steps);
        }

        return CheckResult::ok('El Control de cuentas de usuario está activo.');
    }
}

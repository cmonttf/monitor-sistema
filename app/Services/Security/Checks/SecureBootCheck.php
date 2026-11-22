<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Estado del arranque seguro UEFI.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class SecureBootCheck extends SystemCheck
{
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
     * Interpreta `mokutil --sb-state`: activado es correcto, desactivado es una advertencia.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('mokutil')) {
            return CheckResult::unknown('mokutil no está instalado.', [], [
                $this->platform->installStep('Instala la herramienta que informa el estado de Secure Boot.', 'mokutil'),
            ]);
        }

        $output = $this->system->run(['mokutil', '--sb-state'])->output();

        return match (true) {
            str_contains($output, 'SecureBoot enabled') => CheckResult::ok('Secure Boot está activado.'),
            str_contains($output, 'SecureBoot disabled') => CheckResult::warning('Secure Boot está desactivado.', [], [
                FixStep::note(
                    'Reinicia y entra a la configuración UEFI/BIOS (normalmente con F2, F10, F12 o Supr al encender).'
                ),
                FixStep::note('Activa «Secure Boot» en la sección de seguridad o arranque, guarda y reinicia.'),
                FixStep::note(
                    'Si usas controladores externos (por ejemplo NVIDIA), la distribución puede pedirte '
                        . 'registrar una clave MOK al reiniciar.'
                ),
            ]),
            default => CheckResult::unknown(
                'No se pudo determinar el estado de Secure Boot.',
                array_filter([trim($output)])
            ),
        };
    }
}

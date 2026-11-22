<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Estado del cortafuegos UFW.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class FirewallCheck extends SystemCheck
{
    /**
     * Archivo de configuración de UFW que indica si el cortafuegos está habilitado.
     */
    private const string CONFIG = '/etc/ufw/ufw.conf';

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Cortafuegos (UFW)';
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
     * Exige que UFW esté habilitado en su configuración y que su servicio esté activo;
     * en cualquier otro caso el estado es crítico.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('ufw')) {
            return CheckResult::critical(
                'No hay cortafuegos UFW instalado.',
                [],
                [
                    FixStep::command(
                        'Instala y activa el cortafuegos (bloquea las conexiones entrantes por defecto).',
                        'sudo apt install ufw && sudo ufw enable'
                    ),
                ]
            );
        }

        $isEnabled = preg_match('/^\s*ENABLED\s*=\s*yes/mi', $this->system->readFile(self::CONFIG) ?? '') === 1;
        $serviceState = $this->system->serviceState('ufw');

        if ($isEnabled && $serviceState === 'active') {
            return CheckResult::ok('El cortafuegos está activo.');
        }

        return CheckResult::critical(
            'El cortafuegos está desactivado.',
            ["Servicio: {$serviceState}"],
            [
                FixStep::command('Activa el cortafuegos y haz que arranque con el equipo.', 'sudo ufw enable'),
                FixStep::command(
                    'Si usas SSH para entrar al equipo, permítelo antes de activarlo.',
                    'sudo ufw allow OpenSSH'
                ),
            ]
        );
    }
}

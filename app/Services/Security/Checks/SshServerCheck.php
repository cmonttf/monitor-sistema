<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Exposición y configuración del servidor SSH.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class SshServerCheck extends SystemCheck
{
    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Servidor SSH';
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
     * Si el servidor SSH está activo, revisa su configuración: acceso como root es crítico y
     * acceso por contraseña es advertencia.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        if ($this->system->serviceState('ssh') !== 'active') {
            return CheckResult::ok('El servidor SSH no está activo.');
        }

        $config = implode("\n", array_map(
            fn (string $path): string => $this->system->readFile($path) ?? '',
            ['/etc/ssh/sshd_config', ...$this->system->glob('/etc/ssh/sshd_config.d/*.conf')],
        ));

        if (preg_match('/^\s*PermitRootLogin\s+yes/mi', $config) === 1) {
            return CheckResult::critical(
                'SSH activo y permite acceso directo como root.',
                ['Define PermitRootLogin no en /etc/ssh/sshd_config']
            );
        }

        if (preg_match('/^\s*PasswordAuthentication\s+yes/mi', $config) === 1) {
            return CheckResult::warning(
                'SSH activo con acceso por contraseña.',
                ['Considera usar sólo llaves (PasswordAuthentication no)']
            );
        }

        return CheckResult::ok('SSH activo con configuración restringida.');
    }
}

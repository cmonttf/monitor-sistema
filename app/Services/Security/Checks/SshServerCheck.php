<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

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
        $service = $this->activeService();

        if ($service === null) {
            return CheckResult::ok('El servidor SSH no está activo.');
        }

        $config = implode("\n", array_map(
            fn (string $path): string => $this->system->readFile($path) ?? '',
            ['/etc/ssh/sshd_config', ...$this->system->glob('/etc/ssh/sshd_config.d/*.conf')],
        ));

        if (preg_match('/^\s*PermitRootLogin\s+yes/mi', $config) === 1) {
            return CheckResult::critical(
                'SSH activo y permite acceso directo como root.',
                [],
                [
                    FixStep::command(
                        'Edita la configuración y cambia la línea a «PermitRootLogin no».',
                        'sudoedit /etc/ssh/sshd_config'
                    ),
                    FixStep::command('Aplica el cambio.', "sudo systemctl restart {$service}"),
                    FixStep::command(
                        'Si no necesitas entrar a este equipo por SSH, desactívalo.',
                        "sudo systemctl disable --now {$service}"
                    ),
                ]
            );
        }

        if (preg_match('/^\s*PasswordAuthentication\s+yes/mi', $config) === 1) {
            return CheckResult::warning(
                'SSH activo con acceso por contraseña.',
                [],
                [
                    FixStep::note(
                        'Primero copia tu llave pública desde el equipo cliente con «ssh-copy-id usuario@este-equipo».'
                    ),
                    FixStep::command(
                        'Luego cambia la línea a «PasswordAuthentication no».',
                        'sudoedit /etc/ssh/sshd_config'
                    ),
                    FixStep::command('Aplica el cambio.', "sudo systemctl restart {$service}"),
                ]
            );
        }

        return CheckResult::ok('SSH activo con configuración restringida.');
    }

    /**
     * Busca el servicio del servidor SSH activo: "ssh" en Debian/Ubuntu y "sshd" en Fedora, RHEL y Arch.
     *
     * @return string|null Nombre del servicio activo, o null si ninguno lo está.
     */
    private function activeService(): ?string
    {
        foreach (['ssh', 'sshd'] as $service) {
            if ($this->system->serviceState($service) === 'active') {
                return $service;
            }
        }

        return null;
    }
}

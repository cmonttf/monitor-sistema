<?php

namespace App\Enums;

/**
 * Familia de distribuciones Linux, que determina el gestor de paquetes y las herramientas de seguridad
 * por defecto.
 *
 * @package App\Enums
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
enum LinuxFamily: string
{
    /**
     * Debian, Ubuntu, Linux Mint, Pop!_OS...: apt, UFW y AppArmor.
     */
    case Debian = 'debian';

    /**
     * Fedora, RHEL, Rocky, AlmaLinux, CentOS...: dnf, firewalld y SELinux.
     */
    case RedHat = 'redhat';

    /**
     * Arch, Manjaro, EndeavourOS...: pacman.
     */
    case Arch = 'arch';

    /**
     * Distribución no reconocida: sólo se ejecutan los chequeos genéricos de Linux.
     */
    case Unknown = 'unknown';

    /**
     * Comando para instalar paquetes con el gestor de la familia.
     *
     * @param string ...$packages Paquetes a instalar.
     *
     * @return string|null Comando, o null si la familia no se reconoce.
     */
    public function installCommand(string ...$packages): ?string
    {
        $list = implode(' ', $packages);

        return match ($this) {
            self::Debian => "sudo apt install {$list}",
            self::RedHat => "sudo dnf install {$list}",
            self::Arch => "sudo pacman -S {$list}",
            self::Unknown => null,
        };
    }
}

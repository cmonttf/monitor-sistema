<?php

namespace App\Services\Security;

use App\Enums\LinuxFamily;
use App\Enums\OperatingSystem;

/**
 * Plataforma en la que corre el monitor: sistema operativo y, en Linux, familia de distribuciones.
 *
 * @package App\Services\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
final readonly class Platform
{
    /**
     * Crea la descripción de una plataforma.
     *
     * @param OperatingSystem  $os     Sistema operativo.
     * @param LinuxFamily|null $family Familia de distribuciones (sólo en Linux).
     * @param string           $name   Nombre legible, por ejemplo "Ubuntu 26.04.1 LTS".
     */
    public function __construct(
        public OperatingSystem $os,
        public ?LinuxFamily $family = null,
        public string $name = '',
    ) {
    }

    /**
     * Crea una plataforma Linux de la familia indicada (útil en pruebas).
     *
     * @param LinuxFamily $family Familia de distribuciones.
     * @param string      $name   Nombre legible.
     *
     * @return self Plataforma Linux.
     */
    public static function linux(LinuxFamily $family, string $name = 'Linux'): self
    {
        return new self(OperatingSystem::Linux, $family, $name);
    }

    /**
     * Crea una plataforma Windows (útil en pruebas).
     *
     * @param string $name Nombre legible.
     *
     * @return self Plataforma Windows.
     */
    public static function windows(string $name = 'Windows'): self
    {
        return new self(OperatingSystem::Windows, null, $name);
    }

    /**
     * Indica si la plataforma es Linux, opcionalmente de alguna de las familias indicadas.
     *
     * @param LinuxFamily ...$families Familias aceptadas; sin argumentos acepta cualquiera.
     *
     * @return bool true si es Linux (y de una de las familias, si se indicaron).
     */
    public function isLinux(LinuxFamily ...$families): bool
    {
        return $this->os === OperatingSystem::Linux
            && ($families === [] || in_array($this->family, $families, true));
    }

    /**
     * Indica si la plataforma es Windows.
     *
     * @return bool true en Windows.
     */
    public function isWindows(): bool
    {
        return $this->os === OperatingSystem::Windows;
    }

    /**
     * Paso para instalar paquetes con el gestor de la distribución, o una indicación genérica si la
     * familia no se reconoce.
     *
     * @param string $text        Qué se instala.
     * @param string ...$packages Paquetes a instalar.
     *
     * @return FixStep Paso de instalación.
     */
    public function installStep(string $text, string ...$packages): FixStep
    {
        $command = $this->family?->installCommand(...$packages);

        return $command === null
            ? FixStep::note(
                "{$text} Instala con el gestor de paquetes de tu distribución: " . implode(', ', $packages) . '.'
            )
            : FixStep::command($text, $command);
    }
}

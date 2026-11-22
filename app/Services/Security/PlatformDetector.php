<?php

namespace App\Services\Security;

use App\Enums\LinuxFamily;
use App\Enums\OperatingSystem;

/**
 * Detecta el sistema operativo y, en Linux, la familia de la distribución a partir de /etc/os-release.
 *
 * @package App\Services\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class PlatformDetector
{
    /**
     * Archivo estándar con la identificación de la distribución Linux.
     */
    private const string OS_RELEASE = '/etc/os-release';

    /**
     * Identificadores de os-release (ID e ID_LIKE) que corresponden a cada familia.
     */
    private const array FAMILY_IDS = [
        'debian' => LinuxFamily::Debian,
        'ubuntu' => LinuxFamily::Debian,
        'fedora' => LinuxFamily::RedHat,
        'rhel' => LinuxFamily::RedHat,
        'centos' => LinuxFamily::RedHat,
        'arch' => LinuxFamily::Arch,
    ];

    /**
     * Recibe el acceso al sistema operativo.
     *
     * @param SystemInspector $system Acceso a comandos y archivos del sistema.
     */
    public function __construct(private SystemInspector $system)
    {
    }

    /**
     * Detecta la plataforma actual.
     *
     * @return Platform Plataforma detectada.
     */
    public function detect(): Platform
    {
        return match ($this->system->osFamily()) {
            'Windows' => Platform::windows('Windows ' . $this->system->osVersion()),
            'Linux' => $this->detectLinux(),
            default => new Platform(OperatingSystem::Other, null, $this->system->osFamily()),
        };
    }

    /**
     * Identifica la familia de la distribución: primero por ID y luego por cada valor de ID_LIKE.
     *
     * @return Platform Plataforma Linux.
     */
    private function detectLinux(): Platform
    {
        $values = [];
        preg_match_all(
            '/^(\w+)=(?:"([^"]*)"|(\S*))/m',
            $this->system->readFile(self::OS_RELEASE) ?? '',
            $matches,
            PREG_SET_ORDER
        );

        foreach ($matches as $match) {
            $values[$match[1]] = $match[2] !== '' ? $match[2] : ($match[3] ?? '');
        }

        $candidates = [strtolower($values['ID'] ?? ''), ...explode(' ', strtolower($values['ID_LIKE'] ?? ''))];
        $family = LinuxFamily::Unknown;

        foreach ($candidates as $candidate) {
            if (isset(self::FAMILY_IDS[$candidate])) {
                $family = self::FAMILY_IDS[$candidate];
                break;
            }
        }

        return Platform::linux($family, $values['PRETTY_NAME'] ?? 'Linux');
    }
}

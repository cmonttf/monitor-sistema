<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Actualizaciones automáticas de seguridad (unattended-upgrades).
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class UnattendedUpgradesCheck extends SystemCheck
{
    /**
     * Configuración de APT que activa la actualización periódica y las actualizaciones desatendidas.
     */
    private const string CONFIG = '/etc/apt/apt.conf.d/20auto-upgrades';

    /**
     * Registro de unattended-upgrades, cuya fecha indica la última ejecución.
     */
    private const string LOG = '/var/log/unattended-upgrades/unattended-upgrades.log';

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Actualizaciones automáticas';
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
     * Es crítico si unattended-upgrades no está instalado o desactivado, y advertencia si lleva
     * más de 7 días sin ejecutarse.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('unattended-upgrade')) {
            return CheckResult::critical(
                'unattended-upgrades no está instalado.',
                ['sudo apt install unattended-upgrades']
            );
        }

        $config = $this->system->readFile(self::CONFIG) ?? '';
        $isEnabled = preg_match('/APT::Periodic::Unattended-Upgrade\s+"[1-9]\d*"/', $config) === 1
            && preg_match('/APT::Periodic::Update-Package-Lists\s+"[1-9]\d*"/', $config) === 1;

        if (! $isEnabled) {
            return CheckResult::critical(
                'Las actualizaciones automáticas están desactivadas.',
                ['sudo dpkg-reconfigure -plow unattended-upgrades']
            );
        }

        $lastRun = $this->system->modifiedAt(self::LOG);

        if ($lastRun === null) {
            return CheckResult::ok('Activadas (sin registro de ejecución legible).');
        }

        $days = (int) $lastRun->diffInDays(now());
        $details = ['Última ejecución: ' . $lastRun->format('d-m-Y H:i')];

        if ($days > 7) {
            return CheckResult::warning("Activadas, pero no se ejecutan hace {$days} días.", $details);
        }

        return CheckResult::ok('Activadas; última ejecución ' . $lastRun->diffForHumans() . '.', $details);
    }
}

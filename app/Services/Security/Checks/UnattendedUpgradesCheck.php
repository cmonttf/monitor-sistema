<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Actualizaciones automáticas de seguridad (unattended-upgrades).
 *
 * @package App\Services\Security\Checks
 */
class UnattendedUpgradesCheck extends SystemCheck
{
    private const string CONFIG = '/etc/apt/apt.conf.d/20auto-upgrades';

    private const string LOG = '/var/log/unattended-upgrades/unattended-upgrades.log';

    public function name(): string
    {
        return 'Actualizaciones automáticas';
    }

    public function category(): string
    {
        return 'Actualizaciones';
    }

    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('unattended-upgrade')) {
            return CheckResult::critical('unattended-upgrades no está instalado.', ['sudo apt install unattended-upgrades']);
        }

        $config = $this->system->readFile(self::CONFIG) ?? '';
        $isEnabled = preg_match('/APT::Periodic::Unattended-Upgrade\s+"[1-9]\d*"/', $config) === 1
            && preg_match('/APT::Periodic::Update-Package-Lists\s+"[1-9]\d*"/', $config) === 1;

        if (! $isEnabled) {
            return CheckResult::critical('Las actualizaciones automáticas están desactivadas.', ['sudo dpkg-reconfigure -plow unattended-upgrades']);
        }

        $lastRun = $this->system->modifiedAt(self::LOG);

        if ($lastRun === null) {
            return CheckResult::ok('Activadas (sin registro de ejecución legible).');
        }

        $days = (int) $lastRun->diffInDays(now());
        $details = ['Última ejecución: '.$lastRun->format('d-m-Y H:i')];

        if ($days > 7) {
            return CheckResult::warning("Activadas, pero no se ejecutan hace {$days} días.", $details);
        }

        return CheckResult::ok('Activadas; última ejecución '.$lastRun->diffForHumans().'.', $details);
    }
}

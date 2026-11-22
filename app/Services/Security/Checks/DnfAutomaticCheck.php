<?php

namespace App\Services\Security\Checks;

use App\Enums\LinuxFamily;
use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;
use App\Services\Security\Platform;

/**
 * Actualizaciones automáticas con dnf-automatic en Fedora, RHEL y derivadas.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class DnfAutomaticCheck extends SystemCheck
{
    /**
     * Temporizadores de dnf-automatic (DNF 4 y DNF 5) que ejecutan las actualizaciones periódicas.
     */
    private const array TIMERS = [
        'dnf-automatic.timer',
        'dnf-automatic-install.timer',
        'dnf5-automatic.timer',
    ];

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
     * Aplica sólo a la familia Fedora/RHEL.
     *
     * @param Platform $platform Plataforma en la que corre el monitor.
     *
     * @return bool true en Fedora, RHEL y derivadas.
     */
    public function supports(Platform $platform): bool
    {
        return $platform->isLinux(LinuxFamily::RedHat);
    }

    /**
     * Correcto si algún temporizador de dnf-automatic está activo; advertencia si no hay ninguno.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        foreach (self::TIMERS as $timer) {
            if ($this->system->serviceState($timer) === 'active') {
                return CheckResult::ok("Activadas con {$timer}.");
            }
        }

        return CheckResult::warning('Las actualizaciones automáticas no están activadas.', [], [
            $this->platform->installStep('Instala dnf-automatic.', 'dnf-automatic'),
            FixStep::note(
                'En /etc/dnf/automatic.conf deja apply_updates = yes (o upgrade_type = security para sólo seguridad).'
            ),
            FixStep::command('Activa el temporizador diario.', 'sudo systemctl enable --now dnf-automatic.timer'),
        ]);
    }
}

<?php

namespace App\Services\Security\Checks;

use App\Enums\LinuxFamily;
use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Estado del cortafuegos de Linux: UFW (Debian, Ubuntu, Arch) o firewalld (Fedora, RHEL).
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class FirewallCheck extends SystemCheck
{
    /**
     * Archivo de configuración de UFW que indica si el cortafuegos está habilitado.
     */
    private const string UFW_CONFIG = '/etc/ufw/ufw.conf';

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Cortafuegos';
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
     * Correcto si UFW está habilitado y su servicio activo, o si firewalld está en ejecución; crítico si
     * ninguno está activo o instalado.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $hasUfw = $this->system->hasCommand('ufw');
        $hasFirewalld = $this->system->hasCommand('firewall-cmd');

        if ($hasUfw && $this->isUfwActive()) {
            return CheckResult::ok('El cortafuegos UFW está activo.');
        }

        if ($hasFirewalld && trim($this->system->run(['firewall-cmd', '--state'])->output()) === 'running') {
            return CheckResult::ok('El cortafuegos firewalld está activo.');
        }

        if ($hasUfw) {
            return CheckResult::critical('El cortafuegos UFW está desactivado.', [
                'Servicio: ' . $this->system->serviceState('ufw'),
            ], [
                FixStep::command(
                    'Si usas SSH para entrar al equipo, permítelo antes de activarlo.',
                    'sudo ufw allow OpenSSH'
                ),
                FixStep::command('Activa el cortafuegos y haz que arranque con el equipo.', 'sudo ufw enable'),
            ]);
        }

        if ($hasFirewalld) {
            return CheckResult::critical('El cortafuegos firewalld está detenido.', [], [
                FixStep::command('Inícialo y haz que arranque con el equipo.', 'sudo systemctl enable --now firewalld'),
            ]);
        }

        return CheckResult::critical('No hay un cortafuegos instalado.', [], $this->installSteps());
    }

    /**
     * Indica si UFW está habilitado en su configuración y su servicio está activo.
     *
     * @return bool true si UFW protege el equipo.
     */
    private function isUfwActive(): bool
    {
        $isEnabled = preg_match('/^\s*ENABLED\s*=\s*yes/mi', $this->system->readFile(self::UFW_CONFIG) ?? '') === 1;

        return $isEnabled && $this->system->serviceState('ufw') === 'active';
    }

    /**
     * Pasos para instalar el cortafuegos habitual de la distribución.
     *
     * @return list<FixStep> Pasos de instalación y activación.
     */
    private function installSteps(): array
    {
        if ($this->platform->isLinux(LinuxFamily::RedHat)) {
            return [
                $this->platform->installStep('Instala firewalld.', 'firewalld'),
                FixStep::command('Inícialo y haz que arranque con el equipo.', 'sudo systemctl enable --now firewalld'),
            ];
        }

        return [
            $this->platform->installStep('Instala UFW, que bloquea las conexiones entrantes por defecto.', 'ufw'),
            FixStep::command('Actívalo y haz que arranque con el equipo.', 'sudo ufw enable'),
        ];
    }
}

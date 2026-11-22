<?php

namespace App\Services\Security\Checks;

use App\Enums\LinuxFamily;
use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Control de acceso obligatorio del kernel: AppArmor (Debian, Ubuntu) o SELinux (Fedora, RHEL).
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class MandatoryAccessControlCheck extends SystemCheck
{
    /**
     * Parámetro del kernel que vale "Y" cuando AppArmor está habilitado.
     */
    private const string APPARMOR_PARAMETER = '/sys/module/apparmor/parameters/enabled';

    /**
     * Archivo que vale "1" con SELinux en modo enforcing y "0" en modo permisivo; no existe si está deshabilitado.
     */
    private const string SELINUX_ENFORCE = '/sys/fs/selinux/enforce';

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Control de acceso (AppArmor / SELinux)';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Sistema';
    }

    /**
     * Correcto con AppArmor habilitado o SELinux en modo enforcing; advertencia con SELinux permisivo.
     * Sin ninguno es crítico en las familias que lo traen por defecto y advertencia en el resto (Arch).
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        if (trim($this->system->readFile(self::APPARMOR_PARAMETER) ?? '') === 'Y') {
            return CheckResult::ok('AppArmor está habilitado en el kernel.');
        }

        $selinux = $this->system->readFile(self::SELINUX_ENFORCE);

        if ($selinux !== null && trim($selinux) === '1') {
            return CheckResult::ok('SELinux está activo en modo enforcing.');
        }

        if ($selinux !== null) {
            return CheckResult::warning(
                'SELinux está en modo permisivo: registra las infracciones pero no las bloquea.',
                [],
                [
                    FixStep::command('Activa el modo enforcing ahora.', 'sudo setenforce 1'),
                    FixStep::note('Para que se mantenga al reiniciar, deja SELINUX=enforcing en /etc/selinux/config.'),
                ]
            );
        }

        return match ($this->platform->family) {
            LinuxFamily::Debian => CheckResult::critical('AppArmor está deshabilitado.', [], [
                FixStep::command('Activa el servicio de AppArmor.', 'sudo systemctl enable --now apparmor'),
                FixStep::command(
                    'Revisa que el arranque no lo desactive (no debe aparecer apparmor=0).',
                    'cat /proc/cmdline'
                ),
                FixStep::note(
                    'Si aparece apparmor=0, quítalo de GRUB_CMDLINE_LINUX en /etc/default/grub, ejecuta «sudo '
                    . 'update-grub» y reinicia.'
                ),
            ]),
            LinuxFamily::RedHat => CheckResult::critical('SELinux está deshabilitado.', [], [
                FixStep::note('Deja SELINUX=enforcing en /etc/selinux/config (con «sudoedit /etc/selinux/config»).'),
                FixStep::command(
                    'Programa el reetiquetado de archivos para el próximo arranque.',
                    'sudo fixfiles onboot'
                ),
                FixStep::command('Reinicia para aplicarlo (el primer arranque tarda más).', 'sudo reboot'),
            ]),
            default => CheckResult::warning('No hay AppArmor ni SELinux activos.', [], [
                FixStep::note(
                    'Esta distribución no trae control de acceso obligatorio por defecto; puedes habilitar AppArmor '
                    . 'siguiendo la guía de tu distribución.'
                ),
            ]),
        };
    }
}

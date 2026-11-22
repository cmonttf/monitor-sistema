<?php

namespace App\Services\Security\Checks;

use App\Enums\LinuxFamily;
use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;
use App\Services\Security\Platform;

/**
 * Paquetes DNF pendientes de actualizar en Fedora, RHEL y derivadas, distinguiendo los de seguridad.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class DnfUpdatesCheck extends SystemCheck
{
    /**
     * Código de salida de `dnf check-update` cuando hay actualizaciones disponibles.
     */
    private const int UPDATES_AVAILABLE_EXIT_CODE = 100;

    /**
     * Cantidad máxima de paquetes listados en los detalles de la tarjeta.
     */
    private const int MAX_LISTED = 25;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Paquetes del sistema (DNF)';
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
     * Aplica sólo a la familia Fedora/RHEL, que usa DNF.
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
     * Consulta `dnf check-update` (código 100 si hay actualizaciones) y `dnf updateinfo --security`:
     * es crítico si hay actualizaciones de seguridad y advertencia si sólo hay normales.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('dnf')) {
            return CheckResult::unknown('DNF no está disponible en este sistema.');
        }

        $result = $this->system->run(['dnf', '-q', 'check-update'], 120);

        if ($result->exitCode() !== 0 && $result->exitCode() !== self::UPDATES_AVAILABLE_EXIT_CODE) {
            return CheckResult::unknown('No se pudo consultar DNF.', array_filter([trim($result->errorOutput())]));
        }

        $packages = $this->packageNames($result->output());

        if ($packages === []) {
            return CheckResult::ok('Todos los paquetes están actualizados.');
        }

        $securityCount = $this->securityAdvisoryCount();
        $details = array_slice($packages, 0, self::MAX_LISTED);

        if (count($packages) > self::MAX_LISTED) {
            $details[] = '… y ' . (count($packages) - self::MAX_LISTED) . ' más';
        }

        $fix = [
            FixStep::command('Instala todas las actualizaciones pendientes.', 'sudo dnf upgrade --refresh'),
            FixStep::note('Si alguna actualización lo pide, reinicia el equipo después de instalar.'),
        ];

        if ($securityCount > 0) {
            return CheckResult::critical(
                "{$securityCount} avisos de seguridad pendientes (" . count($packages) . ' paquetes en total).',
                $details,
                [FixStep::command(
                    'Instala sólo las actualizaciones de seguridad.',
                    'sudo dnf upgrade --security'
                ), ...$fix]
            );
        }

        return CheckResult::warning(count($packages) . ' paquetes pendientes de actualizar.', $details, $fix);
    }

    /**
     * Extrae los nombres de paquete (sin arquitectura) de la salida de `dnf check-update`.
     *
     * @param string $output Salida del comando.
     *
     * @return list<string> Nombres de paquetes.
     */
    private function packageNames(string $output): array
    {
        $names = [];

        foreach (explode("\n", $output) as $line) {
            if (preg_match('/^(\S+)\.(\w+)\s+\S+\s+\S+/', trim($line), $match) === 1 && $match[1] !== 'Obsoleting') {
                $names[] = $match[1];
            }
        }

        return array_values(array_unique($names));
    }

    /**
     * Cuenta los avisos de seguridad pendientes con `dnf updateinfo list --security`.
     *
     * @return int Cantidad de avisos (0 si la consulta no está disponible).
     */
    private function securityAdvisoryCount(): int
    {
        $result = $this->system->run(['dnf', '-q', 'updateinfo', 'list', '--security'], 120);

        if ($result->failed()) {
            return 0;
        }

        $advisories = [];

        foreach (explode("\n", trim($result->output())) as $line) {
            $advisory = strtok(trim($line), ' ');

            if ($advisory !== false && preg_match('/^[A-Z][A-Z0-9]*-[\w:-]+$/', $advisory) === 1) {
                $advisories[$advisory] = true;
            }
        }

        return count($advisories);
    }
}

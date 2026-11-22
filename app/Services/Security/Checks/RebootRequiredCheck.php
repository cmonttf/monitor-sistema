<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Detecta si hay un reinicio pendiente para aplicar actualizaciones o un kernel nuevo.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class RebootRequiredCheck extends SystemCheck
{
    /**
     * Archivo que crean los paquetes cuando el sistema necesita reiniciarse.
     */
    private const string FLAG = '/var/run/reboot-required';

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Reinicio pendiente';
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
     * Advierte si hay un kernel instalado más nuevo que el que está en uso, si desaparecieron los módulos
     * del kernel en uso (Arch), si needs-restarting lo pide (Fedora/RHEL) o si existe la marca de reinicio
     * pendiente (Debian/Ubuntu).
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $running = $this->system->runningKernel();
        $newest = $this->newestInstalledKernel();
        $details = ["Kernel en uso: {$running}"];

        if ($newest !== null && version_compare($newest, $running, '>')) {
            $details[] = "Kernel instalado más reciente: {$newest}";

            return CheckResult::warning(
                'Hay un kernel más nuevo instalado; reinicia para usarlo.',
                $details,
                $this->rebootSteps()
            );
        }

        if ($this->areRunningKernelModulesMissing($running)) {
            return CheckResult::warning(
                'El kernel se actualizó y sus módulos anteriores ya no están; reinicia para usar el nuevo.',
                $details,
                $this->rebootSteps()
            );
        }

        if (
            $this->system->hasCommand('needs-restarting') && $this->system->run(
                ['needs-restarting', '-r']
            )->exitCode() === 1
        ) {
            return CheckResult::warning(
                'El sistema requiere reiniciarse para completar actualizaciones.',
                $details,
                $this->rebootSteps()
            );
        }

        if ($this->system->fileExists(self::FLAG)) {
            $packages = array_values(array_filter(explode("\n", $this->system->readFile(self::FLAG . '.pkgs') ?? '')));

            return CheckResult::warning(
                'El sistema requiere reiniciarse para completar actualizaciones.',
                [...$details, ...$packages],
                $this->rebootSteps()
            );
        }

        return CheckResult::ok('No hay reinicios pendientes.', $details);
    }

    /**
     * Obtiene la versión más reciente entre los kernels instalados en /boot.
     *
     * @return string|null Versión del kernel, o null si no se encontró ninguno.
     */
    private function newestInstalledKernel(): ?string
    {
        $versions = array_map(
            fn (string $path): string => substr(basename($path), strlen('vmlinuz-')),
            $this->system->glob('/boot/vmlinuz-*'),
        );

        usort($versions, version_compare(...));

        return $versions === [] ? null : end($versions);
    }

    /**
     * Detecta que el kernel en uso fue reemplazado: su directorio de módulos ya no existe aunque haya otros.
     * Se ignora si no hay ningún directorio de módulos (contenedores, WSL).
     *
     * @param string $running Versión del kernel en uso.
     *
     * @return bool true si faltan los módulos del kernel en uso.
     */
    private function areRunningKernelModulesMissing(string $running): bool
    {
        $installed = array_map('basename', $this->system->glob('/usr/lib/modules/*'));

        return $installed !== [] && ! in_array($running, $installed, true);
    }

    /**
     * Pasos para reiniciar el equipo.
     *
     * @return list<FixStep> Pasos de reinicio.
     */
    private function rebootSteps(): array
    {
        return [
            FixStep::note('Guarda tu trabajo y reinicia el equipo cuando puedas.'),
            FixStep::command('O reinicia desde la terminal.', 'sudo reboot'),
        ];
    }
}

<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Detecta si hay un reinicio pendiente para aplicar actualizaciones o un kernel nuevo.
 *
 * @package App\Services\Security\Checks
 */
class RebootRequiredCheck extends SystemCheck
{
    private const string FLAG = '/var/run/reboot-required';

    public function name(): string
    {
        return 'Reinicio pendiente';
    }

    public function category(): string
    {
        return 'Actualizaciones';
    }

    public function run(): CheckResult
    {
        $running = $this->system->runningKernel();
        $newest = $this->newestInstalledKernel();
        $details = ["Kernel en uso: {$running}"];

        if ($newest !== null && version_compare($newest, $running, '>')) {
            $details[] = "Kernel instalado más reciente: {$newest}";

            return CheckResult::warning('Hay un kernel más nuevo instalado; reinicia para usarlo.', $details);
        }

        if ($this->system->fileExists(self::FLAG)) {
            $packages = array_values(array_filter(explode("\n", $this->system->readFile(self::FLAG.'.pkgs') ?? '')));

            return CheckResult::warning('El sistema requiere reiniciarse para completar actualizaciones.', [...$details, ...$packages]);
        }

        return CheckResult::ok('No hay reinicios pendientes.', $details);
    }

    /**
     * @return string|null
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
}

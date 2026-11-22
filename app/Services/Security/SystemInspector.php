<?php

namespace App\Services\Security;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Process\ProcessResult;
use Illuminate\Support\Facades\Process;
use Symfony\Component\Process\ExecutableFinder;

/**
 * Punto único de acceso al sistema operativo (comandos y archivos),
 * para que los chequeos sean fáciles de probar con dobles.
 *
 * @package App\Services\Security
 */
class SystemInspector
{
    /**
     * Ejecuta un comando con salida en inglés (para poder interpretarla).
     *
     * @param  list<string>  $command
     * @param  int  $timeout  Segundos máximos de ejecución.
     * @return ProcessResult
     */
    public function run(array $command, int $timeout = 15): ProcessResult
    {
        return Process::timeout($timeout)
            ->env(['LANG' => 'C', 'LC_ALL' => 'C', 'LANGUAGE' => 'C'])
            ->run($command);
    }

    /**
     * Indica si un ejecutable está disponible en el PATH o en sbin.
     *
     * @return bool
     */
    public function hasCommand(string $binary): bool
    {
        return (new ExecutableFinder)->find($binary, null, ['/usr/sbin', '/sbin']) !== null;
    }

    /**
     * Estado de una unidad systemd (active, inactive, failed...).
     *
     * @return string
     */
    public function serviceState(string $unit): string
    {
        return trim($this->run(['systemctl', 'is-active', $unit])->output()) ?: 'unknown';
    }

    /**
     * @return bool
     */
    public function fileExists(string $path): bool
    {
        return is_file($path);
    }

    /**
     * Lee un archivo; retorna null si no existe o no es legible.
     *
     * @return string|null
     */
    public function readFile(string $path): ?string
    {
        if (! is_file($path) || ! is_readable($path)) {
            return null;
        }

        $contents = file_get_contents($path);

        return $contents === false ? null : $contents;
    }

    /**
     * Fecha de última modificación de un archivo.
     *
     * @return CarbonImmutable|null
     */
    public function modifiedAt(string $path): ?CarbonImmutable
    {
        if (! file_exists($path)) {
            return null;
        }

        $timestamp = filemtime($path);

        return $timestamp === false ? null : CarbonImmutable::createFromTimestamp($timestamp, config('app.timezone'));
    }

    /**
     * @return list<string>
     */
    public function glob(string $pattern): array
    {
        return glob($pattern) ?: [];
    }

    /**
     * Versión del kernel en ejecución.
     *
     * @return string
     */
    public function runningKernel(): string
    {
        return php_uname('r');
    }
}

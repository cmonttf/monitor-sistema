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
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class SystemInspector
{
    /**
     * Ejecuta un comando con salida en inglés (LANG=C) para poder interpretarla.
     *
     * @param list<string> $command Comando y argumentos, sin pasar por la shell.
     * @param int          $timeout Segundos máximos de ejecución.
     *
     * @return ProcessResult Resultado del proceso.
     */
    public function run(array $command, int $timeout = 15): ProcessResult
    {
        return Process::timeout($timeout)
            ->env(['LANG' => 'C', 'LC_ALL' => 'C', 'LANGUAGE' => 'C'])
            ->run($command);
    }

    /**
     * Indica si un ejecutable está disponible en el PATH o en /usr/sbin y /sbin.
     *
     * @param string $binary Nombre del ejecutable.
     *
     * @return bool true si se encontró.
     */
    public function hasCommand(string $binary): bool
    {
        return (new ExecutableFinder())->find($binary, null, ['/usr/sbin', '/sbin']) !== null;
    }

    /**
     * Obtiene el estado de una unidad systemd con `systemctl is-active`.
     *
     * @param string $unit Nombre de la unidad.
     *
     * @return string Estado (active, inactive, failed...) o "unknown" si no hubo respuesta.
     */
    public function serviceState(string $unit): string
    {
        return trim($this->run(['systemctl', 'is-active', $unit])->output()) ?: 'unknown';
    }

    /**
     * Indica si existe un archivo regular.
     *
     * @param string $path Ruta del archivo.
     *
     * @return bool true si existe.
     */
    public function fileExists(string $path): bool
    {
        return is_file($path);
    }

    /**
     * Lee el contenido de un archivo.
     *
     * @param string $path Ruta del archivo.
     *
     * @return string|null Contenido, o null si no existe o no es legible.
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
     * Obtiene la fecha de última modificación de un archivo o directorio.
     *
     * @param string $path Ruta del archivo o directorio.
     *
     * @return CarbonImmutable|null Fecha en la zona horaria de la aplicación, o null si no existe.
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
     * Lista las rutas que coinciden con un patrón.
     *
     * @param string $pattern Patrón de glob, por ejemplo /boot/vmlinuz-*.
     *
     * @return list<string> Rutas encontradas (vacía si no hay coincidencias).
     */
    public function glob(string $pattern): array
    {
        return glob($pattern) ?: [];
    }

    /**
     * Obtiene la versión del kernel en ejecución.
     *
     * @return string Versión, por ejemplo 7.0.0-44-generic.
     */
    public function runningKernel(): string
    {
        return php_uname('r');
    }

    /**
     * Familia del sistema operativo según PHP (Linux, Windows, Darwin...).
     *
     * @return string Valor de PHP_OS_FAMILY.
     */
    public function osFamily(): string
    {
        return PHP_OS_FAMILY;
    }

    /**
     * Versión del sistema operativo, por ejemplo "build 22631 (Windows 11)" en Windows.
     *
     * @return string Versión informada por el sistema.
     */
    public function osVersion(): string
    {
        return php_uname('v');
    }

    /**
     * Ejecuta un script de Windows PowerShell y devuelve su resultado como arreglo. El script debe terminar
     * entregando un único objeto (por ejemplo un [pscustomobject]); se convierte a JSON en UTF-8.
     *
     * @param string $script  Script de PowerShell.
     * @param int    $timeout Segundos máximos de ejecución.
     *
     * @return array<string, mixed>|null Objeto decodificado, o null si el script falló o no entregó JSON.
     */
    public function powershell(string $script, int $timeout = 30): ?array
    {
        $wrapped = "\$ProgressPreference = 'SilentlyContinue'; [Console]::OutputEncoding = [Text.Encoding]::UTF8; "
            . "\$result = & {\n{$script}\n}; ConvertTo-Json -InputObject \$result -Depth 5 -Compress";

        $result = $this->run(
            ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', $wrapped],
            $timeout
        );

        if ($result->failed()) {
            return null;
        }

        $decoded = json_decode(trim($result->output()), true);

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Huella de un archivo para detectar cambios: el SHA-256 de su contenido si es legible, o su tamaño y
     * fecha de modificación si sólo se pueden leer sus metadatos (por ejemplo /etc/shadow).
     *
     * @param string $path Ruta del archivo.
     *
     * @return string|null Huella, o null si el archivo no existe.
     */
    public function fingerprint(string $path): ?string
    {
        if (! is_file($path)) {
            return null;
        }

        if (is_readable($path)) {
            $hash = hash_file('sha256', $path);

            if ($hash !== false) {
                return "sha256:{$hash}";
            }
        }

        $stat = stat($path);

        return $stat === false ? 'sin-acceso' : "meta:{$stat['size']}:{$stat['mtime']}";
    }

    /**
     * Directorio personal del usuario que ejecuta el monitor.
     *
     * @return string Ruta absoluta (vacía si no se pudo determinar).
     */
    public function homeDirectory(): string
    {
        return (string) (getenv('HOME') ?: getenv('USERPROFILE') ?: '');
    }
}

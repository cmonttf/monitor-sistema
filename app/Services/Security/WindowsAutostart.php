<?php

namespace App\Services\Security;

use Illuminate\Support\Facades\File;

/**
 * Arranque automático del monitor en Windows sin permisos de administrador: un script de PowerShell
 * que levanta el servidor oculto y abre el panel, y accesos directos a él en la carpeta Inicio (se
 * ejecuta al iniciar sesión) y en el menú Inicio.
 *
 * @package App\Services\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class WindowsAutostart
{
    /**
     * Nombre de los accesos directos.
     */
    private const string SHORTCUT_NAME = 'Monitor de Seguridad.lnk';

    /**
     * Ícono de los accesos directos (candado de shell32.dll).
     */
    private const string SHORTCUT_ICON = '%SystemRoot%\System32\shell32.dll,47';

    /**
     * Recibe el acceso al sistema operativo.
     *
     * @param SystemInspector $system Acceso a comandos del sistema.
     */
    public function __construct(private SystemInspector $system)
    {
    }

    /**
     * Escribe el script lanzador, crea los accesos directos y levanta el monitor ahora mismo.
     *
     * @param string $php     Ruta del ejecutable de PHP.
     * @param string $artisan Ruta del archivo artisan.
     * @param string $host    Dirección en la que escucha el servidor.
     * @param int    $port    Puerto del servidor.
     *
     * @return bool true si los accesos directos se crearon correctamente.
     */
    public function install(string $php, string $artisan, string $host, int $port): bool
    {
        File::ensureDirectoryExists(dirname($this->launcherPath()));
        File::put($this->launcherPath(), $this->launcherScript($php, $artisan, $host, $port));

        $arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' . $this->launcherPath() . '"';
        $shortcuts = implode(', ', array_map(self::quote(...), $this->shortcutPaths()));

        $created = $this->system->powershell(implode("\n", [
            '$shell = New-Object -ComObject WScript.Shell',
            "foreach (\$path in @({$shortcuts})) {",
            '    $shortcut = $shell.CreateShortcut($path)',
            '    $shortcut.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"',
            '    $shortcut.Arguments = ' . self::quote($arguments),
            '    $shortcut.WorkingDirectory = ' . self::quote(self::directoryOf($artisan)),
            '    $shortcut.WindowStyle = 7',
            "    \$shortcut.Description = 'Monitor de Seguridad'",
            '    $shortcut.IconLocation = ' . self::quote(self::SHORTCUT_ICON),
            '    $shortcut.Save()',
            '}',
            '[pscustomobject]@{ ok = $true }',
        ]));

        $this->system->powershell(
            'Start-Process -FilePath powershell.exe -ArgumentList ' . self::quote($arguments) . ' -WindowStyle Hidden; '
            . '[pscustomobject]@{ ok = $true }'
        );

        return ($created['ok'] ?? false) === true;
    }

    /**
     * Elimina los accesos directos y el script lanzador, y detiene el servidor que escucha en el puerto y
     * el scheduler de las alertas.
     *
     * @param int $port Puerto del servidor.
     *
     * @return void
     */
    public function uninstall(int $port): void
    {
        File::delete([...$this->shortcutPaths(), $this->launcherPath()]);

        $this->system->powershell(implode("\n", [
            "Get-CimInstance Win32_Process -Filter \"Name = 'php.exe'\" |",
            "    Where-Object { \$_.CommandLine -match ':{$port}\\b|--port={$port}\\b|schedule:work' } |",
            '    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }',
            '[pscustomobject]@{ ok = $true }',
        ]));
    }

    /**
     * Genera el script que levanta el servidor oculto (si el puerto no está en uso), el scheduler de las
     * alertas (si no está corriendo) y abre el panel.
     *
     * @param string $php     Ruta del ejecutable de PHP.
     * @param string $artisan Ruta del archivo artisan.
     * @param string $host    Dirección en la que escucha el servidor.
     * @param int    $port    Puerto del servidor.
     *
     * @return string Contenido del script de PowerShell.
     */
    public function launcherScript(string $php, string $artisan, string $host, int $port): string
    {
        $phpPath = self::quote($php);
        $artisanArgument = self::quote('"' . $artisan . '"');

        return implode("\r\n", [
            '# Generado por «php artisan monitor:autostart»: levanta el monitor y lo abre en el navegador.',
            'Set-Location -LiteralPath ' . self::quote(self::directoryOf($artisan)),
            "\$serve = @({$artisanArgument}, 'serve', '--host={$host}', '--port={$port}', '--no-reload')",
            "if (-not (Get-NetTCPConnection -State Listen -LocalPort {$port} -ErrorAction SilentlyContinue)) {",
            "    Start-Process -FilePath {$phpPath} -ArgumentList \$serve -WindowStyle Hidden",
            '}',
            "\$scheduler = Get-CimInstance Win32_Process -Filter \"Name = 'php.exe'\" | "
                . "Where-Object { \$_.CommandLine -like '*schedule:work*' }",
            'if (-not $scheduler) {',
            "    Start-Process -FilePath {$phpPath} -ArgumentList @({$artisanArgument}, 'schedule:work')"
                . ' -WindowStyle Hidden',
            '}',
            "Start-Process -FilePath {$phpPath} -ArgumentList @({$artisanArgument}, 'monitor:open')"
                . ' -WindowStyle Hidden',
            '',
        ]);
    }

    /**
     * Ruta del script lanzador, dentro del almacenamiento de la aplicación.
     *
     * @return string Ruta absoluta.
     */
    public function launcherPath(): string
    {
        return storage_path('app' . DIRECTORY_SEPARATOR . 'monitor-seguridad.ps1');
    }

    /**
     * Rutas de los accesos directos: carpeta Inicio (arranque al iniciar sesión) y menú Inicio.
     *
     * @return list<string> Rutas absolutas.
     */
    public function shortcutPaths(): array
    {
        $programs = (getenv('APPDATA') ?: '') . '\Microsoft\Windows\Start Menu\Programs';

        return [$programs . '\Startup\\' . self::SHORTCUT_NAME, $programs . '\\' . self::SHORTCUT_NAME];
    }

    /**
     * Escribe un texto como cadena literal de PowerShell (comillas simples, duplicando las internas).
     *
     * @param string $value Texto a citar.
     *
     * @return string Cadena literal de PowerShell.
     */
    public static function quote(string $value): string
    {
        return "'" . str_replace("'", "''", $value) . "'";
    }

    /**
     * Directorio que contiene un archivo, aceptando separadores de Windows (\\) y de Unix (/).
     *
     * @param string $path Ruta de un archivo.
     *
     * @return string Directorio padre.
     */
    private static function directoryOf(string $path): string
    {
        return preg_replace('#[\\\\/][^\\\\/]*$#', '', $path) ?? $path;
    }
}

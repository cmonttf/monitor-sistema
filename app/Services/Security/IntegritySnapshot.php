<?php

namespace App\Services\Security;

/**
 * Toma la huella de los elementos que un atacante modifica para mantener el acceso a un equipo: cuentas,
 * privilegios, claves SSH autorizadas, tareas programadas, programas de inicio y el archivo hosts.
 *
 * @phpstan-type Entry array{fingerprint: string, sensitive: bool}
 *
 * @package App\Services\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class IntegritySnapshot
{
    /**
     * Archivos de Linux cuyo cambio indica una posible toma de control (cuentas y privilegios).
     */
    private const array LINUX_SENSITIVE_FILES = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/group',
        '/etc/sudoers',
        '/etc/ld.so.preload',
    ];

    /**
     * Archivos de Linux que también se vigilan (tareas, red y configuración de acceso).
     */
    private const array LINUX_FILES = [
        '/etc/hosts',
        '/etc/crontab',
        '/etc/ssh/sshd_config',
    ];

    /**
     * Patrones de archivos de Linux vigilados; cada archivo encontrado es un elemento.
     */
    private const array LINUX_GLOBS = [
        '/etc/sudoers.d/*' => true,
        '/etc/cron.d/*' => false,
        '/etc/systemd/system/*.service' => false,
    ];

    /**
     * Rutas relativas al directorio personal vigiladas en Linux: patrón => si es sensible.
     */
    private const array LINUX_HOME_GLOBS = [
        '.ssh/authorized_keys' => true,
        '.config/autostart/*.desktop' => false,
        '.config/systemd/user/*.service' => false,
        '.bashrc' => false,
        '.profile' => false,
    ];

    /**
     * Lee en Windows los elementos vigilados como texto: administradores locales, claves Run, carpetas de
     * inicio, tareas programadas, servicios automáticos y el archivo hosts.
     */
    private const string WINDOWS_SCRIPT = <<<'PS'
        $items = [ordered]@{}
        try {
            $admins = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.Name }
            $items['!Administradores locales'] = (@($admins) | Sort-Object) -join "`n"
        } catch {}
        foreach ($key in @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        )) {
            $values = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if ($values) {
                $values.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                    $items["!Inicio automático: $key\$($_.Name)"] = [string]$_.Value
                }
            }
        }
        foreach ($folder in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
            Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue | ForEach-Object {
                $items["Carpeta de inicio: $($_.FullName)"] = (Get-FileHash -LiteralPath $_.FullName).Hash
            }
        }
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }
        foreach ($task in $tasks) {
            $actions = @($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "`n"
            $items["Tarea programada: $($task.TaskPath)$($task.TaskName)"] = $actions
        }
        Get-CimInstance Win32_Service -Filter "StartMode = 'Auto'" -ErrorAction SilentlyContinue | ForEach-Object {
            $items["Servicio automático: $($_.Name)"] = [string]$_.PathName
        }
        $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        if (Test-Path -LiteralPath $hosts) {
            $items['Archivo hosts'] = (Get-FileHash -LiteralPath $hosts).Hash
        }
        [pscustomobject]@{ items = [pscustomobject]$items }
        PS;

    /**
     * Recibe el acceso al sistema operativo y la plataforma.
     *
     * @param SystemInspector $system   Acceso a comandos y archivos del sistema.
     * @param Platform        $platform Plataforma en la que corre el monitor.
     */
    public function __construct(private SystemInspector $system, private Platform $platform)
    {
    }

    /**
     * Toma la huella actual de los elementos vigilados.
     *
     * @return array<string, Entry> Elemento => huella y si su cambio es sensible.
     */
    public function capture(): array
    {
        return $this->platform->isWindows() ? $this->captureWindows() : $this->captureLinux();
    }

    /**
     * Cuentas de Linux con UID 0 (privilegios de root) además de root: una señal clara de puerta trasera.
     *
     * @return list<string> Nombres de las cuentas sospechosas.
     */
    public function extraRootAccounts(): array
    {
        if (! $this->platform->isLinux()) {
            return [];
        }

        $accounts = [];

        foreach (explode("\n", $this->system->readFile('/etc/passwd') ?? '') as $line) {
            $fields = explode(':', $line);

            if (count($fields) > 2 && $fields[2] === '0' && $fields[0] !== 'root') {
                $accounts[] = $fields[0];
            }
        }

        return $accounts;
    }

    /**
     * Toma la huella de los archivos vigilados de Linux y del crontab del usuario.
     *
     * @return array<string, Entry> Elemento => huella.
     */
    private function captureLinux(): array
    {
        $entries = [];
        $home = rtrim($this->system->homeDirectory(), '/');
        $paths = array_fill_keys(self::LINUX_SENSITIVE_FILES, true) + array_fill_keys(self::LINUX_FILES, false);

        foreach (self::LINUX_GLOBS as $pattern => $sensitive) {
            $paths += array_fill_keys($this->system->glob($pattern), $sensitive);
        }

        foreach (self::LINUX_HOME_GLOBS as $pattern => $sensitive) {
            if ($home !== '') {
                $paths += array_fill_keys($this->system->glob("{$home}/{$pattern}"), $sensitive);
            }
        }

        foreach ($paths as $path => $sensitive) {
            $fingerprint = $this->system->fingerprint((string) $path);

            if ($fingerprint !== null) {
                $entries[(string) $path] = ['fingerprint' => $fingerprint, 'sensitive' => $sensitive];
            }
        }

        $crontab = $this->system->run(['crontab', '-l']);

        if ($crontab->successful() && trim($crontab->output()) !== '') {
            $entries['Crontab del usuario'] = ['fingerprint' => 'sha256:' . hash(
                'sha256',
                $crontab->output()
            ), 'sensitive' => false];
        }

        return $entries;
    }

    /**
     * Toma la huella de los elementos vigilados de Windows; los nombres que empiezan con «!» son sensibles.
     *
     * @return array<string, Entry> Elemento => huella.
     */
    private function captureWindows(): array
    {
        $entries = [];

        foreach ($this->system->powershell(self::WINDOWS_SCRIPT, 60)['items'] ?? [] as $name => $value) {
            $sensitive = str_starts_with((string) $name, '!');
            $entries[ltrim((string) $name, '!')] = [
                'fingerprint' => 'sha256:' . hash('sha256', (string) $value),
                'sensitive' => $sensitive,
            ];
        }

        return $entries;
    }
}

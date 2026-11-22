<?php

namespace App\Console\Commands;

use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Process;

/**
 * Instala (o elimina) el arranque automático del monitor para el usuario actual:
 * un servicio systemd de usuario que levanta el servidor y una entrada de
 * autoarranque del escritorio que abre el panel en el navegador al iniciar sesión.
 *
 * @package App\Console\Commands
 */
#[Signature('monitor:autostart {--remove : Desinstala el arranque automático}')]
#[Description('Configura el monitor para que se inicie y abra en el navegador al encender el equipo')]
class InstallAutostartCommand extends Command
{
    public const string SERVICE_NAME = 'monitor-seguridad.service';

    public const string DESKTOP_NAME = 'monitor-seguridad.desktop';

    /**
     * Ejecuta el comando.
     *
     * @return int
     */
    public function handle(): int
    {
        return $this->option('remove') ? $this->uninstall() : $this->install();
    }

    /**
     * @return int
     */
    private function install(): int
    {
        File::ensureDirectoryExists(dirname($this->servicePath()));
        File::ensureDirectoryExists(dirname($this->autostartPath()));
        File::ensureDirectoryExists(dirname($this->launcherPath()));

        File::put($this->servicePath(), $this->serviceUnit());
        File::put($this->autostartPath(), $this->desktopEntry());
        File::put($this->launcherPath(), $this->desktopEntry());

        $this->components->task('Servicio systemd de usuario', fn (): bool => $this->systemctl('daemon-reload')
            && $this->systemctl('enable', self::SERVICE_NAME)
            && $this->systemctl('restart', self::SERVICE_NAME));

        $this->components->info('Listo. El monitor se levantará y abrirá en el navegador cada vez que inicies sesión.');
        $this->components->bulletList([
            'Panel: ' . $this->dashboardUrl(),
            'Servicio: ' . $this->servicePath(),
            'Autoarranque: ' . $this->autostartPath(),
            'Lanzador en el menú de aplicaciones: ' . $this->launcherPath(),
        ]);

        return self::SUCCESS;
    }

    /**
     * @return int
     */
    private function uninstall(): int
    {
        $this->systemctl('disable', '--now', self::SERVICE_NAME);

        File::delete([$this->servicePath(), $this->autostartPath(), $this->launcherPath()]);

        $this->systemctl('daemon-reload');

        $this->components->info('Arranque automático eliminado.');

        return self::SUCCESS;
    }

    /**
     * @return string
     */
    private function serviceUnit(): string
    {
        $php = PHP_BINARY;
        $artisan = base_path('artisan');
        $host = config('security-monitor.host');
        $port = config('security-monitor.port');
        $workingDirectory = base_path();

        return <<<UNIT
            [Unit]
            Description=Monitor de Seguridad (Laravel)
            After=network.target

            [Service]
            Type=simple
            WorkingDirectory={$workingDirectory}
            ExecStart="{$php}" "{$artisan}" serve --host={$host} --port={$port} --no-reload
            Restart=on-failure
            RestartSec=5

            [Install]
            WantedBy=default.target

            UNIT;
    }

    /**
     * @return string
     */
    private function desktopEntry(): string
    {
        $php = PHP_BINARY;
        $artisan = base_path('artisan');

        return <<<DESKTOP
            [Desktop Entry]
            Type=Application
            Name=Monitor de Seguridad
            Comment=Estado de los elementos de seguridad del equipo
            Exec="{$php}" "{$artisan}" monitor:open
            Icon=security-high
            Terminal=false
            Categories=System;Security;
            X-GNOME-Autostart-enabled=true
            X-GNOME-Autostart-Delay=5

            DESKTOP;
    }

    /**
     * @param  string  ...$arguments
     * @return bool
     */
    private function systemctl(string ...$arguments): bool
    {
        return Process::run(['systemctl', '--user', ...$arguments])->successful();
    }

    /**
     * @return string
     */
    private function dashboardUrl(): string
    {
        return 'http://' . config('security-monitor.host') . ':' . config('security-monitor.port');
    }

    /**
     * @return string
     */
    private function servicePath(): string
    {
        return $this->configHome() . '/systemd/user/' . self::SERVICE_NAME;
    }

    /**
     * @return string
     */
    private function autostartPath(): string
    {
        return $this->configHome() . '/autostart/' . self::DESKTOP_NAME;
    }

    /**
     * @return string
     */
    private function launcherPath(): string
    {
        $dataHome = getenv('XDG_DATA_HOME') ?: $this->home() . '/.local/share';

        return $dataHome . '/applications/' . self::DESKTOP_NAME;
    }

    /**
     * @return string
     */
    private function configHome(): string
    {
        return getenv('XDG_CONFIG_HOME') ?: $this->home() . '/.config';
    }

    /**
     * @return string
     */
    private function home(): string
    {
        return (string) (getenv('HOME') ?: $_SERVER['HOME'] ?? '');
    }
}

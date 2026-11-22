<?php

namespace App\Console\Commands;

use App\Services\Security\Platform;
use App\Services\Security\WindowsAutostart;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Process;

/**
 * Instala (o elimina) el arranque automático del monitor para el usuario actual. En Linux: un servicio
 * systemd de usuario que levanta el servidor y una entrada de autoarranque del escritorio que abre el
 * panel. En Windows: un script de PowerShell y accesos directos en las carpetas Inicio y menú Inicio.
 *
 * @package App\Console\Commands
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
#[Signature('monitor:autostart {--remove : Desinstala el arranque automático}')]
#[Description('Configura el monitor para que se inicie y abra en el navegador al encender el equipo')]
class InstallAutostartCommand extends Command
{
    /**
     * Nombre de la unidad systemd de usuario que levanta el servidor del monitor.
     */
    public const string SERVICE_NAME = 'monitor-seguridad.service';

    /**
     * Nombre de la unidad systemd de usuario que ejecuta el scheduler de las alertas programadas.
     */
    public const string SCHEDULER_SERVICE_NAME = 'monitor-seguridad-alertas.service';

    /**
     * Nombre del archivo .desktop de autoarranque y del lanzador del menú.
     */
    public const string DESKTOP_NAME = 'monitor-seguridad.desktop';

    /**
     * Instala o, con --remove, desinstala el arranque automático según el sistema operativo.
     *
     * @param Platform         $platform Plataforma en la que corre el monitor.
     * @param WindowsAutostart $windows  Instalador del arranque automático de Windows.
     *
     * @return int Código de salida.
     */
    public function handle(Platform $platform, WindowsAutostart $windows): int
    {
        if ($platform->isWindows()) {
            return $this->option('remove') ? $this->uninstallWindows($windows) : $this->installWindows($windows);
        }

        if (! $platform->isLinux()) {
            $this->components->error('El arranque automático sólo está disponible en Linux y Windows.');

            return self::FAILURE;
        }

        return $this->option('remove') ? $this->uninstall() : $this->install();
    }

    /**
     * Crea el script lanzador y los accesos directos de Windows, y levanta el monitor.
     *
     * @param WindowsAutostart $windows Instalador del arranque automático de Windows.
     *
     * @return int Código de salida.
     */
    private function installWindows(WindowsAutostart $windows): int
    {
        $isInstalled = false;

        $this->components->task('Accesos directos en Inicio', function () use ($windows, &$isInstalled): bool {
            $isInstalled = $windows->install(
                PHP_BINARY,
                base_path('artisan'),
                (string) config('security-monitor.host'),
                (int) config('security-monitor.port')
            );

            return $isInstalled;
        });

        if (! $isInstalled) {
            $this->components->error(
                'No se pudieron crear los accesos directos; revisa que PowerShell esté disponible.'
            );

            return self::FAILURE;
        }

        $this->components->info('Listo. El monitor se levantará y abrirá en el navegador cada vez que inicies sesión.');
        $this->components->bulletList([
            'Panel: ' . $this->dashboardUrl(),
            'Script lanzador: ' . $windows->launcherPath(),
            ...array_map(fn (string $path): string => 'Acceso directo: ' . $path, $windows->shortcutPaths()),
        ]);

        return self::SUCCESS;
    }

    /**
     * Elimina el arranque automático de Windows y detiene el servidor.
     *
     * @param WindowsAutostart $windows Instalador del arranque automático de Windows.
     *
     * @return int Código de salida.
     */
    private function uninstallWindows(WindowsAutostart $windows): int
    {
        $windows->uninstall((int) config('security-monitor.port'));

        $this->components->info('Arranque automático eliminado.');

        return self::SUCCESS;
    }

    /**
     * Escribe en Linux la unidad systemd, la entrada de autoarranque y el lanzador, y habilita y
     * reinicia el servicio.
     *
     * @return int Código de salida.
     */
    private function install(): int
    {
        File::ensureDirectoryExists(dirname($this->servicePath()));
        File::ensureDirectoryExists(dirname($this->autostartPath()));
        File::ensureDirectoryExists(dirname($this->launcherPath()));

        File::put($this->servicePath(), $this->serviceUnit());
        File::put($this->servicePath(self::SCHEDULER_SERVICE_NAME), $this->schedulerUnit());
        File::put($this->autostartPath(), $this->desktopEntry());
        File::put($this->launcherPath(), $this->desktopEntry());

        $this->components->task('Servicio systemd de usuario', fn (): bool => $this->systemctl('daemon-reload')
            && $this->systemctl('enable', self::SERVICE_NAME)
            && $this->systemctl('restart', self::SERVICE_NAME));
        $this->components->task('Alertas programadas (scheduler)', fn (): bool => $this->systemctl(
            'enable',
            self::SCHEDULER_SERVICE_NAME
        ) && $this->systemctl('restart', self::SCHEDULER_SERVICE_NAME));

        $this->components->info('Listo. El monitor se levantará y abrirá en el navegador cada vez que inicies sesión.');
        $this->components->bulletList([
            'Panel: ' . $this->dashboardUrl(),
            'Servicio: ' . $this->servicePath(),
            'Alertas programadas: ' . $this->servicePath(self::SCHEDULER_SERVICE_NAME),
            'Autoarranque: ' . $this->autostartPath(),
            'Lanzador en el menú de aplicaciones: ' . $this->launcherPath(),
        ]);

        return self::SUCCESS;
    }

    /**
     * Deshabilita y detiene en Linux el servicio y elimina los archivos instalados.
     *
     * @return int Código de salida.
     */
    private function uninstall(): int
    {
        $this->systemctl('disable', '--now', self::SERVICE_NAME, self::SCHEDULER_SERVICE_NAME);

        File::delete([
            $this->servicePath(),
            $this->servicePath(self::SCHEDULER_SERVICE_NAME),
            $this->autostartPath(),
            $this->launcherPath(),
        ]);

        $this->systemctl('daemon-reload');

        $this->components->info('Arranque automático eliminado.');

        return self::SUCCESS;
    }

    /**
     * Genera la unidad systemd que ejecuta `artisan serve` en la dirección configurada, con 4 workers
     * para que el monitor en tiempo real no espere a que termine una verificación completa.
     *
     * @return string Contenido de la unidad.
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
            Environment=PHP_CLI_SERVER_WORKERS=4
            ExecStart="{$php}" "{$artisan}" serve --host={$host} --port={$port} --no-reload
            Restart=on-failure
            RestartSec=5

            [Install]
            WantedBy=default.target

            UNIT;
    }

    /**
     * Genera la unidad systemd que ejecuta `artisan schedule:work`, que dispara las alertas programadas.
     *
     * @return string Contenido de la unidad.
     */
    private function schedulerUnit(): string
    {
        $php = PHP_BINARY;
        $artisan = base_path('artisan');
        $workingDirectory = base_path();

        return <<<UNIT
            [Unit]
            Description=Monitor de Seguridad: alertas programadas (Laravel scheduler)
            After=network.target

            [Service]
            Type=simple
            WorkingDirectory={$workingDirectory}
            ExecStart="{$php}" "{$artisan}" schedule:work
            Restart=on-failure
            RestartSec=10

            [Install]
            WantedBy=default.target

            UNIT;
    }

    /**
     * Genera la entrada de escritorio que ejecuta `artisan monitor:open` al iniciar sesión.
     *
     * @return string Contenido del archivo .desktop.
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
     * Ejecuta systemctl sobre el gestor de servicios del usuario.
     *
     * @param string ...$arguments Argumentos para systemctl.
     *
     * @return bool true si el comando terminó correctamente.
     */
    private function systemctl(string ...$arguments): bool
    {
        return Process::run(['systemctl', '--user', ...$arguments])->successful();
    }

    /**
     * Construye la URL del panel a partir de la configuración.
     *
     * @return string URL del panel.
     */
    private function dashboardUrl(): string
    {
        return 'http://' . config('security-monitor.host') . ':' . config('security-monitor.port');
    }

    /**
     * Ruta de una unidad systemd de usuario.
     *
     * @param string $unit Nombre de la unidad (por defecto, la del servidor del monitor).
     *
     * @return string Ruta absoluta.
     */
    private function servicePath(string $unit = self::SERVICE_NAME): string
    {
        return $this->configHome() . '/systemd/user/' . $unit;
    }

    /**
     * Ruta de la entrada de autoarranque del escritorio.
     *
     * @return string Ruta absoluta.
     */
    private function autostartPath(): string
    {
        return $this->configHome() . '/autostart/' . self::DESKTOP_NAME;
    }

    /**
     * Ruta del lanzador en el menú de aplicaciones (respeta XDG_DATA_HOME).
     *
     * @return string Ruta absoluta.
     */
    private function launcherPath(): string
    {
        $dataHome = getenv('XDG_DATA_HOME') ?: $this->home() . '/.local/share';

        return $dataHome . '/applications/' . self::DESKTOP_NAME;
    }

    /**
     * Directorio de configuración del usuario (respeta XDG_CONFIG_HOME).
     *
     * @return string Ruta absoluta.
     */
    private function configHome(): string
    {
        return getenv('XDG_CONFIG_HOME') ?: $this->home() . '/.config';
    }

    /**
     * Directorio personal del usuario.
     *
     * @return string Ruta absoluta.
     */
    private function home(): string
    {
        return (string) (getenv('HOME') ?: $_SERVER['HOME'] ?? '');
    }
}

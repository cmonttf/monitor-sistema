<?php

namespace Tests\Feature\Security;

use App\Enums\CheckStatus;
use App\Services\Security\Checks\AntivirusDaemonCheck;
use App\Services\Security\Checks\AntivirusSignaturesCheck;
use App\Services\Security\Checks\AntivirusUpdaterCheck;
use App\Services\Security\Checks\AptUpdatesCheck;
use App\Services\Security\Checks\FirewallCheck;
use App\Services\Security\Checks\OpenPortsCheck;
use App\Services\Security\Checks\RebootRequiredCheck;
use App\Services\Security\Checks\ScreenLockCheck;
use App\Services\Security\Checks\SnapUpdatesCheck;
use App\Services\Security\Checks\UnattendedUpgradesCheck;
use App\Services\Security\FixStep;
use App\Services\Security\SystemInspector;
use Illuminate\Support\Facades\Process;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * Pruebas de los chequeos de seguridad con comandos y archivos del sistema simulados.
 *
 * @package Tests\Feature\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class SecurityChecksTest extends TestCase
{
    /**
     * Impide que las pruebas ejecuten procesos reales del sistema.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        Process::preventStrayProcesses();
    }

    /**
     * Patrón de Process::fake para un comando ejecutado como array (argumentos entre comillas).
     *
     * @param string $command Comando con argumentos separados por espacios.
     *
     * @return string Patrón con cada argumento entre comillas simples.
     */
    private static function command(string $command): string
    {
        return "'" . str_replace(' ', "' '", $command) . "'";
    }

    /**
     * Extrae los comandos de una lista de pasos de solución.
     *
     * @param list<FixStep> $steps Pasos de solución.
     *
     * @return list<string> Comandos, sin los pasos que son sólo indicaciones.
     */
    private static function commands(array $steps): array
    {
        return array_values(array_filter(array_map(fn (FixStep $step): ?string => $step->command, $steps)));
    }

    /**
     * Inspector real para comandos (interceptados con Process::fake) y simulado para archivos y servicios.
     *
     * @param array<string, string|null> $files    Ruta => contenido (null = no existe).
     * @param list<string>               $commands Ejecutables que se consideran instalados.
     * @param array<string, string>      $services Unidad systemd => estado.
     *
     * @return SystemInspector Inspector parcialmente simulado.
     */
    private function inspector(array $files = [], array $commands = [], array $services = []): SystemInspector
    {
        $configure = function (MockInterface $mock) use ($files, $commands, $services): void {
            $mock->shouldReceive('hasCommand')
                ->andReturnUsing(fn (string $binary): bool => in_array($binary, $commands, true));
            $mock->shouldReceive('readFile')->andReturnUsing(fn (string $path): ?string => $files[$path] ?? null);
            $mock->shouldReceive('fileExists')->andReturnUsing(fn (string $path): bool => isset($files[$path]));
            $mock->shouldReceive('serviceState')
                ->andReturnUsing(fn (string $unit): string => $services[$unit] ?? 'inactive');
        };

        return $this->partialMock(SystemInspector::class, $configure);
    }

    /**
     * Las actualizaciones de seguridad pendientes son críticas y se listan primero.
     *
     * @return void
     */
    public function test_apt_reports_pending_security_updates_as_critical(): void
    {
        Process::fake([self::command('apt list --upgradable') => Process::result(<<<'OUT'
            Listing...
            openssl/resolute-security 3.5.1-1ubuntu1 amd64 [upgradable from: 3.5.0-1ubuntu1]
            tracker-extract/resolute-updates 3.11.0-1ubuntu1.1 amd64 [upgradable from: 3.8.2-4ubuntu2.1]
            OUT)]);

        $result = (new AptUpdatesCheck($this->inspector(commands: ['apt'])))->run();

        $this->assertSame(CheckStatus::Critical, $result->status);
        $this->assertSame('1 actualizaciones de seguridad pendientes (2 en total).', $result->message);
        $this->assertSame(['🔒 openssl', 'tracker-extract'], $result->details);
        $this->assertSame(
            'sudo apt update && sudo apt install --only-upgrade openssl tracker-extract',
            $result->fix[0]->command
        );
    }

    /**
     * Las actualizaciones normales son advertencia y sin actualizaciones el estado es correcto.
     *
     * @return void
     */
    public function test_apt_reports_regular_updates_as_warning_and_none_as_ok(): void
    {
        Process::fake([self::command('apt list --upgradable') => Process::sequence()
            ->push(Process::result("Listing...\ntracker-extract/resolute-updates 3.11 amd64 [upgradable from: 3.8]\n"))
            ->push(Process::result("Listing...\n")),
        ]);
        $check = new AptUpdatesCheck($this->inspector(commands: ['apt']));

        $this->assertSame(CheckStatus::Warning, $check->run()->status);
        $this->assertSame(CheckStatus::Ok, $check->run()->status);
    }

    /**
     * Fechas de firmas y el estado esperado para cada antigüedad.
     *
     * @return array<string, array{string, CheckStatus}> Caso => [fecha de firmas, estado esperado].
     */
    public static function signatureAges(): array
    {
        return [
            'recientes' => ['2026-11-21 10:00:00', CheckStatus::Ok],
            'algunos días' => ['2026-11-18 10:00:00', CheckStatus::Warning],
            'obsoletas' => ['2026-10-18 03:24:14', CheckStatus::Critical],
        ];
    }

    /**
     * El estado del antivirus depende de la antigüedad de las firmas.
     *
     * @param string      $signedAt Fecha de las firmas.
     * @param CheckStatus $expected Estado esperado.
     *
     * @return void
     */
    #[DataProvider('signatureAges')]
    public function test_antivirus_status_depends_on_signature_age(string $signedAt, CheckStatus $expected): void
    {
        $this->travelTo('2026-11-22 12:00:00');
        $date = date('D M j H:i:s Y', strtotime($signedAt));
        Process::fake([self::command('clamscan --version') => Process::result("ClamAV 1.5.4/28157/{$date}\n")]);

        $result = (new AntivirusSignaturesCheck($this->inspector(commands: ['clamscan'])))->run();

        $this->assertSame($expected, $result->status);
    }

    /**
     * Sin ClamAV instalado el estado es advertencia.
     *
     * @return void
     */
    public function test_missing_antivirus_is_a_warning(): void
    {
        $result = (new AntivirusSignaturesCheck($this->inspector()))->run();

        $this->assertSame(CheckStatus::Warning, $result->status);
    }

    /**
     * Un servicio freshclam fallido es crítico.
     *
     * @return void
     */
    public function test_failed_freshclam_service_is_critical(): void
    {
        $inspector = $this->inspector(commands: ['freshclam'], services: ['clamav-freshclam' => 'failed']);

        $result = (new AntivirusUpdaterCheck($inspector))->run();

        $this->assertSame(CheckStatus::Critical, $result->status);
        $this->assertContains(
            'sudo systemctl reset-failed clamav-freshclam && sudo systemctl restart clamav-freshclam',
            self::commands($result->fix)
        );
    }

    /**
     * Estados del servicio clamav-daemon y el estado esperado de la tarjeta.
     *
     * @return array<string, array{string, CheckStatus}> Caso => [estado systemd, estado esperado].
     */
    public static function daemonStates(): array
    {
        return [
            'activo' => ['active', CheckStatus::Ok],
            'cargando firmas' => ['activating', CheckStatus::Ok],
            'fallido' => ['failed', CheckStatus::Critical],
            'detenido' => ['inactive', CheckStatus::Warning],
        ];
    }

    /**
     * El estado del escáner clamd depende del estado de su servicio.
     *
     * @param string      $state    Estado systemd del servicio.
     * @param CheckStatus $expected Estado esperado.
     *
     * @return void
     */
    #[DataProvider('daemonStates')]
    public function test_clamd_status_depends_on_service_state(string $state, CheckStatus $expected): void
    {
        $inspector = $this->inspector(commands: ['clamd'], services: ['clamav-daemon' => $state]);

        $result = (new AntivirusDaemonCheck($inspector))->run();

        $this->assertSame($expected, $result->status);
    }

    /**
     * Sin clamav-daemon instalado el estado es sin datos.
     *
     * @return void
     */
    public function test_missing_clamd_is_unknown(): void
    {
        $result = (new AntivirusDaemonCheck($this->inspector()))->run();

        $this->assertSame(CheckStatus::Unknown, $result->status);
    }

    /**
     * El cortafuegos sólo es correcto si está habilitado y su servicio activo.
     *
     * @return void
     */
    public function test_firewall_is_ok_only_when_enabled_and_running(): void
    {
        $enabled = ['/etc/ufw/ufw.conf' => "ENABLED=yes\n"];

        $disabled = ['/etc/ufw/ufw.conf' => "ENABLED=no\n"];
        $statusFor = fn (SystemInspector $inspector): CheckStatus => (new FirewallCheck($inspector))->run()->status;

        $this->assertSame(CheckStatus::Ok, $statusFor($this->inspector($enabled, ['ufw'], ['ufw' => 'active'])));
        $this->assertSame(CheckStatus::Critical, $statusFor($this->inspector($disabled, ['ufw'], ['ufw' => 'active'])));
        $this->assertSame(
            CheckStatus::Critical,
            $statusFor($this->inspector($enabled, ['ufw'], ['ufw' => 'inactive']))
        );
        $this->assertSame(CheckStatus::Critical, (new FirewallCheck($this->inspector()))->run()->status);
    }

    /**
     * Las actualizaciones automáticas desactivadas son críticas.
     *
     * @return void
     */
    public function test_unattended_upgrades_disabled_is_critical(): void
    {
        $files = [
            '/etc/apt/apt.conf.d/20auto-upgrades' => "APT::Periodic::Update-Package-Lists \"1\";\n"
                . "APT::Periodic::Unattended-Upgrade \"0\";\n",
        ];

        $result = (new UnattendedUpgradesCheck($this->inspector($files, ['unattended-upgrade'])))->run();

        $this->assertSame(CheckStatus::Critical, $result->status);
    }

    /**
     * Salida de `ss -tlnH` con puertos locales y dos puertos expuestos (80 y 51330).
     */
    private const string LISTENERS = <<<'OUT'
        LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*
        LISTEN 0 511 127.0.0.1:8787 0.0.0.0:*
        LISTEN 0 128 [::1]:631 [::]:*
        LISTEN 0 511 *:80 *:*
        LISTEN 0 4096 *:51330 *:*
        OUT;

    /**
     * Simula `ss` con los puertos de prueba y `sudo ufw status verbose` con la salida indicada.
     *
     * @param string $ufwOutput   Salida simulada de UFW.
     * @param int    $ufwExitCode Código de salida simulado de sudo/UFW.
     *
     * @return void
     */
    private function fakePorts(string $ufwOutput, int $ufwExitCode = 0): void
    {
        Process::fake([
            self::command('ss -tlnH') => Process::result(self::LISTENERS),
            self::command('sudo -n /usr/sbin/ufw status verbose')
                => Process::result($ufwOutput, exitCode: $ufwExitCode),
        ]);
    }

    /**
     * Arma una salida de `ufw status verbose` activa con las reglas y la política indicadas.
     *
     * @param string $rules   Líneas de reglas en el formato de UFW.
     * @param string $default Política por defecto de entrada.
     *
     * @return string Salida simulada.
     */
    private static function ufwStatus(string $rules = '', string $default = 'deny'): string
    {
        return <<<OUT
            Status: active
            Logging: on (low)
            Default: {$default} (incoming), allow (outgoing), disabled (routed)
            New profiles: skip

            To                         Action      From
            --                         ------      ----
            {$rules}
            OUT;
    }

    /**
     * Los puertos bloqueados por la política por defecto se muestran como correctos.
     *
     * @return void
     */
    public function test_ports_blocked_by_the_default_policy_are_ok(): void
    {
        $this->fakePorts(self::ufwStatus());

        $result = (new OpenPortsCheck($this->inspector()))->run();

        $this->assertSame(CheckStatus::Ok, $result->status);
        $this->assertSame('2 servicios escuchan en la red, pero el cortafuegos los bloquea.', $result->message);
        $this->assertSame([], $result->fix);
        $this->assertSame([
            '✓ 80/tcp — bloqueado por la política por defecto (deny)',
            '✓ 51330/tcp — bloqueado por la política por defecto (deny)',
        ], $result->details);
    }

    /**
     * Un puerto permitido mediante un perfil de aplicación es advertencia.
     *
     * @return void
     */
    public function test_port_allowed_through_an_app_profile_is_a_warning(): void
    {
        $profile = '/etc/ufw/applications.d/apache2-utils.ufw.profile';
        $this->fakePorts(self::ufwStatus(
            "Apache Full                ALLOW IN    Anywhere\n"
            . 'Apache Full (v6)           ALLOW IN    Anywhere (v6)'
        ));
        $inspector = $this->inspector([$profile => "[Apache Full]\ntitle=Web\nports=80,443/tcp\n"]);
        $inspector->shouldReceive('glob')->with('/etc/ufw/applications.d/*')->andReturn([$profile]);
        $inspector->shouldReceive('glob')->with('/etc/ufw/applications.d/*/*')->andReturn([]);

        $result = (new OpenPortsCheck($inspector))->run();

        $this->assertSame(CheckStatus::Warning, $result->status);
        $this->assertSame([
            '⚠ 80/tcp — permitido por la regla «Apache Full» desde Anywhere',
            '✓ 51330/tcp — bloqueado por la política por defecto (deny)',
        ], $result->details);
        $this->assertContains('sudo ufw status numbered', self::commands($result->fix));
        $this->assertStringContainsString('«Apache Full»', implode(' ', array_column(
            array_map(fn (FixStep $step): array => $step->toArray(), $result->fix),
            'text'
        )));
    }

    /**
     * Se aplica la primera regla que coincide, incluidos rangos y orígenes restringidos.
     *
     * @return void
     */
    public function test_first_matching_rule_wins(): void
    {
        $this->fakePorts(self::ufwStatus(
            "80/tcp                     DENY IN     Anywhere\n"
            . "80,443/tcp                 ALLOW IN    Anywhere\n"
            . '51000:52000/tcp            ALLOW IN    192.168.1.0/24'
        ));

        $result = (new OpenPortsCheck($this->inspector()))->run();

        $this->assertSame([
            '⚠ 51330/tcp — permitido por la regla «51000:52000/tcp» desde 192.168.1.0/24',
            '✓ 80/tcp — bloqueado por la regla «80/tcp» desde Anywhere',
        ], $result->details);
    }

    /**
     * Las reglas de otro protocolo o de salida no abren el puerto.
     *
     * @return void
     */
    public function test_rules_for_other_protocols_or_outgoing_traffic_do_not_open_ports(): void
    {
        $this->fakePorts(self::ufwStatus(
            "80/udp                     ALLOW IN    Anywhere\n"
            . '51330                      ALLOW OUT   Anywhere'
        ));

        $result = (new OpenPortsCheck($this->inspector()))->run();

        $this->assertSame(CheckStatus::Ok, $result->status);
    }

    /**
     * Con política por defecto allow los puertos quedan accesibles.
     *
     * @return void
     */
    public function test_ports_are_open_when_the_default_policy_allows(): void
    {
        $this->fakePorts(self::ufwStatus(default: 'allow'));

        $result = (new OpenPortsCheck($this->inspector()))->run();

        $this->assertSame(CheckStatus::Warning, $result->status);
        $this->assertSame('2 puertos son accesibles desde la red a través del cortafuegos.', $result->message);
        $this->assertContains('sudo ufw default deny incoming', self::commands($result->fix));
    }

    /**
     * Sin permiso para leer UFW se listan los puertos y se explica cómo habilitarlo.
     *
     * @return void
     */
    public function test_without_permission_to_read_ufw_it_lists_ports_and_explains_how_to_enable_it(): void
    {
        $this->fakePorts('sudo: a password is required', ufwExitCode: 1);

        $result = (new OpenPortsCheck($this->inspector()))->run();

        $this->assertSame(CheckStatus::Warning, $result->status);
        $this->assertSame(
            '2 puertos TCP escuchan en la red (no se pudieron leer las reglas de UFW).',
            $result->message
        );
        $this->assertSame(['80/tcp', '51330/tcp'], $result->details);
        $this->assertStringContainsString('NOPASSWD: /usr/sbin/ufw status verbose', (string) $result->fix[0]->command);
    }

    /**
     * Sin puertos expuestos el estado es correcto.
     *
     * @return void
     */
    public function test_no_exposed_listeners_is_ok(): void
    {
        Process::fake([self::command('ss -tlnH') => Process::result("LISTEN 0 511 127.0.0.1:8787 0.0.0.0:*\n")]);

        $result = (new OpenPortsCheck($this->inspector()))->run();

        $this->assertSame(CheckStatus::Ok, $result->status);
        $this->assertSame('Ningún servicio escucha fuera del equipo.', $result->message);
    }

    /**
     * Las aplicaciones Snap pendientes indican el comando para actualizarlas.
     *
     * @return void
     */
    public function test_snap_updates_include_the_refresh_command(): void
    {
        Process::fake([self::command('snap refresh --list') => Process::result(
            "Name     Version  Rev  Size  Publisher  Notes\nfirefox  140.0    1    90MB  mozilla    -\n"
        )]);

        $result = (new SnapUpdatesCheck($this->inspector(commands: ['snap'])))->run();

        $this->assertContains('sudo snap refresh', self::commands($result->fix));
    }

    /**
     * Un kernel instalado más nuevo que el actual exige reiniciar.
     *
     * @return void
     */
    public function test_newer_installed_kernel_requires_reboot(): void
    {
        $inspector = $this->inspector();
        $inspector->shouldReceive('runningKernel')->andReturn('7.0.0-9-generic');
        $inspector->shouldReceive('glob')
            ->with('/boot/vmlinuz-*')
            ->andReturn(['/boot/vmlinuz-7.0.0-9-generic', '/boot/vmlinuz-7.0.0-10-generic']);

        $result = (new RebootRequiredCheck($inspector))->run();

        $this->assertSame(CheckStatus::Warning, $result->status);
        $this->assertContains('Kernel instalado más reciente: 7.0.0-10-generic', $result->details);
    }

    /**
     * Las aplicaciones Snap pendientes se listan como advertencia.
     *
     * @return void
     */
    public function test_snap_lists_pending_refreshes(): void
    {
        Process::fake([self::command('snap refresh --list') => Process::result(
            "Name     Version  Rev  Size  Publisher  Notes\nfirefox  140.0    1    90MB  mozilla    -\n"
        )]);

        $result = (new SnapUpdatesCheck($this->inspector(commands: ['snap'])))->run();

        $this->assertSame(CheckStatus::Warning, $result->status);
        $this->assertSame(['firefox'], $result->details);
    }

    /**
     * El bloqueo de pantalla desactivado es crítico.
     *
     * @return void
     */
    public function test_screen_lock_disabled_is_critical(): void
    {
        Process::fake([
            self::command('gsettings get org.gnome.desktop.screensaver lock-enabled') => Process::result("false\n"),
            self::command('gsettings get org.gnome.desktop.session idle-delay') => Process::result("uint32 300\n"),
        ]);

        $result = (new ScreenLockCheck($this->inspector(commands: ['gsettings'])))->run();

        $this->assertSame(CheckStatus::Critical, $result->status);
    }
}

<?php

namespace Tests\Feature\Security;

use App\Enums\CheckStatus;
use App\Enums\LinuxFamily;
use App\Services\Security\Checks\AntivirusDaemonCheck;
use App\Services\Security\Checks\AptUpdatesCheck;
use App\Services\Security\Checks\DnfAutomaticCheck;
use App\Services\Security\Checks\DnfUpdatesCheck;
use App\Services\Security\Checks\FirewallCheck;
use App\Services\Security\Checks\MandatoryAccessControlCheck;
use App\Services\Security\Checks\OpenPortsCheck;
use App\Services\Security\Checks\PacmanUpdatesCheck;
use App\Services\Security\Checks\RebootRequiredCheck;
use App\Services\Security\Checks\SshServerCheck;
use App\Services\Security\FirewalldStatus;
use App\Services\Security\FixStep;
use App\Services\Security\Platform;
use App\Services\Security\SystemInspector;
use Illuminate\Support\Facades\Process;
use Mockery\MockInterface;
use Tests\TestCase;

/**
 * Pruebas de los chequeos específicos de cada familia Linux: Fedora/RHEL (DNF, firewalld, SELinux) y Arch.
 *
 * @package Tests\Feature\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class LinuxFamiliesTest extends TestCase
{
    /**
     * Impide que las pruebas ejecuten procesos reales del sistema.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        Process::fake([]);
        Process::preventStrayProcesses();
    }

    /**
     * Inspector real para comandos (interceptados con Process::fake) y simulado para archivos y servicios.
     *
     * @param array<string, string|null> $files    Ruta => contenido.
     * @param list<string>               $commands Ejecutables que se consideran instalados.
     * @param array<string, string>      $services Unidad systemd => estado.
     * @param list<string>               $modules  Directorios de /usr/lib/modules.
     *
     * @return SystemInspector Inspector parcialmente simulado.
     */
    private function inspector(
        array $files = [],
        array $commands = [],
        array $services = [],
        array $modules = []
    ): SystemInspector {
        return $this->partialMock(SystemInspector::class, function (MockInterface $mock) use (
            $files,
            $commands,
            $services,
            $modules
        ): void {
            $mock->shouldReceive('hasCommand')->andReturnUsing(
                fn (string $binary): bool => in_array($binary, $commands, true)
            );
            $mock->shouldReceive('readFile')->andReturnUsing(fn (string $path): ?string => $files[$path] ?? null);
            $mock->shouldReceive('fileExists')->andReturnUsing(fn (string $path): bool => isset($files[$path]));
            $mock->shouldReceive('serviceState')->andReturnUsing(
                fn (string $unit): string => $services[$unit] ?? 'inactive'
            );
            $mock->shouldReceive('glob')->andReturnUsing(
                fn (string $pattern): array => $pattern === '/usr/lib/modules/*'
                    ? array_map(fn (string $module): string => "/usr/lib/modules/{$module}", $modules)
                    : []
            );
        });
    }

    /**
     * Comandos de una lista de pasos de solución.
     *
     * @param list<FixStep> $steps Pasos de solución.
     *
     * @return list<string> Comandos.
     */
    private static function commands(array $steps): array
    {
        return array_values(array_filter(array_map(fn (FixStep $step): ?string => $step->command, $steps)));
    }

    /**
     * Los chequeos de APT sólo aplican a Debian/Ubuntu y los de DNF sólo a Fedora/RHEL.
     *
     * @return void
     */
    public function test_package_checks_apply_only_to_their_family(): void
    {
        $fedora = Platform::linux(LinuxFamily::RedHat);
        $ubuntu = Platform::linux(LinuxFamily::Debian);
        $arch = Platform::linux(LinuxFamily::Arch);
        $inspector = new SystemInspector();

        $this->assertFalse((new AptUpdatesCheck($inspector, $fedora))->supports($fedora));
        $this->assertTrue((new DnfUpdatesCheck($inspector, $fedora))->supports($fedora));
        $this->assertFalse((new DnfUpdatesCheck($inspector, $ubuntu))->supports($ubuntu));
        $this->assertTrue((new PacmanUpdatesCheck($inspector, $arch))->supports($arch));
        $this->assertFalse((new DnfUpdatesCheck($inspector, Platform::windows()))->supports(Platform::windows()));
    }

    /**
     * DNF con avisos de seguridad es crítico y sugiere instalar sólo las de seguridad.
     *
     * @return void
     */
    public function test_dnf_security_updates_are_critical(): void
    {
        Process::fake([
            self::command('dnf -q check-update') => Process::result(
                "\nopenssl.x86_64                3.5.1-1.fc43        updates\n"
                . "kernel.x86_64                6.15.2-200.fc43     updates\n",
                exitCode: 100
            ),
            self::command('dnf -q updateinfo list --security') => Process::result(
                "FEDORA-2026-1a2b3c4d5e Important/Sec. openssl-3.5.1-1.fc43.x86_64\n"
            ),
        ]);
        $fedora = Platform::linux(LinuxFamily::RedHat);

        $result = (new DnfUpdatesCheck($this->inspector(commands: ['dnf']), $fedora))->run();

        $this->assertSame(CheckStatus::Critical, $result->status);
        $this->assertSame('1 avisos de seguridad pendientes (2 paquetes en total).', $result->message);
        $this->assertSame(['openssl', 'kernel'], $result->details);
        $this->assertSame('sudo dnf upgrade --security', $result->fix[0]->command);
    }

    /**
     * DNF sin actualizaciones (código 0) es correcto.
     *
     * @return void
     */
    public function test_dnf_without_updates_is_ok(): void
    {
        Process::fake([self::command('dnf -q check-update') => Process::result('')]);
        $fedora = Platform::linux(LinuxFamily::RedHat);

        $result = (new DnfUpdatesCheck($this->inspector(commands: ['dnf']), $fedora))->run();

        $this->assertSame(CheckStatus::Ok, $result->status);
    }

    /**
     * Sin temporizador de dnf-automatic activo se advierte; con uno activo es correcto.
     *
     * @return void
     */
    public function test_dnf_automatic_timer_is_required(): void
    {
        $fedora = Platform::linux(LinuxFamily::RedHat);

        $without = (new DnfAutomaticCheck($this->inspector(), $fedora))->run();
        $with = (
            new DnfAutomaticCheck($this->inspector(services: ['dnf5-automatic.timer' => 'active']), $fedora)
        )->run();

        $this->assertSame(CheckStatus::Warning, $without->status);
        $this->assertContains('sudo dnf install dnf-automatic', self::commands($without->fix));
        $this->assertSame(CheckStatus::Ok, $with->status);
    }

    /**
     * El comando checkupdates con código 2 no tiene actualizaciones; con salida lista los paquetes como advertencia.
     *
     * @return void
     */
    public function test_pacman_updates_come_from_checkupdates(): void
    {
        Process::fake([self::command('checkupdates') => Process::sequence()
            ->push(Process::result('', exitCode: 2))
            ->push(Process::result("linux 6.15.1.arch1-1 -> 6.15.2.arch1-1\nfirefox 140.0-1 -> 140.0.1-1\n")),
        ]);
        $arch = Platform::linux(LinuxFamily::Arch);
        $check = new PacmanUpdatesCheck($this->inspector(commands: ['checkupdates']), $arch);

        $this->assertSame(CheckStatus::Ok, $check->run()->status);
        $result = $check->run();
        $this->assertSame(CheckStatus::Warning, $result->status);
        $this->assertSame(['linux', 'firefox'], $result->details);
        $this->assertSame('sudo pacman -Syu', $result->fix[0]->command);
    }

    /**
     * Sin checkupdates se indica instalar pacman-contrib.
     *
     * @return void
     */
    public function test_missing_checkupdates_suggests_pacman_contrib(): void
    {
        $arch = Platform::linux(LinuxFamily::Arch);

        $result = (new PacmanUpdatesCheck($this->inspector(), $arch))->run();

        $this->assertSame(CheckStatus::Unknown, $result->status);
        $this->assertSame('sudo pacman -S pacman-contrib', $result->fix[0]->command);
    }

    /**
     * Con firewalld en ejecución el cortafuegos es correcto; detenido es crítico.
     *
     * @return void
     */
    public function test_firewalld_is_recognized(): void
    {
        Process::fake([self::command('firewall-cmd --state') => Process::sequence()
            ->push(Process::result("running\n"))
            ->push(Process::result("not running\n", exitCode: 252)),
        ]);
        $fedora = Platform::linux(LinuxFamily::RedHat);
        $check = new FirewallCheck($this->inspector(commands: ['firewall-cmd']), $fedora);

        $this->assertSame(CheckStatus::Ok, $check->run()->status);
        $stopped = $check->run();
        $this->assertSame(CheckStatus::Critical, $stopped->status);
        $this->assertSame('sudo systemctl enable --now firewalld', $stopped->fix[0]->command);
    }

    /**
     * Sin cortafuegos instalado, Fedora sugiere firewalld y Debian sugiere UFW.
     *
     * @return void
     */
    public function test_missing_firewall_suggests_the_family_default(): void
    {
        $fedora = Platform::linux(LinuxFamily::RedHat);
        $ubuntu = Platform::linux(LinuxFamily::Debian);

        $this->assertSame(
            'sudo dnf install firewalld',
            (new FirewallCheck($this->inspector(), $fedora))->run()->fix[0]->command
        );
        $this->assertSame(
            'sudo apt install ufw',
            (new FirewallCheck($this->inspector(), $ubuntu))->run()->fix[0]->command
        );
    }

    /**
     * SELinux en modo enforcing es correcto, permisivo es advertencia y deshabilitado en Fedora es crítico.
     *
     * @return void
     */
    public function test_selinux_states(): void
    {
        $fedora = Platform::linux(LinuxFamily::RedHat);
        $statusFor = fn (?string $enforce): CheckStatus => (new MandatoryAccessControlCheck(
            $this->inspector($enforce === null ? [] : ['/sys/fs/selinux/enforce' => $enforce]),
            $fedora
        ))->run()->status;

        $this->assertSame(CheckStatus::Ok, $statusFor("1\n"));
        $this->assertSame(CheckStatus::Warning, $statusFor("0\n"));
        $this->assertSame(CheckStatus::Critical, $statusFor(null));
    }

    /**
     * Sin AppArmor ni SELinux, Arch es advertencia (no los trae por defecto) y Ubuntu es crítico.
     *
     * @return void
     */
    public function test_missing_mandatory_access_control_depends_on_the_family(): void
    {
        $arch = Platform::linux(LinuxFamily::Arch);
        $ubuntu = Platform::linux(LinuxFamily::Debian);

        $this->assertSame(
            CheckStatus::Warning,
            (new MandatoryAccessControlCheck($this->inspector(), $arch))->run()->status
        );
        $this->assertSame(
            CheckStatus::Critical,
            (new MandatoryAccessControlCheck($this->inspector(), $ubuntu))->run()->status
        );
        $this->assertSame(CheckStatus::Ok, (new MandatoryAccessControlCheck(
            $this->inspector(['/sys/module/apparmor/parameters/enabled' => "Y\n"]),
            $ubuntu
        ))->run()->status);
    }

    /**
     * El servidor SSH se reconoce como «sshd» (Fedora, Arch) y los comandos usan ese nombre.
     *
     * @return void
     */
    public function test_sshd_service_name_is_used(): void
    {
        $fedora = Platform::linux(LinuxFamily::RedHat);
        $inspector = $this->inspector(
            ['/etc/ssh/sshd_config' => "PermitRootLogin yes\n"],
            services: ['sshd' => 'active']
        );

        $result = (new SshServerCheck($inspector, $fedora))->run();

        $this->assertSame(CheckStatus::Critical, $result->status);
        $this->assertContains('sudo systemctl restart sshd', self::commands($result->fix));
    }

    /**
     * En Fedora el escáner de ClamAV es el servicio clamd@scan.
     *
     * @return void
     */
    public function test_clamd_service_name_on_fedora(): void
    {
        $fedora = Platform::linux(LinuxFamily::RedHat);
        $inspector = $this->inspector(commands: ['clamd'], services: ['clamd@scan' => 'failed']);

        $result = (new AntivirusDaemonCheck($inspector, $fedora))->run();

        $this->assertSame(CheckStatus::Critical, $result->status);
        $this->assertContains(
            'sudo systemctl reset-failed clamd@scan && sudo systemctl restart clamd@scan',
            self::commands($result->fix)
        );
    }

    /**
     * Si desaparecieron los módulos del kernel en uso (Arch tras actualizar), hay que reiniciar.
     *
     * @return void
     */
    public function test_missing_running_kernel_modules_require_reboot(): void
    {
        $arch = Platform::linux(LinuxFamily::Arch);
        $inspector = $this->inspector(modules: ['6.15.2-arch1-1']);
        $inspector->shouldReceive('runningKernel')->andReturn('6.15.1-arch1-1');

        $result = (new RebootRequiredCheck($inspector, $arch))->run();

        $this->assertSame(CheckStatus::Warning, $result->status);
        $this->assertStringContainsString('módulos', $result->message);
    }

    /**
     * Sin directorio de módulos (contenedores, WSL) no se pide reiniciar por esa razón.
     *
     * @return void
     */
    public function test_absent_modules_directory_does_not_require_reboot(): void
    {
        $arch = Platform::linux(LinuxFamily::Arch);
        $inspector = $this->inspector();
        $inspector->shouldReceive('runningKernel')->andReturn('6.15.1-arch1-1');

        $result = (new RebootRequiredCheck($inspector, $arch))->run();

        $this->assertSame(CheckStatus::Ok, $result->status);
    }

    /**
     * Con firewalld, un puerto abierto por un servicio de la zona es advertencia y se sugiere quitarlo.
     *
     * @return void
     */
    public function test_open_ports_are_evaluated_against_firewalld(): void
    {
        Process::fake([
            self::command('ss -tlnH') => Process::result("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 511 *:80 *:*\n"),
            self::command('firewall-cmd --state') => Process::result("running\n"),
            self::command('firewall-cmd --get-default-zone') => Process::result("public\n"),
            self::command('firewall-cmd --zone=public --list-ports') => Process::result("\n"),
            self::command('firewall-cmd --zone=public --list-services') => Process::result("dhcpv6-client ssh\n"),
            self::command(
                'firewall-cmd --info-service=dhcpv6-client'
            ) => Process::result("dhcpv6-client\n  ports: 546/udp\n"),
            self::command('firewall-cmd --info-service=ssh') => Process::result("ssh\n  ports: 22/tcp\n  protocols:\n"),
        ]);
        $fedora = Platform::linux(LinuxFamily::RedHat);

        $result = (new OpenPortsCheck($this->inspector(commands: ['firewall-cmd']), $fedora))->run();

        $this->assertSame(CheckStatus::Warning, $result->status);
        $this->assertSame([
            '⚠ 22/tcp — permitido por el servicio «ssh» de la zona «public»',
            '✓ 80/tcp — bloqueado por la zona «public»',
        ], $result->details);
        $this->assertContains(
            'sudo firewall-cmd --permanent --zone=public --remove-service=ssh && sudo firewall-cmd --reload',
            self::commands($result->fix)
        );
    }

    /**
     * Los rangos de puertos de firewalld usan guion y respetan el protocolo.
     *
     * @return void
     */
    public function test_firewalld_port_ranges(): void
    {
        $status = new FirewalldStatus(true, 'public', ['9000-9100/tcp']);

        $this->assertTrue($status->evaluate(9050, 'tcp', false)['allowed']);
        $this->assertFalse($status->evaluate(9050, 'udp', false)['allowed']);
        $this->assertFalse($status->evaluate(9101, 'tcp', true)['allowed']);
        $this->assertSame(
            ['22/tcp', '2222/tcp'],
            FirewalldStatus::parseServicePorts("ssh\n  ports: 22/tcp 2222/tcp\n")
        );
    }
}

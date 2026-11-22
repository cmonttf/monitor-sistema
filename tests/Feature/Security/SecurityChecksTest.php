<?php

namespace Tests\Feature\Security;

use App\Enums\CheckStatus;
use App\Services\Security\Checks\AntivirusSignaturesCheck;
use App\Services\Security\Checks\AntivirusUpdaterCheck;
use App\Services\Security\Checks\AptUpdatesCheck;
use App\Services\Security\Checks\FirewallCheck;
use App\Services\Security\Checks\OpenPortsCheck;
use App\Services\Security\Checks\RebootRequiredCheck;
use App\Services\Security\Checks\ScreenLockCheck;
use App\Services\Security\Checks\SnapUpdatesCheck;
use App\Services\Security\Checks\UnattendedUpgradesCheck;
use App\Services\Security\SystemInspector;
use Illuminate\Support\Facades\Process;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class SecurityChecksTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Process::preventStrayProcesses();
    }

    /**
     * Patrón de Process::fake para un comando ejecutado como array (argumentos entre comillas).
     */
    private static function command(string $command): string
    {
        return "'".str_replace(' ', "' '", $command)."'";
    }

    /**
     * Inspector real para comandos (interceptados con Process::fake) y simulado para archivos.
     *
     * @param  array<string, string|null>  $files  Ruta => contenido (null = no existe).
     */
    private function inspector(array $files = [], array $commands = [], array $services = []): SystemInspector
    {
        return $this->partialMock(SystemInspector::class, function (MockInterface $mock) use ($files, $commands, $services): void {
            $mock->shouldReceive('hasCommand')->andReturnUsing(fn (string $binary): bool => in_array($binary, $commands, true));
            $mock->shouldReceive('readFile')->andReturnUsing(fn (string $path): ?string => $files[$path] ?? null);
            $mock->shouldReceive('fileExists')->andReturnUsing(fn (string $path): bool => isset($files[$path]));
            $mock->shouldReceive('serviceState')->andReturnUsing(fn (string $unit): string => $services[$unit] ?? 'inactive');
        });
    }

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
    }

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
     * @return array<string, array{string, CheckStatus}>
     */
    public static function signatureAges(): array
    {
        return [
            'recientes' => ['2026-11-21 10:00:00', CheckStatus::Ok],
            'algunos días' => ['2026-11-18 10:00:00', CheckStatus::Warning],
            'obsoletas' => ['2026-10-18 03:24:14', CheckStatus::Critical],
        ];
    }

    #[DataProvider('signatureAges')]
    public function test_antivirus_status_depends_on_signature_age(string $signedAt, CheckStatus $expected): void
    {
        $this->travelTo('2026-11-22 12:00:00');
        $date = date('D M j H:i:s Y', strtotime($signedAt));
        Process::fake([self::command('clamscan --version') => Process::result("ClamAV 1.5.4/28157/{$date}\n")]);

        $result = (new AntivirusSignaturesCheck($this->inspector(commands: ['clamscan'])))->run();

        $this->assertSame($expected, $result->status);
    }

    public function test_missing_antivirus_is_a_warning(): void
    {
        $result = (new AntivirusSignaturesCheck($this->inspector()))->run();

        $this->assertSame(CheckStatus::Warning, $result->status);
    }

    public function test_failed_freshclam_service_is_critical(): void
    {
        $result = (new AntivirusUpdaterCheck($this->inspector(commands: ['freshclam'], services: ['clamav-freshclam' => 'failed'])))->run();

        $this->assertSame(CheckStatus::Critical, $result->status);
    }

    public function test_firewall_is_ok_only_when_enabled_and_running(): void
    {
        $enabled = ['/etc/ufw/ufw.conf' => "ENABLED=yes\n"];

        $this->assertSame(CheckStatus::Ok, (new FirewallCheck($this->inspector($enabled, ['ufw'], ['ufw' => 'active'])))->run()->status);
        $this->assertSame(CheckStatus::Critical, (new FirewallCheck($this->inspector(['/etc/ufw/ufw.conf' => "ENABLED=no\n"], ['ufw'], ['ufw' => 'active'])))->run()->status);
        $this->assertSame(CheckStatus::Critical, (new FirewallCheck($this->inspector($enabled, ['ufw'], ['ufw' => 'inactive'])))->run()->status);
        $this->assertSame(CheckStatus::Critical, (new FirewallCheck($this->inspector()))->run()->status);
    }

    public function test_unattended_upgrades_disabled_is_critical(): void
    {
        $files = ['/etc/apt/apt.conf.d/20auto-upgrades' => "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n"];

        $result = (new UnattendedUpgradesCheck($this->inspector($files, ['unattended-upgrade'])))->run();

        $this->assertSame(CheckStatus::Critical, $result->status);
    }

    public function test_open_ports_ignores_loopback_addresses(): void
    {
        Process::fake([self::command('ss -tlnH') => Process::result(<<<'OUT'
            LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*
            LISTEN 0 511 127.0.0.1:8787 0.0.0.0:*
            LISTEN 0 128 [::1]:631 [::]:*
            LISTEN 0 511 *:80 *:*
            LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
            OUT)]);

        $result = (new OpenPortsCheck($this->inspector()))->run();

        $this->assertSame(CheckStatus::Warning, $result->status);
        $this->assertSame(['*:80', '0.0.0.0:22'], $result->details);
    }

    public function test_newer_installed_kernel_requires_reboot(): void
    {
        $inspector = $this->inspector();
        $inspector->shouldReceive('runningKernel')->andReturn('7.0.0-9-generic');
        $inspector->shouldReceive('glob')->with('/boot/vmlinuz-*')->andReturn(['/boot/vmlinuz-7.0.0-9-generic', '/boot/vmlinuz-7.0.0-10-generic']);

        $result = (new RebootRequiredCheck($inspector))->run();

        $this->assertSame(CheckStatus::Warning, $result->status);
        $this->assertContains('Kernel instalado más reciente: 7.0.0-10-generic', $result->details);
    }

    public function test_snap_lists_pending_refreshes(): void
    {
        Process::fake([self::command('snap refresh --list') => Process::result("Name     Version  Rev  Size  Publisher  Notes\nfirefox  140.0    1    90MB  mozilla    -\n")]);

        $result = (new SnapUpdatesCheck($this->inspector(commands: ['snap'])))->run();

        $this->assertSame(CheckStatus::Warning, $result->status);
        $this->assertSame(['firefox'], $result->details);
    }

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

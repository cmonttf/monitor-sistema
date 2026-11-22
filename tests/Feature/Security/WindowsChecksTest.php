<?php

namespace Tests\Feature\Security;

use App\Enums\CheckStatus;
use App\Services\Security\Checks\DiskSpaceCheck;
use App\Services\Security\Checks\MemoryCheck;
use App\Services\Security\Checks\WindowsAntivirusCheck;
use App\Services\Security\Checks\WindowsDiskEncryptionCheck;
use App\Services\Security\Checks\WindowsFirewallCheck;
use App\Services\Security\Checks\WindowsOpenPortsCheck;
use App\Services\Security\Checks\WindowsRebootCheck;
use App\Services\Security\Checks\WindowsRemoteDesktopCheck;
use App\Services\Security\Checks\WindowsScreenLockCheck;
use App\Services\Security\Checks\WindowsSecureBootCheck;
use App\Services\Security\Checks\WindowsUacCheck;
use App\Services\Security\Checks\WindowsUpdateCheck;
use App\Services\Security\Platform;
use App\Services\Security\ResourceSampler;
use App\Services\Security\SystemInspector;
use App\Services\Security\WindowsAutostart;
use Illuminate\Support\Facades\Process;
use Mockery\MockInterface;
use Tests\TestCase;

/**
 * Pruebas de los chequeos de Windows con las respuestas de PowerShell simuladas.
 *
 * @package Tests\Feature\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class WindowsChecksTest extends TestCase
{
    /**
     * Plataforma Windows con la que se construyen los chequeos.
     */
    private Platform $platform;

    /**
     * Impide que las pruebas ejecuten procesos reales y prepara la plataforma Windows.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        Process::fake([]);
        Process::preventStrayProcesses();
        $this->platform = Platform::windows('Windows 11');
    }

    /**
     * Inspector cuyo método powershell() devuelve las respuestas indicadas, en orden.
     *
     * @param array<string, mixed>|null ...$responses Objetos que entregaría PowerShell (null = falla).
     *
     * @return SystemInspector Inspector simulado.
     */
    private function powershell(?array ...$responses): SystemInspector
    {
        return $this->partialMock(SystemInspector::class, function (MockInterface $mock) use ($responses): void {
            $mock->shouldReceive('powershell')->andReturn(...$responses);
        });
    }

    /**
     * Los chequeos de Windows sólo aplican a Windows.
     *
     * @return void
     */
    public function test_windows_checks_apply_only_to_windows(): void
    {
        $check = new WindowsUpdateCheck(new SystemInspector(), $this->platform);

        $this->assertTrue($check->supports($this->platform));
        $this->assertFalse($check->supports(Platform::linux(\App\Enums\LinuxFamily::Debian)));
    }

    /**
     * Las actualizaciones de seguridad pendientes son críticas y se listan primero con candado.
     *
     * @return void
     */
    public function test_pending_security_updates_are_critical(): void
    {
        $inspector = $this->powershell(['updates' => [
            ['title' => 'Actualización acumulativa 2026-11 (KB5070000)', 'security' => true],
            ['title' => 'Controlador de Intel', 'security' => false],
        ], 'lastInstall' => '2026-11-01T10:00:00']);

        $result = (new WindowsUpdateCheck($inspector, $this->platform))->run();

        $this->assertSame(CheckStatus::Critical, $result->status);
        $this->assertSame('1 actualizaciones de seguridad pendientes (2 en total).', $result->message);
        $this->assertSame('🔒 Actualización acumulativa 2026-11 (KB5070000)', $result->details[0]);
        $this->assertSame('start ms-settings:windowsupdate', $result->fix[0]->command);
    }

    /**
     * Sin actualizaciones es correcto y si la consulta falla queda sin datos.
     *
     * @return void
     */
    public function test_windows_update_without_updates_or_failing(): void
    {
        $check = new WindowsUpdateCheck(
            $this->powershell(['updates' => [], 'lastInstall' => null], null),
            $this->platform
        );

        $this->assertSame(CheckStatus::Ok, $check->run()->status);
        $this->assertSame(CheckStatus::Unknown, $check->run()->status);
    }

    /**
     * Las claves de reinicio pendiente producen una advertencia.
     *
     * @return void
     */
    public function test_pending_reboot_is_detected(): void
    {
        $inspector = $this->powershell(
            ['windowsUpdate' => true, 'servicing' => false, 'lastBoot' => '2026-11-20T08:00:00']
        );

        $this->assertSame(CheckStatus::Warning, (new WindowsRebootCheck($inspector, $this->platform))->run()->status);
    }

    /**
     * El valor productState indica si el antivirus está activo y si sus firmas están al día.
     *
     * @return void
     */
    public function test_antivirus_product_state_is_decoded(): void
    {
        $this->assertSame(['enabled' => true, 'upToDate' => true], WindowsAntivirusCheck::decodeProductState(0x061100));
        $this->assertSame(
            ['enabled' => false, 'upToDate' => true],
            WindowsAntivirusCheck::decodeProductState(0x060100)
        );
        $this->assertSame(
            ['enabled' => true, 'upToDate' => false],
            WindowsAntivirusCheck::decodeProductState(0x061110)
        );
    }

    /**
     * Defender activo con firmas recientes es correcto; sin protección en tiempo real es crítico; con
     * firmas antiguas es crítico.
     *
     * @return void
     */
    public function test_defender_states(): void
    {
        $products = [['name' => 'Windows Defender', 'state' => 0x061100]];
        $defender = fn (bool $realTime, int $age): array => ['products' => $products, 'defender' => [
            'enabled' => true,
            'realTime' => $realTime,
            'signatureAge' => $age,
            'signatureUpdated' => '2026-11-22T00:00:00',
        ]];
        $statusFor = fn (array $data): CheckStatus => (
            new WindowsAntivirusCheck($this->powershell($data), $this->platform)
        )->run()->status;

        $this->assertSame(CheckStatus::Ok, $statusFor($defender(true, 0)));
        $this->assertSame(CheckStatus::Critical, $statusFor($defender(false, 0)));
        $this->assertSame(CheckStatus::Warning, $statusFor($defender(true, 4)));
        $this->assertSame(CheckStatus::Critical, $statusFor($defender(true, 10)));
    }

    /**
     * Sin ningún antivirus activo es crítico; un antivirus de terceros activo y al día es correcto.
     *
     * @return void
     */
    public function test_antivirus_without_active_product_or_third_party(): void
    {
        $none = $this->powershell(
            ['products' => [['name' => 'Windows Defender', 'state' => 0x060100]], 'defender' => null]
        );
        $thirdParty = $this->powershell(
            ['products' => [['name' => 'ESET Security', 'state' => 0x041000]], 'defender' => null]
        );

        $this->assertSame(CheckStatus::Critical, (new WindowsAntivirusCheck($none, $this->platform))->run()->status);
        $result = (new WindowsAntivirusCheck($thirdParty, $this->platform))->run();
        $this->assertSame(CheckStatus::Ok, $result->status);
        $this->assertSame('ESET Security está activo y al día.', $result->message);
    }

    /**
     * Un perfil del firewall desactivado es crítico.
     *
     * @return void
     */
    public function test_disabled_firewall_profile_is_critical(): void
    {
        $inspector = $this->powershell(['profiles' => [
            ['name' => 'Domain', 'enabled' => true, 'inbound' => 'NotConfigured'],
            ['name' => 'Private', 'enabled' => true, 'inbound' => 'Block'],
            ['name' => 'Public', 'enabled' => false, 'inbound' => 'Block'],
        ]]);

        $result = (new WindowsFirewallCheck($inspector, $this->platform))->run();

        $this->assertSame(CheckStatus::Critical, $result->status);
        $this->assertSame('El firewall está desactivado en el perfil Público.', $result->message);
    }

    /**
     * BitLocker: cifrada es correcto, sin cifrar es advertencia y sin información queda sin datos.
     *
     * @return void
     */
    public function test_bitlocker_states(): void
    {
        $statusFor = fn (?int $protection): CheckStatus => (new WindowsDiskEncryptionCheck(
            $this->powershell(['system' => 'C:', 'drives' => [['drive' => 'C:', 'protection' => $protection]]]),
            $this->platform
        ))->run()->status;

        $this->assertSame(CheckStatus::Ok, $statusFor(1));
        $this->assertSame(CheckStatus::Warning, $statusFor(2));
        $this->assertSame(CheckStatus::Warning, $statusFor(5));
        $this->assertSame(CheckStatus::Unknown, $statusFor(null));
    }

    /**
     * Secure Boot activado, desactivado o ilegible.
     *
     * @return void
     */
    public function test_secure_boot_states(): void
    {
        $check = new WindowsSecureBootCheck(
            $this->powershell(['enabled' => 1], ['enabled' => 0], ['enabled' => null]),
            $this->platform
        );

        $this->assertSame(CheckStatus::Ok, $check->run()->status);
        $this->assertSame(CheckStatus::Warning, $check->run()->status);
        $this->assertSame(CheckStatus::Unknown, $check->run()->status);
    }

    /**
     * El bloqueo es correcto por política de inactividad o protector con contraseña; si no, advertencia.
     *
     * @return void
     */
    public function test_screen_lock_states(): void
    {
        $base = ['saverActive' => '0', 'saverSecure' => '0', 'saverTimeout' => '600', 'inactivityTimeout' => null];
        $check = new WindowsScreenLockCheck($this->powershell(
            [...$base, 'inactivityTimeout' => 300],
            [...$base, 'saverActive' => '1', 'saverSecure' => '1'],
            $base,
        ), $this->platform);

        $this->assertSame(CheckStatus::Ok, $check->run()->status);
        $this->assertSame(CheckStatus::Ok, $check->run()->status);
        $this->assertSame(CheckStatus::Warning, $check->run()->status);
    }

    /**
     * UAC deshabilitado es crítico y elevar sin preguntar es advertencia.
     *
     * @return void
     */
    public function test_uac_states(): void
    {
        $check = new WindowsUacCheck($this->powershell(
            ['enableLua' => 1, 'adminPrompt' => 5],
            ['enableLua' => 0, 'adminPrompt' => 5],
            ['enableLua' => 1, 'adminPrompt' => 0],
        ), $this->platform);

        $this->assertSame(CheckStatus::Ok, $check->run()->status);
        $this->assertSame(CheckStatus::Critical, $check->run()->status);
        $this->assertSame(CheckStatus::Warning, $check->run()->status);
    }

    /**
     * Escritorio remoto: desactivado es correcto, activo con NLA es advertencia y sin NLA es crítico.
     *
     * @return void
     */
    public function test_remote_desktop_states(): void
    {
        $check = new WindowsRemoteDesktopCheck($this->powershell(
            ['denyConnections' => 1, 'networkLevelAuth' => 1],
            ['denyConnections' => 0, 'networkLevelAuth' => 1],
            ['denyConnections' => 0, 'networkLevelAuth' => 0],
        ), $this->platform);

        $this->assertSame(CheckStatus::Ok, $check->run()->status);
        $this->assertSame(CheckStatus::Warning, $check->run()->status);
        $this->assertSame(CheckStatus::Critical, $check->run()->status);
    }

    /**
     * Los puertos expuestos se listan con su proceso; con el firewall desactivado son advertencia.
     *
     * @return void
     */
    public function test_open_ports_list_processes(): void
    {
        $listeners = [
            ['address' => '0.0.0.0', 'port' => 445, 'process' => 'System'],
            ['address' => '127.0.0.1', 'port' => 8787, 'process' => 'php'],
            ['address' => '::', 'port' => 3389, 'process' => 'svchost'],
        ];
        $check = new WindowsOpenPortsCheck($this->powershell(
            ['listeners' => $listeners, 'firewallEnabled' => true],
            ['listeners' => $listeners, 'firewallEnabled' => false],
        ), $this->platform);

        $protected = $check->run();
        $this->assertSame(CheckStatus::Ok, $protected->status);
        $this->assertSame(['445/tcp — System', '3389/tcp — svchost'], $protected->details);
        $this->assertSame(CheckStatus::Warning, $check->run()->status);
    }

    /**
     * La memoria y los discos de Windows se leen con una sola llamada y alimentan sus chequeos.
     *
     * @return void
     */
    public function test_windows_resources_are_sampled_once(): void
    {
        $gb = 1024 ** 3;
        $inspector = $this->partialMock(SystemInspector::class, function (MockInterface $mock) use ($gb): void {
            $mock->shouldReceive('powershell')->once()->andReturn([
                'memory' => ['total' => 16 * $gb, 'available' => $gb / 2, 'swapTotal' => 4 * $gb, 'swapUsed' => $gb],
                'disks' => [['device' => 'C:', 'fstype' => 'NTFS', 'size' => 500 * $gb, 'available' => 200 * $gb]],
            ]);
        });
        $sampler = new ResourceSampler($inspector, $this->platform);

        $memory = (new MemoryCheck($sampler, $this->platform))->run();
        $disk = (new DiskSpaceCheck($sampler, $this->platform))->run();

        $this->assertSame(CheckStatus::Critical, $memory->status);
        $this->assertSame('taskmgr', $memory->fix[0]->command);
        $this->assertNull($sampler->memory()['cached']);
        $this->assertSame(CheckStatus::Ok, $disk->status);
        $this->assertSame('C:', $sampler->disks()[0]['mount']);
        $this->assertSame(60.0, $sampler->disks()[0]['used_percent']);
    }

    /**
     * El script lanzador levanta el servidor sólo si el puerto está libre y luego abre el panel.
     *
     * @return void
     */
    public function test_autostart_launcher_script(): void
    {
        $script = (new WindowsAutostart(new SystemInspector()))->launcherScript(
            'C:\php\php.exe',
            "C:\\Users\\O'Brien\\monitor\\artisan",
            '127.0.0.1',
            8787
        );

        $this->assertStringContainsString("Set-Location -LiteralPath 'C:\\Users\\O''Brien\\monitor'", $script);
        $this->assertStringContainsString('Get-NetTCPConnection -State Listen -LocalPort 8787', $script);
        $this->assertStringContainsString("'serve', '--host=127.0.0.1', '--port=8787', '--no-reload'", $script);
        $this->assertStringContainsString("'monitor:open'", $script);
    }
}

<?php

namespace Tests\Feature\Security;

use App\Enums\LinuxFamily;
use App\Enums\OperatingSystem;
use App\Services\Security\Platform;
use App\Services\Security\PlatformDetector;
use App\Services\Security\SecurityMonitor;
use App\Services\Security\SystemInspector;
use Illuminate\Support\Facades\Process;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * Pruebas de la detección de plataforma y del filtrado de chequeos por plataforma.
 *
 * @package Tests\Feature\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class PlatformTest extends TestCase
{
    /**
     * Detector con el sistema operativo y el contenido de /etc/os-release indicados.
     *
     * @param string      $osFamily  Valor de PHP_OS_FAMILY simulado.
     * @param string|null $osRelease Contenido de /etc/os-release.
     *
     * @return PlatformDetector Detector con el inspector simulado.
     */
    private function detector(string $osFamily, ?string $osRelease = null): PlatformDetector
    {
        $inspector = $this->partialMock(SystemInspector::class, function (MockInterface $mock) use (
            $osFamily,
            $osRelease
        ): void {
            $mock->shouldReceive('osFamily')->andReturn($osFamily);
            $mock->shouldReceive('osVersion')->andReturn('build 22631 (Windows 11)');
            $mock->shouldReceive('readFile')->with('/etc/os-release')->andReturn($osRelease);
        });

        return new PlatformDetector($inspector);
    }

    /**
     * Distribuciones y la familia que les corresponde.
     *
     * @return array<string, array{string, LinuxFamily}> Caso => [os-release, familia esperada].
     */
    public static function distributions(): array
    {
        return [
            'Ubuntu' => ["ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 26.04 LTS\"", LinuxFamily::Debian],
            'Linux Mint' => ["ID=linuxmint\nID_LIKE=\"ubuntu debian\"", LinuxFamily::Debian],
            'Fedora' => ["ID=fedora\nPRETTY_NAME=\"Fedora Linux 43\"", LinuxFamily::RedHat],
            'Rocky' => ["ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"", LinuxFamily::RedHat],
            'Arch' => ["ID=arch\nPRETTY_NAME=\"Arch Linux\"", LinuxFamily::Arch],
            'Manjaro' => ["ID=manjaro\nID_LIKE=arch", LinuxFamily::Arch],
            'openSUSE' => ["ID=\"opensuse-tumbleweed\"\nID_LIKE=\"opensuse suse\"", LinuxFamily::Unknown],
        ];
    }

    /**
     * La familia se reconoce por ID o por ID_LIKE de /etc/os-release.
     *
     * @param string      $osRelease Contenido de /etc/os-release.
     * @param LinuxFamily $expected  Familia esperada.
     *
     * @return void
     */
    #[DataProvider('distributions')]
    public function test_linux_family_is_detected_from_os_release(string $osRelease, LinuxFamily $expected): void
    {
        $platform = $this->detector('Linux', $osRelease)->detect();

        $this->assertSame(OperatingSystem::Linux, $platform->os);
        $this->assertSame($expected, $platform->family);
    }

    /**
     * El nombre legible se toma de PRETTY_NAME.
     *
     * @return void
     */
    public function test_pretty_name_is_used_as_platform_name(): void
    {
        $platform = $this->detector('Linux', "ID=ubuntu\nPRETTY_NAME=\"Ubuntu 26.04.1 LTS\"\n")->detect();

        $this->assertSame('Ubuntu 26.04.1 LTS', $platform->name);
    }

    /**
     * Windows se detecta por PHP_OS_FAMILY, sin leer /etc/os-release.
     *
     * @return void
     */
    public function test_windows_is_detected(): void
    {
        $platform = $this->detector('Windows')->detect();

        $this->assertTrue($platform->isWindows());
        $this->assertSame('Windows build 22631 (Windows 11)', $platform->name);
    }

    /**
     * El comando de instalación usa el gestor de paquetes de cada familia.
     *
     * @return void
     */
    public function test_install_command_uses_the_family_package_manager(): void
    {
        $this->assertSame('sudo apt install ufw', LinuxFamily::Debian->installCommand('ufw'));
        $this->assertSame(
            'sudo dnf install clamav clamav-update',
            LinuxFamily::RedHat->installCommand('clamav', 'clamav-update')
        );
        $this->assertSame('sudo pacman -S pacman-contrib', LinuxFamily::Arch->installCommand('pacman-contrib'));
        $this->assertNull(LinuxFamily::Unknown->installCommand('ufw'));
        $this->assertNull(Platform::linux(LinuxFamily::Unknown)->installStep('Instala UFW.', 'ufw')->command);
    }

    /**
     * Cada plataforma ejecuta sólo sus chequeos: Windows no muestra los de Linux y viceversa.
     *
     * @return void
     */
    public function test_monitor_runs_only_the_checks_of_the_platform(): void
    {
        Process::fake([]);
        Process::preventStrayProcesses();
        $keysFor = function (Platform $platform): array {
            $this->app->instance(Platform::class, $platform);
            $keys = array_column($this->app->make(SecurityMonitor::class)->generate()['checks'], 'key');
            $this->app->forgetInstance(SecurityMonitor::class);

            return $keys;
        };

        $windows = $keysFor(Platform::windows());
        $fedora = $keysFor(Platform::linux(LinuxFamily::RedHat));
        $ubuntu = $keysFor(Platform::linux(LinuxFamily::Debian));

        $this->assertContains('windows-update-check', $windows);
        $this->assertContains('memory-check', $windows);
        $this->assertNotContains('firewall-check', $windows);
        $this->assertContains('dnf-updates-check', $fedora);
        $this->assertNotContains('apt-updates-check', $fedora);
        $this->assertNotContains('windows-update-check', $fedora);
        $this->assertContains('apt-updates-check', $ubuntu);
        $this->assertNotContains('dnf-updates-check', $ubuntu);
    }
}

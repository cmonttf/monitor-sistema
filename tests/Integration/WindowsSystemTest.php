<?php

namespace Tests\Integration;

use App\Enums\CheckStatus;
use App\Services\Security\AttackTimeline;
use App\Services\Security\Checks\SecurityCheck;
use App\Services\Security\Checks\WindowsCheck;
use App\Services\Security\Checks\WindowsFirewallCheck;
use App\Services\Security\Checks\WindowsOpenPortsCheck;
use App\Services\Security\Checks\WindowsRebootCheck;
use App\Services\Security\Checks\WindowsRemoteDesktopCheck;
use App\Services\Security\Checks\WindowsScreenLockCheck;
use App\Services\Security\Checks\WindowsUacCheck;
use App\Services\Security\IntegritySnapshot;
use App\Services\Security\Platform;
use App\Services\Security\ResourceSampler;
use App\Services\Security\SecurityMonitor;
use App\Services\Security\SystemInspector;
use App\Services\Security\WindowsAutostart;
use Illuminate\Support\Facades\Process;
use PHPUnit\Framework\Attributes\RequiresOperatingSystemFamily;
use ReflectionClass;
use Tests\TestCase;

/**
 * Pruebas de integración en un Windows real (sin simulaciones): sintaxis de los scripts de PowerShell y
 * ejecución de los chequeos contra el sistema. Se ejecutan en la CI con «php artisan test tests/Integration».
 *
 * @package Tests\Integration
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
#[RequiresOperatingSystemFamily('Windows')]
class WindowsSystemTest extends TestCase
{
    /**
     * Chequeos cuyos datos se pueden leer siempre sin administrador; si quedan sin datos, su script falló.
     */
    private const array ALWAYS_READABLE_CHECKS = [
        WindowsFirewallCheck::class,
        WindowsOpenPortsCheck::class,
        WindowsRebootCheck::class,
        WindowsRemoteDesktopCheck::class,
        WindowsScreenLockCheck::class,
        WindowsUacCheck::class,
    ];

    /**
     * Chequeos de Windows registrados en la configuración.
     *
     * @return list<class-string<SecurityCheck>> Clases de los chequeos de Windows.
     */
    private static function windowsCheckClasses(): array
    {
        return array_values(array_filter(
            config('security-monitor.checks'),
            fn (string $class): bool => is_subclass_of($class, WindowsCheck::class)
        ));
    }

    /**
     * Todos los scripts de PowerShell de la aplicación, por nombre.
     *
     * @return array<string, string> Origen => script.
     */
    private static function powershellScripts(): array
    {
        $scripts = [];

        $classes = [
            ...self::windowsCheckClasses(),
            ResourceSampler::class,
            IntegritySnapshot::class,
            AttackTimeline::class,
        ];

        foreach ($classes as $class) {
            foreach ((new ReflectionClass($class))->getConstants() as $name => $value) {
                if (is_string($value) && in_array($name, ['SCRIPT', 'WINDOWS_SCRIPT'], true)) {
                    $scripts[class_basename($class)] = str_replace('__HOURS__', '24', $value);
                }
            }
        }

        $autostart = new WindowsAutostart(app(SystemInspector::class));
        $scripts['WindowsAutostart::launcherScript'] = $autostart->launcherScript(
            PHP_BINARY,
            base_path('artisan'),
            '127.0.0.1',
            8787
        );

        return $scripts;
    }

    /**
     * El monitor se reconoce como Windows.
     *
     * @return void
     */
    public function test_platform_is_detected_as_windows(): void
    {
        $this->assertTrue(app(Platform::class)->isWindows());
    }

    /**
     * Cada script de PowerShell se analiza sin errores de sintaxis (sin ejecutarlo).
     *
     * @return void
     */
    public function test_powershell_scripts_have_valid_syntax(): void
    {
        $parser = '$errors = $null; '
            . '$source = [Console]::In.ReadToEnd(); '
            . '[void][System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$null, [ref]$errors); '
            . '$errors | ForEach-Object { $_.Message }; exit @($errors).Count';

        $scripts = self::powershellScripts();
        $this->assertGreaterThanOrEqual(17, count($scripts));

        foreach ($scripts as $origin => $script) {
            $result = Process::input($script)
                ->run(['powershell', '-NoProfile', '-NonInteractive', '-Command', $parser]);

            $this->assertTrue(
                $result->successful(),
                "Error de sintaxis en {$origin}: " . $result->output() . $result->errorOutput()
            );
        }
    }

    /**
     * Los chequeos de Windows se ejecutan contra el sistema real sin lanzar excepciones, y los que siempre
     * tienen datos los obtienen (lo que prueba que su script corre).
     *
     * @return void
     */
    public function test_windows_checks_run_against_the_real_system(): void
    {
        foreach (self::windowsCheckClasses() as $class) {
            $result = app($class)->run();

            fwrite(
                STDERR,
                sprintf("%-28s %-8s %s\n", class_basename($class), $result->status->value, $result->message)
            );

            if (in_array($class, self::ALWAYS_READABLE_CHECKS, true)) {
                $this->assertNotSame(
                    CheckStatus::Unknown,
                    $result->status,
                    class_basename($class) . ': ' . $result->message
                );
            }
        }
    }

    /**
     * La memoria y los discos se leen con CIM.
     *
     * @return void
     */
    public function test_resources_are_read(): void
    {
        $sampler = app(ResourceSampler::class);

        $this->assertGreaterThan(0, $sampler->memory()['total'] ?? 0);
        $this->assertNotEmpty($sampler->disks());
        $this->assertMatchesRegularExpression('/^[A-Z]:$/', $sampler->disks()[0]['mount']);
    }

    /**
     * El reporte completo no tiene chequeos que hayan fallado por una excepción.
     *
     * @return void
     */
    public function test_full_report_has_no_check_errors(): void
    {
        $report = app(SecurityMonitor::class)->generate();

        $this->assertNotEmpty($report['checks']);
        $this->assertNotContains('Error al ejecutar el chequeo.', array_column($report['checks'], 'message'));
    }

    /**
     * La toma de huellas lee los elementos vigilados y la línea de tiempo de ataques responde (los
     * registros que exigen administrador quedan como sin datos, no como error).
     *
     * @return void
     */
    public function test_integrity_and_attack_timeline_read_the_real_system(): void
    {
        $entries = app(IntegritySnapshot::class)->capture();
        $timeline = app(AttackTimeline::class)->events(24);

        $this->assertNotEmpty($entries);
        $this->assertArrayHasKey('Archivo hosts', $entries);
        $this->assertNotContains(
            'malware',
            $timeline['unavailable'],
            'Defender debería poder leerse sin administrador.'
        );
    }
}

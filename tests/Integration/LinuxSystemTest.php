<?php

namespace Tests\Integration;

use App\Services\Security\Platform;
use App\Services\Security\ResourceSampler;
use App\Services\Security\SecurityMonitor;
use PHPUnit\Framework\Attributes\RequiresOperatingSystemFamily;
use Tests\TestCase;

/**
 * Pruebas de integración en un Linux real (sin simulaciones): los chequeos se ejecutan contra el sistema.
 * Se ejecutan en la CI con «php artisan test tests/Integration».
 *
 * @package Tests\Integration
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
#[RequiresOperatingSystemFamily('Linux')]
class LinuxSystemTest extends TestCase
{
    /**
     * El monitor se reconoce como Linux y la familia de la distribución se detecta.
     *
     * @return void
     */
    public function test_platform_is_detected_as_linux(): void
    {
        $platform = app(Platform::class);

        $this->assertTrue($platform->isLinux());
        $this->assertNotSame('', $platform->name);
    }

    /**
     * La memoria y los discos se leen de /proc/meminfo y df.
     *
     * @return void
     */
    public function test_resources_are_read(): void
    {
        $sampler = app(ResourceSampler::class);

        $this->assertGreaterThan(0, $sampler->memory()['total'] ?? 0);
        $this->assertNotEmpty($sampler->disks());
    }

    /**
     * El reporte completo se genera sin chequeos que hayan fallado por una excepción.
     *
     * @return void
     */
    public function test_full_report_has_no_check_errors(): void
    {
        $report = app(SecurityMonitor::class)->generate();

        foreach ($report['checks'] as $check) {
            fwrite(STDERR, sprintf("%-28s %-8s %s\n", $check['name'], $check['status'], $check['message']));
        }

        $this->assertNotEmpty($report['checks']);
        $this->assertNotContains('Error al ejecutar el chequeo.', array_column($report['checks'], 'message'));
    }
}

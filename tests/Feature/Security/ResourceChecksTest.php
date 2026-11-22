<?php

namespace Tests\Feature\Security;

use App\Enums\CheckStatus;
use App\Services\Security\Checks\DiskSpaceCheck;
use App\Services\Security\Checks\MemoryCheck;
use App\Services\Security\ResourceSampler;
use App\Services\Security\SystemInspector;
use Illuminate\Support\Facades\Process;
use Mockery\MockInterface;
use Tests\TestCase;

/**
 * Pruebas del lector de memoria y discos, de sus chequeos y del endpoint en vivo.
 *
 * @package Tests\Feature\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class ResourceChecksTest extends TestCase
{
    /**
     * Patrón de Process::fake para el comando df que usa ResourceSampler.
     */
    private const string DF_COMMAND = "'df' '-B1' '--output=source,fstype,size,used,avail,target'";

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
     * Simula /proc/meminfo con los valores indicados (en GB) y devuelve el lector.
     *
     * @param float $totalGb     RAM total.
     * @param float $availableGb RAM disponible.
     * @param float $swapTotalGb Swap total.
     * @param float $swapFreeGb  Swap libre.
     *
     * @return ResourceSampler Lector con el inspector simulado.
     */
    private function samplerWithMemory(
        float $totalGb,
        float $availableGb,
        float $swapTotalGb = 8,
        float $swapFreeGb = 8
    ): ResourceSampler {
        $kb = fn (float $gb): int => (int) ($gb * 1024 * 1024);
        $meminfo = "MemTotal:       {$kb($totalGb)} kB\nMemFree:         1000 kB\n"
            . "MemAvailable:   {$kb($availableGb)} kB\nBuffers:          102400 kB\nCached:          1048576 kB\n"
            . "SwapTotal:      {$kb($swapTotalGb)} kB\nSwapFree:       {$kb($swapFreeGb)} kB\n";

        $inspector = $this->partialMock(SystemInspector::class, function (MockInterface $mock) use ($meminfo): void {
            $mock->shouldReceive('readFile')->with('/proc/meminfo')->andReturn($meminfo);
        });

        return new ResourceSampler($inspector);
    }

    /**
     * Simula la salida de df y devuelve el lector.
     *
     * @param string $output Filas de df después del encabezado.
     *
     * @return ResourceSampler Lector con df simulado.
     */
    private function samplerWithDisks(string $output): ResourceSampler
    {
        Process::fake([self::DF_COMMAND => Process::result(
            "Filesystem     Type        1B-blocks         Used        Avail Mounted on\n{$output}"
        )]);

        return new ResourceSampler(new SystemInspector());
    }

    /**
     * La RAM usada es el total menos la disponible, y la caché suma Cached y Buffers.
     *
     * @return void
     */
    public function test_memory_sample_uses_available_memory(): void
    {
        $memory = $this->samplerWithMemory(16, 6, 8, 6)->memory();

        $this->assertSame(16 * 1024 ** 3, $memory['total']);
        $this->assertSame(10 * 1024 ** 3, $memory['used']);
        $this->assertSame(6 * 1024 ** 3, $memory['available']);
        $this->assertSame((1048576 + 102400) * 1024, $memory['cached']);
        $this->assertSame(2 * 1024 ** 3, $memory['swap_used']);
    }

    /**
     * Sólo se listan discos reales, una vez por dispositivo, con el porcentaje calculado como df.
     *
     * @return void
     */
    public function test_disk_sample_skips_virtual_filesystems_and_repeated_devices(): void
    {
        $disks = $this->samplerWithDisks(<<<'OUT'
            /dev/nvme0n1p2 ext4     500000000000 270000000000 205000000000 /
            tmpfs          tmpfs      1400000000      3000000   1397000000 /run
            /dev/loop3     squashfs     80000000     80000000            0 /snap/firefox/123
            /dev/nvme0n1p1 vfat       1124999168     11280384   1113718784 /boot/efi
            /dev/nvme0n1p2 ext4     500000000000 270000000000 205000000000 /var/snap/bind
            /dev/sdb1      ext4     100000000000  50000000000  50000000000 /media/usuario/Mi Disco
            OUT)->disks();

        $this->assertSame(['/', '/boot/efi', '/media/usuario/Mi Disco'], array_column($disks, 'mount'));
        $this->assertSame(56.8, $disks[0]['used_percent']);
    }

    /**
     * El estado de la memoria depende del porcentaje de RAM usada y de la swap.
     *
     * @return void
     */
    public function test_memory_status_depends_on_usage(): void
    {
        $statusFor = fn (ResourceSampler $sampler): CheckStatus => (new MemoryCheck($sampler))->run()->status;

        $this->assertSame(CheckStatus::Ok, $statusFor($this->samplerWithMemory(16, 8)));
        $this->assertSame(CheckStatus::Warning, $statusFor($this->samplerWithMemory(16, 2)));
        $this->assertSame(CheckStatus::Critical, $statusFor($this->samplerWithMemory(16, 0.5)));
        $this->assertSame(CheckStatus::Warning, $statusFor($this->samplerWithMemory(16, 8, 8, 1)));
    }

    /**
     * La memoria con problemas indica cómo ver los procesos que más usan.
     *
     * @return void
     */
    public function test_high_memory_usage_includes_fix_steps(): void
    {
        $result = (new MemoryCheck($this->samplerWithMemory(16, 0.5)))->run();

        $this->assertSame('ps -eo pid,comm,%mem,rss --sort=-%mem | head -n 15', $result->fix[0]->command);
    }

    /**
     * Un disco con poco espacio es advertencia o crítico y la tarjeta toma el peor estado.
     *
     * @return void
     */
    public function test_disk_status_depends_on_free_space(): void
    {
        $result = (new DiskSpaceCheck($this->samplerWithDisks(<<<'OUT'
            /dev/sda1      ext4     100000000000  90000000000  10000000000 /
            /dev/sdb1      ext4     100000000000  97000000000   3000000000 /datos
            OUT)))->run();

        $this->assertSame(CheckStatus::Critical, $result->status);
        $this->assertSame('Poco espacio libre en /, /datos.', $result->message);
        $this->assertStringContainsString('du -xh --max-depth=2 /', (string) $result->fix[0]->command);
    }

    /**
     * Una partición pequeña casi vacía no se marca crítica por tener menos de 1 GB libre.
     *
     * @return void
     */
    public function test_small_partition_is_not_critical_for_having_less_than_one_gigabyte(): void
    {
        $result = (new DiskSpaceCheck($this->samplerWithDisks(<<<'OUT'
            /dev/sda2      ext4     500000000000 100000000000 400000000000 /
            /dev/sda1      vfat        536870912     10000000    526870912 /boot/efi
            OUT)))->run();

        $this->assertSame(CheckStatus::Ok, $result->status);
        $this->assertSame([], $result->fix);
    }

    /**
     * Un disco grande con menos de 1 GB libre es crítico aunque su porcentaje libre supere el 5 %.
     *
     * @return void
     */
    public function test_large_disk_with_less_than_one_gigabyte_free_is_critical(): void
    {
        $result = (new DiskSpaceCheck($this->samplerWithDisks(
            "/dev/sda1      ext4      12000000000  11000000000    900000000 /\n"
        )))->run();

        $this->assertSame(CheckStatus::Critical, $result->status);
    }

    /**
     * El endpoint en vivo entrega la muestra de memoria, los discos y las filas de ambos chequeos.
     *
     * @return void
     */
    public function test_resources_endpoint_returns_live_sample_and_checks(): void
    {
        $this->app->instance(ResourceSampler::class, $this->samplerWithMemory(16, 8));
        Process::fake([self::DF_COMMAND => Process::result(
            "Filesystem Type 1B-blocks Used Avail Mounted on\n/dev/sda1 ext4 100000000000 40000000000 60000000000 /\n"
        )]);

        $response = $this->getJson(route('security.resources'));

        $response->assertOk();
        $response->assertJsonPath('memory.total', 16 * 1024 ** 3);
        $response->assertJsonPath('disks.0.mount', '/');
        $response->assertJsonPath('checks.0.key', 'memory-check');
        $response->assertJsonPath('checks.0.status', 'ok');
        $response->assertJsonPath('checks.1.key', 'disk-space-check');
    }
}

<?php

namespace App\Services\Security;

/**
 * Lee el uso de memoria y de espacio en disco del equipo, en Linux (/proc/meminfo y df) o en Windows
 * (CIM con PowerShell). Las lecturas se guardan durante la vida del objeto para no repetirlas en una
 * misma solicitud.
 *
 * @phpstan-type MemorySample array{
 *     total: int, used: int, available: int, cached: int|null, swap_total: int, swap_used: int
 * }
 * @phpstan-type DiskSample array{
 *     device: string, mount: string, fstype: string, size: int, used: int, available: int, used_percent: float
 * }
 *
 * @package App\Services\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class ResourceSampler
{
    /**
     * Archivo del kernel con las estadísticas de memoria (valores en kB).
     */
    private const string MEMINFO = '/proc/meminfo';

    /**
     * Sistemas de archivos de discos reales; se omiten los virtuales (tmpfs, squashfs de Snap, etc.).
     */
    private const array DISK_FILESYSTEMS = [
        'ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'f2fs', 'zfs', 'vfat', 'exfat', 'ntfs', 'ntfs3', 'fuseblk',
    ];

    /**
     * Lee en Windows, con una sola llamada, la memoria (en kB y MB según la clase CIM) y las unidades fijas.
     */
    private const string WINDOWS_SCRIPT = <<<'PS'
        $os = Get-CimInstance Win32_OperatingSystem
        $pages = @(Get-CimInstance Win32_PageFileUsage)
        [pscustomobject]@{
            memory = [pscustomobject]@{
                total = [int64]$os.TotalVisibleMemorySize * 1024
                available = [int64]$os.FreePhysicalMemory * 1024
                swapTotal = [int64](($pages | Measure-Object -Property AllocatedBaseSize -Sum).Sum) * 1MB
                swapUsed = [int64](($pages | Measure-Object -Property CurrentUsage -Sum).Sum) * 1MB
            }
            disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
                [pscustomobject]@{
                    device = $_.DeviceID
                    fstype = [string]$_.FileSystem
                    size = [int64]$_.Size
                    available = [int64]$_.FreeSpace
                }
            })
        }
        PS;

    /**
     * Última lectura de memoria (false si aún no se ha leído).
     *
     * @var MemorySample|null|false
     */
    private array|null|false $memorySample = false;

    /**
     * Última lectura de discos (null si aún no se ha leído).
     *
     * @var list<DiskSample>|null
     */
    private ?array $diskSample = null;

    /**
     * Último resultado del script de Windows (null si aún no se ha ejecutado).
     *
     * @var array<string, mixed>|null
     */
    private ?array $windowsData = null;

    /**
     * Recibe el acceso al sistema operativo y la plataforma.
     *
     * @param SystemInspector $system   Acceso a comandos y archivos del sistema.
     * @param Platform        $platform Plataforma en la que corre el monitor.
     */
    public function __construct(private SystemInspector $system, private Platform $platform)
    {
    }

    /**
     * Lee el uso de memoria RAM y swap desde /proc/meminfo. La RAM usada se calcula como el total
     * menos la disponible (MemAvailable), que ya descuenta la caché que el kernel puede liberar.
     *
     * @return MemorySample|null Bytes de cada medida, o null si no se pudo leer.
     */
    public function memory(): ?array
    {
        if ($this->memorySample === false) {
            $this->memorySample = $this->platform->isWindows() ? $this->windowsMemory() : $this->linuxMemory();
        }

        return $this->memorySample;
    }

    /**
     * Lee la memoria en Linux desde /proc/meminfo.
     *
     * @return MemorySample|null Bytes de cada medida, o null si no se pudo leer.
     */
    private function linuxMemory(): ?array
    {
        $contents = $this->system->readFile(self::MEMINFO);

        if ($contents === null || preg_match_all('/^(\w+):\s+(\d+)\s*kB/m', $contents, $matches) === 0) {
            return null;
        }

        $kilobytes = array_combine($matches[1], array_map('intval', $matches[2]));
        $bytes = fn (string $key): int => ($kilobytes[$key] ?? 0) * 1024;

        if ($bytes('MemTotal') === 0) {
            return null;
        }

        return [
            'total' => $bytes('MemTotal'),
            'used' => $bytes('MemTotal') - $bytes('MemAvailable'),
            'available' => $bytes('MemAvailable'),
            'cached' => $bytes('Cached') + $bytes('Buffers'),
            'swap_total' => $bytes('SwapTotal'),
            'swap_used' => $bytes('SwapTotal') - $bytes('SwapFree'),
        ];
    }

    /**
     * Lee el espacio de los sistemas de archivos de discos reales con `df`, una vez por dispositivo.
     *
     * @return list<DiskSample> Discos montados, en el orden del sistema.
     */
    public function disks(): array
    {
        return $this->diskSample ??= $this->platform->isWindows() ? $this->windowsDisks() : $this->linuxDisks();
    }

    /**
     * Lee el espacio de los discos en Linux con df.
     *
     * @return list<DiskSample> Discos montados, en el orden que entrega df.
     */
    private function linuxDisks(): array
    {
        $result = $this->system->run(['df', '-B1', '--output=source,fstype,size,used,avail,target']);

        if ($result->failed()) {
            return [];
        }

        $disks = [];

        foreach (array_slice(explode("\n", trim($result->output())), 1) as $line) {
            $columns = preg_split('/\s+/', trim($line), 6) ?: [];

            if (count($columns) < 6 || ! in_array($columns[1], self::DISK_FILESYSTEMS, true)) {
                continue;
            }

            [$device, $fstype, $size, $used, $available, $mount] = $columns;

            if (isset($disks[$device])) {
                continue;
            }

            $capacity = (int) $used + (int) $available;

            $disks[$device] = [
                'device' => $device,
                'mount' => $mount,
                'fstype' => $fstype,
                'size' => (int) $size,
                'used' => (int) $used,
                'available' => (int) $available,
                'used_percent' => $capacity > 0 ? round((int) $used / $capacity * 100, 1) : 0.0,
            ];
        }

        return array_values($disks);
    }

    /**
     * Lee la memoria en Windows. Windows no expone una caché liberable equivalente, por eso queda en null.
     *
     * @return MemorySample|null Bytes de cada medida, o null si no se pudo leer.
     */
    private function windowsMemory(): ?array
    {
        $memory = $this->windowsSample()['memory'] ?? null;

        if (! is_array($memory) || (int) ($memory['total'] ?? 0) === 0) {
            return null;
        }

        return [
            'total' => (int) $memory['total'],
            'used' => (int) $memory['total'] - (int) $memory['available'],
            'available' => (int) $memory['available'],
            'cached' => null,
            'swap_total' => (int) $memory['swapTotal'],
            'swap_used' => (int) $memory['swapUsed'],
        ];
    }

    /**
     * Lee las unidades locales fijas de Windows.
     *
     * @return list<DiskSample> Unidades, en orden de letra.
     */
    private function windowsDisks(): array
    {
        $disks = [];

        foreach ($this->windowsSample()['disks'] ?? [] as $disk) {
            $size = (int) ($disk['size'] ?? 0);
            $available = (int) ($disk['available'] ?? 0);

            if ($size === 0) {
                continue;
            }

            $disks[] = [
                'device' => (string) $disk['device'],
                'mount' => (string) $disk['device'],
                'fstype' => (string) ($disk['fstype'] ?? ''),
                'size' => $size,
                'used' => $size - $available,
                'available' => $available,
                'used_percent' => round(($size - $available) / $size * 100, 1),
            ];
        }

        return $disks;
    }

    /**
     * Ejecuta una vez el script de Windows que lee memoria y discos.
     *
     * @return array<string, mixed> Resultado decodificado (vacío si falló).
     */
    private function windowsSample(): array
    {
        return $this->windowsData ??= $this->system->powershell(self::WINDOWS_SCRIPT) ?? [];
    }

    /**
     * Formatea una cantidad de bytes en unidades binarias con coma decimal, por ejemplo "13,1 GB".
     *
     * @param int $bytes Cantidad de bytes.
     *
     * @return string Cantidad legible.
     */
    public static function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $power = $bytes > 0 ? min((int) floor(log($bytes, 1024)), count($units) - 1) : 0;
        $value = $bytes / (1024 ** $power);

        return number_format($value, $power >= 3 ? 1 : 0, ',', '.') . ' ' . $units[$power];
    }
}

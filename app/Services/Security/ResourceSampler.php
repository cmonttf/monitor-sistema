<?php

namespace App\Services\Security;

/**
 * Lee el uso de memoria y de espacio en disco del equipo.
 *
 * @phpstan-type MemorySample array{
 *     total: int, used: int, available: int, cached: int, swap_total: int, swap_used: int
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
     * Recibe el acceso al sistema operativo.
     *
     * @param SystemInspector $system Acceso a comandos y archivos del sistema.
     */
    public function __construct(private SystemInspector $system)
    {
    }

    /**
     * Lee el uso de memoria RAM y swap desde /proc/meminfo. La RAM usada se calcula como el total
     * menos la disponible (MemAvailable), que ya descuenta la caché que el kernel puede liberar.
     *
     * @return MemorySample|null Bytes de cada medida, o null si no se pudo leer /proc/meminfo.
     */
    public function memory(): ?array
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
     * @return list<DiskSample> Discos montados, en el orden que entrega df.
     */
    public function disks(): array
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

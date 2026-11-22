<?php

namespace App\Services\Security\Checks;

use App\Enums\CheckStatus;
use App\Enums\LinuxFamily;
use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;
use App\Services\Security\Platform;
use App\Services\Security\ResourceSampler;

/**
 * Espacio libre en los discos montados.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class DiskSpaceCheck implements SecurityCheck
{
    /**
     * Porcentaje de espacio libre bajo el cual se muestra una advertencia.
     */
    public const int WARNING_FREE_PERCENT = 15;

    /**
     * Porcentaje de espacio libre bajo el cual el estado es crítico.
     */
    public const int CRITICAL_FREE_PERCENT = 5;

    /**
     * Bytes libres bajo los cuales el estado es crítico aunque el porcentaje sea mayor (1 GB).
     */
    public const int CRITICAL_FREE_BYTES = 1024 ** 3;

    /**
     * Tamaño mínimo de disco (10 GB) para aplicar el umbral absoluto; así una partición pequeña,
     * como la EFI, no aparece crítica sólo por medir menos de 1 GB.
     */
    public const int ABSOLUTE_THRESHOLD_MIN_SIZE = 10 * 1024 ** 3;

    /**
     * Recibe el lector de uso de recursos y la plataforma.
     *
     * @param ResourceSampler $resources Lector de memoria y discos.
     * @param Platform        $platform  Plataforma en la que corre el monitor.
     */
    public function __construct(private ResourceSampler $resources, private Platform $platform)
    {
    }

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Espacio en disco';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Recursos';
    }

    /**
     * Aplica a Linux y a Windows.
     *
     * @param Platform $platform Plataforma en la que corre el monitor.
     *
     * @return bool true en Linux y Windows.
     */
    public function supports(Platform $platform): bool
    {
        return $platform->isLinux() || $platform->isWindows();
    }

    /**
     * Evalúa cada disco: menos de 15 % libre es advertencia; menos de 5 % es crítico, igual que menos
     * de 1 GB en discos de 10 GB o más.
     * El estado de la tarjeta es el del disco más lleno.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $disks = $this->resources->disks();

        if ($disks === []) {
            return CheckResult::unknown('No se pudo leer el espacio de los discos.');
        }

        $worst = CheckStatus::Ok;
        $fullest = [];
        $details = [];

        foreach ($disks as $disk) {
            $status = $this->statusFor($disk['available'], $disk['size'], $disk['used_percent']);
            $details[] = "{$disk['mount']} — " . ResourceSampler::formatBytes($disk['available'])
                . ' libres de ' . ResourceSampler::formatBytes($disk['size'])
                . ' (' . number_format($disk['used_percent'], 1, ',', '.') . ' % usado)';

            if ($status->severity() > $worst->severity()) {
                $worst = $status;
            }

            if ($status !== CheckStatus::Ok) {
                $fullest[] = $disk['mount'];
            }
        }

        $root = $disks[0];
        $message = 'Quedan ' . ResourceSampler::formatBytes($root['available']) . " libres en {$root['mount']}"
            . ' (' . ResourceSampler::formatBytes($root['size']) . ' en total).';

        if ($worst === CheckStatus::Ok) {
            return CheckResult::ok($message, $details);
        }

        $warningMessage = 'Poco espacio libre en ' . implode(', ', $fullest) . '.';

        return $worst === CheckStatus::Critical
            ? CheckResult::critical($warningMessage, $details, $this->fixSteps($fullest[0]))
            : CheckResult::warning($warningMessage, $details, $this->fixSteps($fullest[0]));
    }

    /**
     * Clasifica un disco según su espacio libre.
     *
     * @param int   $available   Bytes libres.
     * @param int   $size        Bytes totales del disco.
     * @param float $usedPercent Porcentaje usado, calculado como df (sin el espacio reservado para root).
     *
     * @return CheckStatus Estado del disco.
     */
    private function statusFor(int $available, int $size, float $usedPercent): CheckStatus
    {
        $freePercent = 100 - $usedPercent;
        $isNearlyFull = $size >= self::ABSOLUTE_THRESHOLD_MIN_SIZE && $available < self::CRITICAL_FREE_BYTES;

        return match (true) {
            $freePercent < self::CRITICAL_FREE_PERCENT, $isNearlyFull => CheckStatus::Critical,
            $freePercent < self::WARNING_FREE_PERCENT => CheckStatus::Warning,
            default => CheckStatus::Ok,
        };
    }

    /**
     * Pasos para liberar espacio en un disco.
     *
     * @param string $mount Punto de montaje del disco con menos espacio.
     *
     * @return list<FixStep> Pasos de solución.
     */
    private function fixSteps(string $mount): array
    {
        if ($this->platform->isWindows()) {
            return [
                FixStep::command(
                    'Abre el Sensor de almacenamiento para liberar espacio.',
                    'start ms-settings:storagesense'
                ),
                FixStep::command(
                    'O usa el Liberador de espacio en disco (incluye «Limpiar archivos del sistema»).',
                    'cleanmgr'
                ),
                FixStep::note("Revisa en {$mount} las carpetas Descargas, la papelera y los programas que no uses."),
            ];
        }

        return [
            FixStep::command(
                'Encuentra las carpetas que más ocupan.',
                "sudo du -xh --max-depth=2 {$mount} 2>/dev/null | sort -h | tail -n 20"
            ),
            ...$this->packageCleanupSteps(),
            FixStep::command('Reduce los registros del sistema a 200 MB.', 'sudo journalctl --vacuum-size=200M'),
            FixStep::note('Vacía la papelera y revisa la carpeta Descargas.'),
        ];
    }

    /**
     * Pasos para borrar la caché del gestor de paquetes de la distribución.
     *
     * @return list<FixStep> Pasos de limpieza (vacío si la distribución no se reconoce).
     */
    private function packageCleanupSteps(): array
    {
        $command = match ($this->platform->family) {
            LinuxFamily::Debian => 'sudo apt clean && sudo apt autoremove --purge',
            LinuxFamily::RedHat => 'sudo dnf clean all && sudo dnf autoremove',
            LinuxFamily::Arch => 'sudo pacman -Sc',
            default => null,
        };

        return $command === null
            ? []
            : [FixStep::command('Borra la caché de paquetes y los paquetes que ya no se usan.', $command)];
    }
}

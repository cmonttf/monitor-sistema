<?php

namespace App\Services\Security\Checks;

use App\Enums\LinuxFamily;
use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;
use Carbon\CarbonImmutable;
use Throwable;

/**
 * Antigüedad de las firmas del antivirus ClamAV.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class AntivirusSignaturesCheck extends SystemCheck
{
    /**
     * Días de antigüedad de las firmas a partir de los cuales se muestra una advertencia.
     */
    private const int WARNING_DAYS = 2;

    /**
     * Días de antigüedad de las firmas a partir de los cuales el estado es crítico.
     */
    private const int CRITICAL_DAYS = 7;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Firmas del antivirus (ClamAV)';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Protección';
    }

    /**
     * Lee la fecha de las firmas desde `clamscan --version` y la clasifica según su antigüedad;
     * advierte si ClamAV no está instalado.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('clamscan')) {
            return CheckResult::warning(
                'No hay antivirus ClamAV instalado.',
                [],
                [
                    $this->platform->installStep(
                        'Instala ClamAV y su actualizador de firmas.',
                        ...match ($this->platform->family) {
                            LinuxFamily::RedHat => ['clamav', 'clamav-update'],
                            LinuxFamily::Arch => ['clamav'],
                            default => ['clamav', 'clamav-freshclam'],
                        }
                    ),
                ]
            );
        }

        $version = trim($this->system->run(['clamscan', '--version'])->output());
        $parts = explode('/', $version, 3);

        if (count($parts) < 3) {
            return CheckResult::unknown('No se pudo leer la versión de las firmas.', [$version]);
        }

        try {
            $signedAt = CarbonImmutable::parse($parts[2])->setTimezone(config('app.timezone'));
        } catch (Throwable) {
            return CheckResult::unknown('Fecha de firmas no reconocida.', [$version]);
        }

        $days = (int) $signedAt->diffInDays(now());
        $details = [
            "Motor: {$parts[0]}",
            "Base de firmas: {$parts[1]}",
            'Fecha de firmas: ' . $signedAt->format('d-m-Y H:i'),
        ];

        $updateSignatures = [
                FixStep::command(
                    'Descarga las firmas ahora (detiene el servicio mientras tanto para liberar la base).',
                    'sudo systemctl stop clamav-freshclam && sudo freshclam && sudo systemctl start clamav-freshclam'
                ),
                FixStep::note(
                    'Si freshclam muestra un error 429 o «cool-down», el servidor te está limitando: espera unas '
                        . 'horas y repite.'
                ),
        ];

        return match (true) {
            $days > self::CRITICAL_DAYS => CheckResult::critical(
                "Las firmas tienen {$days} días de antigüedad.",
                $details,
                $updateSignatures
            ),
            $days > self::WARNING_DAYS => CheckResult::warning(
                "Las firmas tienen {$days} días de antigüedad.",
                $details,
                $updateSignatures
            ),
            default => CheckResult::ok('Firmas actualizadas ' . $signedAt->diffForHumans() . '.', $details),
        };
    }
}

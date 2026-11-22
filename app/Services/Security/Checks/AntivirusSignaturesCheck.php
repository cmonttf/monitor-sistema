<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use Carbon\CarbonImmutable;
use Throwable;

/**
 * Antigüedad de las firmas del antivirus ClamAV.
 *
 * @package App\Services\Security\Checks
 */
class AntivirusSignaturesCheck extends SystemCheck
{
    private const int WARNING_DAYS = 2;

    private const int CRITICAL_DAYS = 7;

    public function name(): string
    {
        return 'Firmas del antivirus (ClamAV)';
    }

    public function category(): string
    {
        return 'Protección';
    }

    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('clamscan')) {
            return CheckResult::warning('No hay antivirus ClamAV instalado.', ['sudo apt install clamav clamav-freshclam']);
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
            'Fecha de firmas: '.$signedAt->format('d-m-Y H:i'),
        ];

        return match (true) {
            $days > self::CRITICAL_DAYS => CheckResult::critical("Las firmas tienen {$days} días de antigüedad.", $details),
            $days > self::WARNING_DAYS => CheckResult::warning("Las firmas tienen {$days} días de antigüedad.", $details),
            default => CheckResult::ok('Firmas actualizadas '.$signedAt->diffForHumans().'.', $details),
        };
    }
}

<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Antigüedad de la última descarga exitosa de la lista de paquetes.
 *
 * @package App\Services\Security\Checks
 */
class AptIndexFreshnessCheck extends SystemCheck
{
    private const string STAMP = '/var/lib/apt/periodic/update-success-stamp';

    private const string LISTS_DIR = '/var/lib/apt/lists';

    public function name(): string
    {
        return 'Lista de paquetes';
    }

    public function category(): string
    {
        return 'Actualizaciones';
    }

    public function run(): CheckResult
    {
        $updatedAt = $this->system->modifiedAt(self::STAMP) ?? $this->system->modifiedAt(self::LISTS_DIR);

        if ($updatedAt === null) {
            return CheckResult::unknown('No se encontró la fecha de la última actualización de APT.');
        }

        $days = (int) $updatedAt->diffInDays(now());
        $details = ['Última actualización: '.$updatedAt->format('d-m-Y H:i')];

        return match (true) {
            $days > 14 => CheckResult::critical("La lista de paquetes no se actualiza hace {$days} días.", $details),
            $days > 3 => CheckResult::warning("La lista de paquetes no se actualiza hace {$days} días.", $details),
            default => CheckResult::ok('Lista de paquetes actualizada '.$updatedAt->diffForHumans().'.', $details),
        };
    }
}

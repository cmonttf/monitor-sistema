<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Antigüedad de la última descarga exitosa de la lista de paquetes.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class AptIndexFreshnessCheck extends SystemCheck
{
    /**
     * Archivo que APT actualiza tras cada descarga exitosa de la lista de paquetes.
     */
    private const string STAMP = '/var/lib/apt/periodic/update-success-stamp';

    /**
     * Directorio de listas de APT, usado como respaldo si no existe el archivo de marca.
     */
    private const string LISTS_DIR = '/var/lib/apt/lists';

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Lista de paquetes';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Actualizaciones';
    }

    /**
     * Calcula los días desde la última actualización de la lista de paquetes: más de 3 es advertencia
     * y más de 14 es crítico.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $updatedAt = $this->system->modifiedAt(self::STAMP) ?? $this->system->modifiedAt(self::LISTS_DIR);

        if ($updatedAt === null) {
            return CheckResult::unknown('No se encontró la fecha de la última actualización de APT.');
        }

        $days = (int) $updatedAt->diffInDays(now());
        $details = ['Última actualización: ' . $updatedAt->format('d-m-Y H:i')];

        $staleMessage = "La lista de paquetes no se actualiza hace {$days} días.";
        $fix = [
                    FixStep::command('Descarga la lista de paquetes actualizada.', 'sudo apt update'),
                    FixStep::note(
                        'Si falla, revisa la conexión a internet y los repositorios en /etc/apt/sources.list.d/.'
                    ),
                ];

        return match (true) {
            $days > 14 => CheckResult::critical($staleMessage, $details, $fix),
            $days > 3 => CheckResult::warning($staleMessage, $details, $fix),
            default => CheckResult::ok('Lista de paquetes actualizada ' . $updatedAt->diffForHumans() . '.', $details),
        };
    }
}

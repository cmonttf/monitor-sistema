<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Presencia de volúmenes cifrados con LUKS/dm-crypt.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class DiskEncryptionCheck extends SystemCheck
{
    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Cifrado de disco';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Sistema';
    }

    /**
     * Busca en `lsblk` volúmenes de tipo crypt (LUKS); si no hay ninguno, advierte que el disco no está cifrado.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $result = $this->system->run(['lsblk', '-rno', 'NAME,TYPE']);

        if ($result->failed()) {
            return CheckResult::unknown('No se pudo listar los discos.');
        }

        $encrypted = collect(explode("\n", $result->output()))
            ->map(fn (string $line): array => preg_split('/\s+/', trim($line)) ?: [])
            ->filter(fn (array $columns): bool => ($columns[1] ?? null) === 'crypt')
            ->map(fn (array $columns): string => $columns[0])
            ->values()
            ->all();

        if ($encrypted !== []) {
            return CheckResult::ok('El disco está cifrado.', $encrypted);
        }

        return CheckResult::warning(
            'No se detectaron discos cifrados; los datos quedan expuestos si roban el equipo.',
            [],
            [
                FixStep::note(
                    'Cifrar el disco del sistema requiere reinstalar el sistema eligiendo cifrar el disco (LUKS) en el '
                        . 'instalador.'
                ),
                FixStep::note('Antes de reinstalar, respalda tus datos en un disco externo.'),
                FixStep::note(
                    'Para discos externos o USB, puedes cifrarlos desde la aplicación Discos (formatear con LUKS).'
                ),
            ]
        );
    }
}

<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;
use App\Services\Security\IntegrityBaseline;
use App\Services\Security\IntegritySnapshot;
use App\Services\Security\Platform;

/**
 * Monitor de integridad: compara la huella actual de los elementos que un atacante modifica para mantener
 * el acceso (cuentas, privilegios, claves SSH, tareas, inicio automático, hosts) con la línea base aceptada.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class FileIntegrityCheck implements SecurityCheck
{
    /**
     * Archivo de Linux que fuerza la carga de bibliotecas en todos los programas; técnica común de rootkits.
     */
    private const string PRELOAD_FILE = '/etc/ld.so.preload';

    /**
     * Cantidad máxima de cambios listados en los detalles.
     */
    private const int MAX_LISTED = 25;

    /**
     * Recibe la toma de huellas, la línea base y la plataforma.
     *
     * @param IntegritySnapshot $snapshot Toma de huellas de los elementos vigilados.
     * @param IntegrityBaseline $baseline Línea base aceptada.
     * @param Platform          $platform Plataforma en la que corre el monitor.
     */
    public function __construct(
        private IntegritySnapshot $snapshot,
        private IntegrityBaseline $baseline,
        private Platform $platform,
    ) {
    }

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Cambios en archivos críticos';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Detección de ataques';
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
     * Crítico si hay cuentas extra con privilegios de root, si existe /etc/ld.so.preload o si cambió un
     * elemento sensible; advertencia si cambiaron otros elementos. La primera vez registra la línea base.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $rootAccounts = $this->snapshot->extraRootAccounts();

        if ($rootAccounts !== []) {
            return CheckResult::critical(
                'Hay cuentas con privilegios de root además de root: ' . implode(', ', $rootAccounts) . '.',
                [],
                [
                    FixStep::command('Revisa las cuentas con UID 0.', "awk -F: '\$3 == 0' /etc/passwd"),
                    FixStep::note(
                        'Si no las creaste tú, el equipo probablemente está comprometido: desconéctalo de la red.'
                    ),
                ]
            );
        }

        $current = $this->snapshot->capture();

        if ($current === []) {
            return CheckResult::unknown('No se pudo leer ninguno de los elementos vigilados.');
        }

        if ($this->platform->isLinux() && isset($current[self::PRELOAD_FILE])) {
            return CheckResult::critical('Existe ' . self::PRELOAD_FILE . ', una técnica común de rootkits.', [], [
                FixStep::command('Revisa qué bibliotecas fuerza a cargar.', 'cat ' . self::PRELOAD_FILE),
                $this->platform->installStep('Busca rootkits con rkhunter.', 'rkhunter'),
            ]);
        }

        $saved = $this->baseline->load();

        if ($saved === null) {
            $this->baseline->save($current);

            return CheckResult::ok(
                'Se registró la línea base: ' . count($current) . ' elementos vigilados desde ahora.'
            );
        }

        $changes = IntegrityBaseline::compare($current, $saved['entries']);
        $since = date('d-m-Y H:i', (int) strtotime($saved['created_at']));
        $details = array_slice([
            ...array_map(fn (string $name): string => "Modificado: {$name}", $changes['changed']),
            ...array_map(fn (string $name): string => "Nuevo: {$name}", $changes['added']),
            ...array_map(fn (string $name): string => "Eliminado: {$name}", $changes['removed']),
        ], 0, self::MAX_LISTED);
        $total = count($changes['changed']) + count($changes['added']) + count($changes['removed']);

        if ($total === 0) {
            return CheckResult::ok(
                'Sin cambios desde el ' . $since . ' (' . count($current) . ' elementos vigilados).'
            );
        }

        $steps = [
            FixStep::note(
                'Revisa cada cambio. Las actualizaciones del sistema y la instalación de programas también los '
                . 'producen.'
            ),
            FixStep::command(
                'Si los cambios son legítimos, acéptalos como nueva línea base (en la carpeta del monitor).',
                'php artisan monitor:integrity --accept'
            ),
        ];

        if ($changes['sensitive'] !== []) {
            return CheckResult::critical(
                'Cambiaron elementos sensibles desde el ' . $since . ': ' . implode(
                    ', ',
                    array_slice($changes['sensitive'], 0, 3)
                ) . '.',
                $details,
                [
                    FixStep::note(
                        'Si no hiciste estos cambios, alguien pudo crear una cuenta, darse privilegios o dejar una '
                        . 'llave de acceso.'
                    ),
                    ...$steps,
                ]
            );
        }

        return CheckResult::warning("{$total} elementos cambiaron desde el {$since}.", $details, $steps);
    }
}

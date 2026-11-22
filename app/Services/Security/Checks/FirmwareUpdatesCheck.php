<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Actualizaciones de firmware disponibles vía fwupd (BIOS/UEFI, SSD, etc.).
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class FirmwareUpdatesCheck extends SystemCheck
{
    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Firmware (fwupd)';
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
     * Consulta `fwupdmgr get-updates --json` y advierte si algún dispositivo tiene firmware nuevo disponible.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('fwupdmgr')) {
            return CheckResult::unknown('fwupd no está instalado.', [], [
                FixStep::command('Instala el gestor de actualizaciones de firmware.', 'sudo apt install fwupd'),
            ]);
        }

        $result = $this->system->run(['fwupdmgr', 'get-updates', '--json'], 30);

        /**
         * Respuesta JSON de fwupd con los dispositivos y sus versiones disponibles.
         *
         * @var array{Devices?: list<array{Name?: string, Releases?: list<array{Version?: string}>}>}|null $data
         */
        $data = json_decode($result->output(), true);

        if (! is_array($data)) {
            return CheckResult::unknown('No se pudo consultar fwupd.', array_filter([trim($result->errorOutput())]));
        }

        $details = collect($data['Devices'] ?? [])
            ->filter(fn (array $device): bool => ! empty($device['Releases']))
            ->map(fn (array $device): string => ($device['Name'] ?? 'Dispositivo') . ' → '
                . ($device['Releases'][0]['Version'] ?? '?'))
            ->values()
            ->all();

        if ($details !== []) {
            return CheckResult::warning(
                count($details) . ' actualizaciones de firmware disponibles.',
                $details,
                [
                    FixStep::note('Conecta el cargador antes de actualizar firmware.'),
                    FixStep::command(
                        'Descarga los metadatos y aplica las actualizaciones (puede pedir reiniciar).',
                        'fwupdmgr refresh && fwupdmgr update'
                    ),
                ]
            );
        }

        return CheckResult::ok('El firmware está al día.');
    }
}

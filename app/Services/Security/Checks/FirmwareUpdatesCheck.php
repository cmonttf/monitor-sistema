<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Actualizaciones de firmware disponibles vía fwupd (BIOS/UEFI, SSD, etc.).
 *
 * @package App\Services\Security\Checks
 */
class FirmwareUpdatesCheck extends SystemCheck
{
    public function name(): string
    {
        return 'Firmware (fwupd)';
    }

    public function category(): string
    {
        return 'Actualizaciones';
    }

    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('fwupdmgr')) {
            return CheckResult::unknown('fwupd no está instalado.');
        }

        $result = $this->system->run(['fwupdmgr', 'get-updates', '--json'], 30);

        /**
 * @var array{Devices?: list<array{Name?: string, Releases?: list<array{Version?: string}>}>}|null $data
*/
        $data = json_decode($result->output(), true);

        if (! is_array($data)) {
            return CheckResult::unknown('No se pudo consultar fwupd.', array_filter([trim($result->errorOutput())]));
        }

        $details = collect($data['Devices'] ?? [])
            ->filter(fn (array $device): bool => ! empty($device['Releases']))
            ->map(fn (array $device): string => ($device['Name'] ?? 'Dispositivo') . ' → ' . ($device['Releases'][0]['Version'] ?? '?'))
            ->values()
            ->all();

        if ($details !== []) {
            return CheckResult::warning(count($details) . ' actualizaciones de firmware disponibles.', [...$details, 'Aplicar con: fwupdmgr update']);
        }

        return CheckResult::ok('El firmware está al día.');
    }
}

<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Puertos TCP escuchando fuera de la interfaz local.
 *
 * @package App\Services\Security\Checks
 */
class OpenPortsCheck extends SystemCheck
{
    public function name(): string
    {
        return 'Puertos abiertos a la red';
    }

    public function category(): string
    {
        return 'Red';
    }

    public function run(): CheckResult
    {
        $result = $this->system->run(['ss', '-tlnH']);

        if ($result->failed()) {
            return CheckResult::unknown('No se pudo listar los puertos.');
        }

        $exposed = collect(explode("\n", trim($result->output())))
            ->map(fn (string $line): string => preg_split('/\s+/', trim($line))[3] ?? '')
            ->filter(fn (string $address): bool => $address !== '' && ! $this->isLoopback($address))
            ->unique()
            ->values()
            ->all();

        if ($exposed !== []) {
            return CheckResult::warning(count($exposed).' puertos TCP aceptan conexiones desde la red.', $exposed);
        }

        return CheckResult::ok('Ningún servicio escucha fuera del equipo.');
    }

    /**
     * @return bool
     */
    private function isLoopback(string $address): bool
    {
        $host = trim(substr($address, 0, (int) strrpos($address, ':')), '[]');
        $host = explode('%', $host)[0];

        return str_starts_with($host, '127.') || $host === '::1';
    }
}

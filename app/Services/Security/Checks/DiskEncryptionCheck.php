<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Presencia de volúmenes cifrados con LUKS/dm-crypt.
 *
 * @package App\Services\Security\Checks
 */
class DiskEncryptionCheck extends SystemCheck
{
    public function name(): string
    {
        return 'Cifrado de disco';
    }

    public function category(): string
    {
        return 'Sistema';
    }

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

        return CheckResult::warning('No se detectaron discos cifrados; los datos quedan expuestos si roban el equipo.');
    }
}

<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;
use Illuminate\Support\Str;

/**
 * Paquetes APT pendientes de actualizar, distinguiendo los de seguridad.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class AptUpdatesCheck extends SystemCheck
{
    /**
     * Cantidad máxima de paquetes listados en los detalles de la tarjeta.
     */
    private const int MAX_LISTED = 25;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Paquetes del sistema (APT)';
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
     * Consulta `apt list --upgradable`: es crítico si hay actualizaciones de seguridad y
     * advertencia si sólo hay actualizaciones normales.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('apt')) {
            return CheckResult::unknown('APT no está disponible en este sistema.');
        }

        $result = $this->system->run(['apt', 'list', '--upgradable'], 30);

        if ($result->failed()) {
            return CheckResult::unknown('No se pudo consultar APT.', [trim($result->errorOutput())]);
        }

        $packages = collect(explode("\n", $result->output()))
            ->filter(fn (string $line): bool => str_contains($line, '[upgradable from'));

        $security = $packages->filter(fn (string $line): bool => str_contains($line, '-security'));

        $details = $packages
            ->map(fn (string $line): string => (str_contains($line, '-security') ? '🔒 ' : '') . Str::before($line, '/'))
            ->sortByDesc(fn (string $name): bool => str_starts_with($name, '🔒'))
            ->take(self::MAX_LISTED)
            ->values()
            ->all();

        if ($packages->count() > self::MAX_LISTED) {
            $details[] = '… y ' . ($packages->count() - self::MAX_LISTED) . ' más';
        }

        $packageNames = $packages->map(fn (string $line): string => Str::before($line, '/'))->values()->all();
        $fix = $this->upgradeSteps($packageNames);

        if ($security->isNotEmpty()) {
            return CheckResult::critical(
                "{$security->count()} actualizaciones de seguridad pendientes ({$packages->count()} en total).",
                $details,
                $fix,
            );
        }

        if ($packages->isNotEmpty()) {
            return CheckResult::warning("{$packages->count()} paquetes pendientes de actualizar.", $details, $fix);
        }

        return CheckResult::ok('Todos los paquetes están actualizados.');
    }

    /**
     * Arma el comando que instala exactamente los paquetes pendientes. Se usa `apt install --only-upgrade`
     * en vez de `apt upgrade` porque este último retiene ("kept back") los paquetes cuya nueva versión
     * requiere instalar dependencias nuevas.
     *
     * @param list<string> $packageNames Nombres de los paquetes pendientes.
     *
     * @return list<FixStep> Pasos para actualizar.
     */
    private function upgradeSteps(array $packageNames): array
    {
        return [
            FixStep::command(
                'Instala todas las actualizaciones pendientes, incluidas las que «apt upgrade» deja retenidas.',
                'sudo apt update && sudo apt install --only-upgrade ' . implode(' ', $packageNames)
            ),
            FixStep::note('Si alguna actualización lo pide, reinicia el equipo después de instalar.'),
        ];
    }
}

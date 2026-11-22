<?php

namespace App\Services\Security;

use App\Enums\CheckStatus;
use App\Services\Security\Checks\SecurityCheck;
use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Throwable;

/**
 * Ejecuta los chequeos configurados y construye el reporte del panel.
 *
 * @phpstan-type CheckRow array{
 *     key: string, name: string, category: string, status: string,
 *     label: string, message: string, details: list<string>,
 *     fix: list<array{text: string, command: string|null}>
 * }
 * @phpstan-type Report array{
 *     generated_at: string, overall: array{status: string, label: string},
 *     summary: array<string, int>, checks: list<CheckRow>
 * }
 *
 * @package App\Services\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class SecurityMonitor
{
    /**
     * Clave de caché donde se guarda el último reporte generado.
     */
    private const string CACHE_KEY = 'security-monitor.report';

    /**
     * Recibe el contenedor con el que se resuelven los chequeos configurados.
     *
     * @param Container $container Contenedor de servicios de Laravel.
     */
    public function __construct(private Container $container)
    {
    }

    /**
     * Obtiene el reporte desde la caché, o lo genera si expiró o se pide uno nuevo.
     *
     * @param bool $fresh true para ignorar la caché y volver a ejecutar los chequeos.
     *
     * @return Report Reporte del panel.
     */
    public function report(bool $fresh = false): array
    {
        if ($fresh) {
            Cache::forget(self::CACHE_KEY);
        }

        return Cache::remember(
            self::CACHE_KEY,
            config('security-monitor.cache_seconds'),
            fn (): array => $this->generate()
        );
    }

    /**
     * Ejecuta todos los chequeos configurados y arma el reporte con el estado global (el peor)
     * y el resumen por estado; un chequeo que falla no detiene a los demás.
     *
     * @return Report Reporte del panel.
     */
    public function generate(): array
    {
        $checks = collect(config('security-monitor.checks'))
            ->map(fn (string $class): SecurityCheck => $this->container->make($class))
            ->map(fn (SecurityCheck $check): array => $this->runCheck($check));

        $overall = $checks
            ->map(fn (array $row): CheckStatus => CheckStatus::from($row['status']))
            ->sortByDesc(fn (CheckStatus $status): int => $status->severity())
            ->first() ?? CheckStatus::Unknown;

        $summary = collect(CheckStatus::cases())
            ->mapWithKeys(fn (CheckStatus $status): array => [
                $status->value => $checks->where('status', $status->value)->count(),
            ])
            ->all();

        return [
            'generated_at' => now()->toIso8601String(),
            'overall' => ['status' => $overall->value, 'label' => $overall->label()],
            'summary' => $summary,
            'checks' => $checks->values()->all(),
        ];
    }

    /**
     * Ejecuta un chequeo y lo convierte en una fila del reporte; si lanza una excepción, la registra
     * y devuelve un resultado sin datos.
     *
     * @param SecurityCheck $check Chequeo a ejecutar.
     *
     * @return CheckRow Fila del reporte.
     */
    private function runCheck(SecurityCheck $check): array
    {
        try {
            $result = $check->run();
        } catch (Throwable $exception) {
            report($exception);
            $result = CheckResult::unknown('Error al ejecutar el chequeo.', [$exception->getMessage()]);
        }

        return [
            'key' => Str::kebab(class_basename($check)),
            'name' => $check->name(),
            'category' => $check->category(),
            'status' => $result->status->value,
            'label' => $result->status->label(),
            'message' => $result->message,
            'details' => $result->details,
            'fix' => array_map(fn (FixStep $step): array => $step->toArray(), $result->fix),
        ];
    }
}

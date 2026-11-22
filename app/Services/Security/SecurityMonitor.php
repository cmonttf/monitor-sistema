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
 * @phpstan-type CheckRow array{key: string, name: string, category: string, status: string, label: string, message: string, details: list<string>}
 * @phpstan-type Report array{generated_at: string, overall: array{status: string, label: string}, summary: array<string, int>, checks: list<CheckRow>}
 *
 * @package App\Services\Security
 */
class SecurityMonitor
{
    private const string CACHE_KEY = 'security-monitor.report';

    /**
     * @param  Container  $container  Contenedor usado para resolver los chequeos.
     */
    public function __construct(private Container $container) {}

    /**
     * Reporte en caché (o recién generado si expiró o se fuerza).
     *
     * @param  bool  $fresh  Ignora la caché y vuelve a ejecutar los chequeos.
     * @return Report
     */
    public function report(bool $fresh = false): array
    {
        if ($fresh) {
            Cache::forget(self::CACHE_KEY);
        }

        return Cache::remember(self::CACHE_KEY, config('security-monitor.cache_seconds'), fn (): array => $this->generate());
    }

    /**
     * Ejecuta todos los chequeos; un chequeo que falla no detiene a los demás.
     *
     * @return Report
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
            ->mapWithKeys(fn (CheckStatus $status): array => [$status->value => $checks->where('status', $status->value)->count()])
            ->all();

        return [
            'generated_at' => now()->toIso8601String(),
            'overall' => ['status' => $overall->value, 'label' => $overall->label()],
            'summary' => $summary,
            'checks' => $checks->values()->all(),
        ];
    }

    /**
     * @return CheckRow
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
            'details' => array_values($result->details),
        ];
    }
}

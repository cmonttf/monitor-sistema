<?php

namespace App\Services\Security;

use App\Enums\CheckStatus;
use Illuminate\Support\Facades\Storage;

/**
 * Último estado notificado de cada chequeo, para alertar sólo cuando algo cambia y no repetir el mismo
 * aviso en cada revisión programada. Se guarda en el almacenamiento local de la aplicación.
 *
 * @phpstan-import-type CheckRow from SecurityMonitor
 * @phpstan-type        Changes array{worsened: list<CheckRow>, resolved: list<CheckRow>}
 *
 * @package App\Services\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class AlertState
{
    /**
     * Ruta del archivo de estado dentro del disco local.
     */
    private const string PATH = 'security-monitor/alert-state.json';

    /**
     * Severidad mínima que se notifica (advertencia).
     */
    private const int ALERT_SEVERITY = 2;

    /**
     * Carga el último estado notificado.
     *
     * @return array<string, string> Clave del chequeo => estado.
     */
    public function load(): array
    {
        if (! Storage::disk('local')->exists(self::PATH)) {
            return [];
        }

        $data = json_decode((string) Storage::disk('local')->get(self::PATH), true);

        return is_array($data['checks'] ?? null) ? $data['checks'] : [];
    }

    /**
     * Guarda el estado actual de los chequeos como último estado notificado.
     *
     * @param list<CheckRow> $checks Filas del reporte.
     *
     * @return void
     */
    public function save(array $checks): void
    {
        Storage::disk('local')->put(self::PATH, (string) json_encode([
            'updated_at' => now()->toIso8601String(),
            'checks' => array_column($checks, 'status', 'key'),
        ], JSON_PRETTY_PRINT));
    }

    /**
     * Compara el reporte con el último estado notificado. Empeora un chequeo que sube a advertencia o
     * crítico desde un estado menos grave (un chequeo nuevo cuenta como si antes estuviera al día); se
     * resuelve uno que vuelve a «al día» desde advertencia o crítico. Los cambios a «sin datos» no avisan.
     *
     * @param list<CheckRow>        $checks   Filas del reporte actual.
     * @param array<string, string> $previous Último estado notificado.
     *
     * @return Changes Chequeos que empeoraron y que se resolvieron.
     */
    public static function changes(array $checks, array $previous): array
    {
        $worsened = [];
        $resolved = [];

        foreach ($checks as $check) {
            $before = CheckStatus::tryFrom($previous[$check['key']] ?? 'ok') ?? CheckStatus::Ok;
            $now = CheckStatus::from($check['status']);

            if ($now->severity() >= self::ALERT_SEVERITY && $now->severity() > $before->severity()) {
                $worsened[] = $check;
            } elseif ($now === CheckStatus::Ok && $before->severity() >= self::ALERT_SEVERITY) {
                $resolved[] = $check;
            }
        }

        usort($worsened, fn (array $a, array $b): int => CheckStatus::from($b['status'])->severity()
            <=> CheckStatus::from($a['status'])->severity());

        return ['worsened' => $worsened, 'resolved' => $resolved];
    }
}

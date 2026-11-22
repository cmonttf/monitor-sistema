<?php

namespace App\Services\Security;

use App\Enums\CheckStatus;
use Illuminate\Support\Facades\Storage;

/**
 * Último estado notificado de cada chequeo, por canal (correo y escritorio), para alertar sólo cuando algo
 * cambia y no repetir el mismo aviso en cada revisión programada. Cada canal guarda su propio estado: si el
 * correo falla se reintenta sin repetir la notificación de escritorio. Se guarda en el almacenamiento local.
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
     * Canal de alertas por correo.
     */
    public const string MAIL = 'mail';

    /**
     * Canal de alertas por notificación de escritorio.
     */
    public const string DESKTOP = 'desktop';

    /**
     * Ruta del archivo de estado de cada canal dentro del disco local.
     */
    private const array PATHS = [
        self::MAIL => 'security-monitor/alert-state.json',
        self::DESKTOP => 'security-monitor/alert-state-desktop.json',
    ];

    /**
     * Severidad mínima que se notifica (advertencia).
     */
    private const int ALERT_SEVERITY = 2;

    /**
     * Carga el último estado notificado por un canal. Si el escritorio aún no tiene estado propio, usa el
     * del correo, para no repetir avisos ya enviados.
     *
     * @param string $channel Canal: correo o escritorio.
     *
     * @return array<string, string> Clave del chequeo => estado.
     */
    public function load(string $channel = self::MAIL): array
    {
        $path = self::PATHS[$channel];

        if (! Storage::disk('local')->exists($path)) {
            return $channel === self::MAIL ? [] : $this->load(self::MAIL);
        }

        $data = json_decode((string) Storage::disk('local')->get($path), true);

        return is_array($data['checks'] ?? null) ? $data['checks'] : [];
    }

    /**
     * Guarda el estado actual de los chequeos como último estado notificado por un canal.
     *
     * @param list<CheckRow> $checks  Filas del reporte.
     * @param string         $channel Canal: correo o escritorio.
     *
     * @return void
     */
    public function save(array $checks, string $channel = self::MAIL): void
    {
        Storage::disk('local')->put(self::PATHS[$channel], (string) json_encode([
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

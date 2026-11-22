<?php

namespace App\Services\Security;

use Illuminate\Support\Facades\Storage;

/**
 * Línea base del monitor de integridad: la última huella aceptada de los elementos vigilados, guardada en
 * el almacenamiento local de la aplicación, y la comparación con la huella actual.
 *
 * @phpstan-import-type Entry from IntegritySnapshot
 * @phpstan-type        Baseline array{created_at: string, entries: array<string, Entry>}
 * @phpstan-type        Changes array{
 *     added: list<string>, removed: list<string>, changed: list<string>, sensitive: list<string>
 * }
 *
 * @package App\Services\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class IntegrityBaseline
{
    /**
     * Ruta del archivo de la línea base dentro del disco local.
     */
    private const string PATH = 'security-monitor/integrity-baseline.json';

    /**
     * Carga la línea base guardada.
     *
     * @return Baseline|null Línea base, o null si todavía no existe.
     */
    public function load(): ?array
    {
        if (! Storage::disk('local')->exists(self::PATH)) {
            return null;
        }

        $data = json_decode((string) Storage::disk('local')->get(self::PATH), true);

        return is_array($data) && isset($data['entries']) && is_array($data['entries']) ? $data : null;
    }

    /**
     * Guarda la huella indicada como nueva línea base.
     *
     * @param array<string, Entry> $entries Elementos vigilados.
     *
     * @return void
     */
    public function save(array $entries): void
    {
        Storage::disk('local')->put(self::PATH, (string) json_encode([
            'created_at' => now()->toIso8601String(),
            'entries' => $entries,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    /**
     * Compara la huella actual con la línea base. Un elemento es sensible si lo es en cualquiera de las dos.
     *
     * @param array<string, Entry> $current  Huella actual.
     * @param array<string, Entry> $baseline Elementos de la línea base.
     *
     * @return Changes Elementos nuevos, eliminados y modificados, y cuáles de ellos son sensibles.
     */
    public static function compare(array $current, array $baseline): array
    {
        $added = array_values(array_diff(array_keys($current), array_keys($baseline)));
        $removed = array_values(array_diff(array_keys($baseline), array_keys($current)));
        $changed = [];

        foreach (array_intersect_key($current, $baseline) as $name => $entry) {
            if ($entry['fingerprint'] !== $baseline[$name]['fingerprint']) {
                $changed[] = (string) $name;
            }
        }

        $sensitive = array_values(array_filter(
            [...$added, ...$removed, ...$changed],
            fn (string $name): bool => ($current[$name]['sensitive'] ?? false) || (
                $baseline[$name]['sensitive'] ?? false
            )
        ));

        return ['added' => $added, 'removed' => $removed, 'changed' => $changed, 'sensitive' => $sensitive];
    }
}

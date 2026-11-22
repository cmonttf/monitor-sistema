<?php

namespace App\Services\Security;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

/**
 * Registro de las solicitudes al panel que el middleware de acceso local rechazó, para mostrarlas en la
 * detección de ataques. Se guarda en la caché, con un máximo de entradas para que un atacante no pueda
 * agotar el almacenamiento.
 *
 * @phpstan-type BlockedRequest array{time: int, reason: string, host: string, ip: string, path: string}
 *
 * @package App\Services\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class BlockedRequestLog
{
    /**
     * Clave de caché del registro.
     */
    private const string CACHE_KEY = 'security-monitor.blocked-requests';

    /**
     * Cantidad máxima de solicitudes guardadas (se descartan las más antiguas).
     */
    private const int MAX_ENTRIES = 200;

    /**
     * Días que se conserva el registro en la caché.
     */
    private const int RETENTION_DAYS = 7;

    /**
     * Registra una solicitud rechazada.
     *
     * @param Request $request Solicitud rechazada.
     * @param string  $reason  Motivo: "host" (nombre de host no local) o "client" (cliente remoto).
     *
     * @return void
     */
    public function record(Request $request, string $reason): void
    {
        $entries = $this->all();
        $entries[] = [
            'time' => now()->getTimestamp(),
            'reason' => $reason,
            'host' => mb_substr((string) $request->getHost(), 0, 255),
            'ip' => (string) $request->server('REMOTE_ADDR'),
            'path' => mb_substr('/' . ltrim($request->path(), '/'), 0, 255),
        ];

        Cache::put(self::CACHE_KEY, array_slice($entries, -self::MAX_ENTRIES), now()->addDays(self::RETENTION_DAYS));
    }

    /**
     * Solicitudes rechazadas en las últimas horas indicadas.
     *
     * @param int $hours Horas hacia atrás.
     *
     * @return list<BlockedRequest> Solicitudes, de la más antigua a la más reciente.
     */
    public function recent(int $hours): array
    {
        $since = now()->subHours($hours)->getTimestamp();

        return array_values(array_filter($this->all(), fn (array $entry): bool => $entry['time'] >= $since));
    }

    /**
     * Todas las solicitudes guardadas.
     *
     * @return list<BlockedRequest> Solicitudes registradas.
     */
    private function all(): array
    {
        $entries = Cache::get(self::CACHE_KEY, []);

        return is_array($entries) ? array_values($entries) : [];
    }
}

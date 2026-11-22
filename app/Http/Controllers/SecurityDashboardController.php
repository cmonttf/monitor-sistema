<?php

namespace App\Http\Controllers;

use App\Services\Security\AttackTimeline;
use App\Services\Security\Checks\DiskSpaceCheck;
use App\Services\Security\Checks\MemoryCheck;
use App\Services\Security\Platform;
use App\Services\Security\ResourceSampler;
use App\Services\Security\SecurityMonitor;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;

/**
 * Panel de estado de seguridad del equipo.
 *
 * @package App\Http\Controllers
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class SecurityDashboardController extends Controller
{
    /**
     * Recibe el servicio que ejecuta los chequeos.
     *
     * @param SecurityMonitor $monitor Servicio de monitoreo.
     */
    public function __construct(private SecurityMonitor $monitor)
    {
    }

    /**
     * Muestra el panel con el último reporte y la frecuencia de actualización del navegador.
     *
     * @return View Vista del panel.
     */
    public function index(): View
    {
        return view('security.dashboard', [
            'report' => $this->monitor->report(),
            'refreshSeconds' => config('security-monitor.refresh_seconds'),
            'resourcesRefreshSeconds' => config('security-monitor.resources_refresh_seconds'),
            'resourcesHistoryMinutes' => config('security-monitor.resources_history_minutes'),
            'attacksRefreshSeconds' => config('security-monitor.attacks_refresh_seconds'),
            'alerts' => [
                'enabled' => (bool) config('security-monitor.alerts.enabled'),
                'minutes' => (int) config('security-monitor.alerts.minutes'),
                'email' => (string) config('security-monitor.alerts.email'),
                'mailConfigured' => ! in_array(config('mail.default'), ['log', 'array'], true),
                'desktop' => (bool) config('security-monitor.alerts.desktop'),
            ],
            'resourceThresholds' => [
                'memory' => ['warning' => MemoryCheck::WARNING_PERCENT, 'critical' => MemoryCheck::CRITICAL_PERCENT],
                'disk' => [
                    'warning_free_percent' => DiskSpaceCheck::WARNING_FREE_PERCENT,
                    'critical_free_percent' => DiskSpaceCheck::CRITICAL_FREE_PERCENT,
                    'critical_free_bytes' => DiskSpaceCheck::CRITICAL_FREE_BYTES,
                    'absolute_min_size' => DiskSpaceCheck::ABSOLUTE_THRESHOLD_MIN_SIZE,
                ],
            ],
        ]);
    }

    /**
     * Entrega el reporte en JSON; con ?refresh=1 vuelve a ejecutar los chequeos.
     *
     * @param Request $request Solicitud HTTP.
     *
     * @return JsonResponse Reporte del panel.
     */
    public function status(Request $request): JsonResponse
    {
        return response()->json($this->monitor->report(fresh: $request->boolean('refresh')));
    }

    /**
     * Entrega una muestra en vivo de memoria y discos, sin caché, junto con el estado de sus tarjetas.
     * El panel la consulta cada pocos segundos para el gráfico de RAM en tiempo real.
     *
     * @param ResourceSampler $resources Lector de memoria y discos.
     * @param Platform        $platform  Plataforma en la que corre el monitor.
     *
     * @return JsonResponse Muestra con fecha, memoria, discos y filas de los chequeos de recursos.
     */
    public function resources(ResourceSampler $resources, Platform $platform): JsonResponse
    {
        return response()->json([
            'sampled_at' => now()->toIso8601String(),
            'memory' => $resources->memory(),
            'disks' => $resources->disks(),
            'checks' => [
                $this->monitor->checkRow(new MemoryCheck($resources, $platform)),
                $this->monitor->checkRow(new DiskSpaceCheck($resources, $platform)),
            ],
        ]);
    }

    /**
     * Entrega la actividad de ataques de las últimas 24 horas para el gráfico en tiempo real: cada evento
     * con su hora y su tipo, y los tipos que no se pudieron leer.
     *
     * @param AttackTimeline $timeline Línea de tiempo de la actividad de ataques.
     *
     * @return JsonResponse Hora del servidor, eventos y tipos sin datos.
     */
    public function attacks(AttackTimeline $timeline): JsonResponse
    {
        return response()->json([
            'now' => now()->getTimestamp(),
            ...$timeline->events((int) config('security-monitor.attacks_history_hours')),
        ]);
    }
}

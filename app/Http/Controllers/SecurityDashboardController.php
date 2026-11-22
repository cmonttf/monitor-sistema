<?php

namespace App\Http\Controllers;

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
}

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
 */
class SecurityDashboardController extends Controller
{
    /**
     * @param SecurityMonitor  $monitor  Servicio que ejecuta los chequeos.
     */
    public function __construct(private SecurityMonitor $monitor)
    {
    }

    /**
     * Muestra el panel.
     *
     * @return View
     */
    public function index(): View
    {
        return view('security.dashboard', [
            'report' => $this->monitor->report(),
            'refreshSeconds' => config('security-monitor.refresh_seconds'),
        ]);
    }

    /**
     * Estado actual en JSON; con ?refresh=1 vuelve a ejecutar los chequeos.
     *
     * @return JsonResponse
     */
    public function status(Request $request): JsonResponse
    {
        return response()->json($this->monitor->report(fresh: $request->boolean('refresh')));
    }
}

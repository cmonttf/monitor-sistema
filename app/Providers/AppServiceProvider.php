<?php

namespace App\Providers;

use App\Services\Security\Platform;
use App\Services\Security\PlatformDetector;
use Illuminate\Support\ServiceProvider;

/**
 * Proveedor de servicios principal de la aplicación.
 *
 * @package App\Providers
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class AppServiceProvider extends ServiceProvider
{
    /**
     * Registra la plataforma detectada (sistema operativo y familia Linux) como instancia única,
     * para que todos los chequeos de una solicitud compartan la misma detección.
     *
     * @return void
     */
    public function register(): void
    {
        $this->app->singleton(Platform::class, fn (): Platform => $this->app->make(PlatformDetector::class)->detect());
    }

    /**
     * Inicializa servicios de la aplicación (sin inicialización propia por ahora).
     *
     * @return void
     */
    public function boot(): void
    {
        //
    }
}

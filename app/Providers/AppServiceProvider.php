<?php

namespace App\Providers;

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
     * Registra servicios de la aplicación (sin registros propios por ahora).
     *
     * @return void
     */
    public function register(): void
    {
        //
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

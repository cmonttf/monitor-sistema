<?php

use App\Services\Security\Checks;

return [

    /*
    |--------------------------------------------------------------------------
    | Servidor local
    |--------------------------------------------------------------------------
    |
    | El monitor escucha sólo en 127.0.0.1, para que no sea visible desde la red.
    |
    */

    'host' => '127.0.0.1',

    'port' => (int) env('SECURITY_MONITOR_PORT', 8787),

    /*
    |--------------------------------------------------------------------------
    | Frecuencias (segundos)
    |--------------------------------------------------------------------------
    |
    | "cache" es cada cuánto se vuelven a ejecutar los chequeos; "refresh" es
    | cada cuánto el navegador consulta el estado.
    |
    */

    'cache_seconds' => (int) env('SECURITY_MONITOR_CACHE_SECONDS', 300),

    'refresh_seconds' => (int) env('SECURITY_MONITOR_REFRESH_SECONDS', 60),

    /*
    |--------------------------------------------------------------------------
    | Monitor de recursos en tiempo real
    |--------------------------------------------------------------------------
    |
    | "resources_refresh_seconds" es cada cuánto el navegador toma una muestra
    | de memoria y discos; "resources_history_minutes" es cuánto historial de
    | RAM conserva el gráfico.
    |
    */

    'resources_refresh_seconds' => (int) env('SECURITY_MONITOR_RESOURCES_REFRESH_SECONDS', 2),

    'resources_history_minutes' => (int) env('SECURITY_MONITOR_RESOURCES_HISTORY_MINUTES', 15),

    /*
    |--------------------------------------------------------------------------
    | Chequeos habilitados (en orden de aparición)
    |--------------------------------------------------------------------------
    */

    'checks' => [
        Checks\AptUpdatesCheck::class,
        Checks\AptIndexFreshnessCheck::class,
        Checks\UnattendedUpgradesCheck::class,
        Checks\RebootRequiredCheck::class,
        Checks\SnapUpdatesCheck::class,
        Checks\FirmwareUpdatesCheck::class,
        Checks\FirewallCheck::class,
        Checks\AntivirusSignaturesCheck::class,
        Checks\AntivirusUpdaterCheck::class,
        Checks\AntivirusDaemonCheck::class,
        Checks\AppArmorCheck::class,
        Checks\SecureBootCheck::class,
        Checks\DiskEncryptionCheck::class,
        Checks\ScreenLockCheck::class,
        Checks\SshServerCheck::class,
        Checks\OpenPortsCheck::class,
        Checks\MemoryCheck::class,
        Checks\DiskSpaceCheck::class,
    ],

];

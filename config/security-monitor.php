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

    'resources_refresh_seconds' => (int) env(
        'SECURITY_MONITOR_RESOURCES_REFRESH_SECONDS',
        PHP_OS_FAMILY === 'Windows' ? 5 : 2
    ),

    'resources_history_minutes' => (int) env('SECURITY_MONITOR_RESOURCES_HISTORY_MINUTES', 15),

    /*
    |--------------------------------------------------------------------------
    | Gráfico de actividad de ataques en tiempo real
    |--------------------------------------------------------------------------
    |
    | "attacks_refresh_seconds" es cada cuánto el navegador lo actualiza;
    | "attacks_history_hours" es cuánto historial de eventos muestra.
    |
    */

    'attacks_refresh_seconds' => (int) env('SECURITY_MONITOR_ATTACKS_REFRESH_SECONDS', 15),

    'attacks_history_hours' => (int) env('SECURITY_MONITOR_ATTACKS_HISTORY_HOURS', 24),

    /*
    |--------------------------------------------------------------------------
    | Alertas programadas
    |--------------------------------------------------------------------------
    |
    | Cada "minutes" minutos se revisa el equipo y, si algún elemento empeoró,
    | se avisa por correo (a "email", con la configuración MAIL_* de .env) y con
    | una notificación de escritorio. Requiere el scheduler en ejecución
    | (php artisan schedule:work, que monitor:autostart deja corriendo).
    |
    */

    'alerts' => [
        'enabled' => (bool) env('SECURITY_MONITOR_ALERTS', true),
        'email' => env('SECURITY_MONITOR_ALERT_EMAIL'),
        'desktop' => (bool) env('SECURITY_MONITOR_ALERT_DESKTOP', true),
        'minutes' => max(1, min(59, (int) env('SECURITY_MONITOR_ALERT_MINUTES', 5))),
    ],

    /*
    |--------------------------------------------------------------------------
    | Chequeos habilitados (en orden de aparición)
    |--------------------------------------------------------------------------
    |
    | Cada chequeo declara en qué plataformas aplica (supports()); en cada equipo
    | sólo se ejecutan los que corresponden a su sistema y distribución.
    |
    */

    'checks' => [
        // Linux: actualizaciones según la familia de la distribución.
        Checks\AptUpdatesCheck::class,
        Checks\AptIndexFreshnessCheck::class,
        Checks\UnattendedUpgradesCheck::class,
        Checks\DnfUpdatesCheck::class,
        Checks\DnfAutomaticCheck::class,
        Checks\PacmanUpdatesCheck::class,
        Checks\RebootRequiredCheck::class,
        Checks\SnapUpdatesCheck::class,
        Checks\FirmwareUpdatesCheck::class,
        // Linux: protección, sistema y red.
        Checks\FirewallCheck::class,
        Checks\AntivirusSignaturesCheck::class,
        Checks\AntivirusUpdaterCheck::class,
        Checks\AntivirusDaemonCheck::class,
        Checks\MandatoryAccessControlCheck::class,
        Checks\SecureBootCheck::class,
        Checks\DiskEncryptionCheck::class,
        Checks\ScreenLockCheck::class,
        Checks\SshServerCheck::class,
        Checks\OpenPortsCheck::class,
        // Windows.
        Checks\WindowsUpdateCheck::class,
        Checks\WindowsRebootCheck::class,
        Checks\WindowsAntivirusCheck::class,
        Checks\WindowsFirewallCheck::class,
        Checks\WindowsDiskEncryptionCheck::class,
        Checks\WindowsSecureBootCheck::class,
        Checks\WindowsScreenLockCheck::class,
        Checks\WindowsUacCheck::class,
        Checks\WindowsRemoteDesktopCheck::class,
        Checks\WindowsOpenPortsCheck::class,
        // Detección de ataques.
        Checks\LoginFailuresCheck::class,
        Checks\WindowsLoginFailuresCheck::class,
        Checks\BlockedConnectionsCheck::class,
        Checks\WindowsBlockedConnectionsCheck::class,
        Checks\MalwareDetectionsCheck::class,
        Checks\WindowsMalwareDetectionsCheck::class,
        Checks\FileIntegrityCheck::class,
        Checks\PanelAccessCheck::class,
        // Linux y Windows.
        Checks\MemoryCheck::class,
        Checks\DiskSpaceCheck::class,
    ],


];

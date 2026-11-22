<?php

namespace App\Services\Security\Checks;

use App\Services\Security\BlockedRequestLog;
use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;
use App\Services\Security\Platform;

/**
 * Intentos de acceso al propio panel que el middleware de acceso local rechazó en las últimas 24 horas:
 * páginas web que intentan leerlo mediante DNS rebinding o conexiones desde otros equipos.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class PanelAccessCheck implements SecurityCheck
{
    /**
     * Horas hacia atrás en que se revisan los intentos.
     */
    public const int LOOKBACK_HOURS = 24;

    /**
     * Intentos a partir de los cuales el estado es crítico (un ataque insistente).
     */
    public const int CRITICAL_ATTEMPTS = 20;

    /**
     * Cantidad máxima de intentos listados en los detalles.
     */
    private const int MAX_LISTED = 10;

    /**
     * Recibe el registro de solicitudes rechazadas.
     *
     * @param BlockedRequestLog $blockedRequests Registro de solicitudes rechazadas por el middleware.
     */
    public function __construct(private BlockedRequestLog $blockedRequests)
    {
    }

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Intentos de acceso al panel';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Detección de ataques';
    }

    /**
     * Aplica a cualquier plataforma: el panel es el mismo.
     *
     * @param Platform $platform Plataforma en la que corre el monitor.
     *
     * @return bool Siempre true.
     */
    public function supports(Platform $platform): bool
    {
        return true;
    }

    /**
     * Correcto sin intentos rechazados; advertencia con intentos y crítico desde 20 en 24 horas.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $attempts = $this->blockedRequests->recent(self::LOOKBACK_HOURS);

        if ($attempts === []) {
            return CheckResult::ok('Nadie intentó acceder al panel desde fuera del equipo en las últimas 24 horas.');
        }

        $details = array_map(
            fn (array $attempt): string => date('d-m-Y H:i:s', $attempt['time']) . ' — '
                . ($attempt['reason'] === 'host' ? "dominio «{$attempt['host']}»" : "equipo remoto {$attempt['ip']}")
                . " pidió {$attempt['path']}",
            array_slice(array_reverse($attempts), 0, self::MAX_LISTED)
        );
        $fromWebPages = count(array_filter($attempts, fn (array $attempt): bool => $attempt['reason'] === 'host'));
        $message = count($attempts) . ' intentos de acceso al panel bloqueados en 24 horas'
            . (
                $fromWebPages > 0
                    ? ", {$fromWebPages} desde páginas web (posible DNS rebinding)."
                    : ' desde otros equipos.'
            );
        $steps = [
            FixStep::note('El panel los bloqueó: no se filtró información. Igual conviene averiguar el origen.'),
            FixStep::note(
                'Si vienen de un dominio, revisa qué páginas tenías abiertas a esa hora y las extensiones del '
                . 'navegador.'
            ),
            FixStep::note(
                'Si vienen de otro equipo, revisa que el monitor escuche sólo en 127.0.0.1 (php artisan '
                . 'monitor:autostart).'
            ),
        ];

        return count($attempts) >= self::CRITICAL_ATTEMPTS
            ? CheckResult::critical($message, $details, $steps)
            : CheckResult::warning($message, $details, $steps);
    }
}

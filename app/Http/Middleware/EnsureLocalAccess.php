<?php

namespace App\Http\Middleware;

use App\Services\Security\BlockedRequestLog;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Response;

/**
 * Restringe el panel al propio equipo. El panel expone las debilidades del equipo y permite forzar la
 * ejecución de comandos de verificación, por eso exige dos condiciones:
 *
 * - Que el encabezado Host sea un nombre local. Evita el DNS rebinding: una página web maliciosa cuyo
 *   dominio pasa a resolver a 127.0.0.1 enviaría su propio dominio como Host.
 * - Que el cliente sea una dirección de loopback, por si alguien levanta el servidor en otra interfaz y
 *   falsifica el encabezado Host.
 *
 * Se implementa aquí en vez de con trustHosts() porque el middleware TrustHosts de Laravel se desactiva
 * en el entorno local, que es justamente el de este monitor.
 *
 * @package App\Http\Middleware
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class EnsureLocalAccess
{
    /**
     * Nombres de host aceptados (sin puerto).
     */
    private const array LOCAL_HOSTS = ['127.0.0.1', 'localhost', '[::1]', '::1'];

    /**
     * Rangos de direcciones de loopback (IPv4 e IPv6) que se consideran el propio equipo.
     */
    private const array LOOPBACK_RANGES = ['127.0.0.0/8', '::1'];

    /**
     * Recibe el registro donde se anotan las solicitudes rechazadas.
     *
     * @param BlockedRequestLog $blockedRequests Registro de solicitudes rechazadas.
     */
    public function __construct(private BlockedRequestLog $blockedRequests)
    {
    }

    /**
     * Deja pasar la solicitud sólo si el host es local y el cliente es el propio equipo; si no, la registra
     * y responde 403.
     *
     * @param Request                      $request Solicitud entrante.
     * @param Closure(Request): (Response) $next    Siguiente capa de la aplicación.
     *
     * @return Response Respuesta de la aplicación.
     *
     * @throws \Symfony\Component\HttpKernel\Exception\HttpException Cuando el host o el cliente no son locales.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $host = strtolower($request->getHost());
        $clientIp = $request->server('REMOTE_ADDR');

        if (! in_array($host, self::LOCAL_HOSTS, true)) {
            $this->blockedRequests->record($request, 'host');
            abort(Response::HTTP_FORBIDDEN, 'El monitor sólo responde a 127.0.0.1 o localhost.');
        }

        if (! is_string($clientIp) || ! IpUtils::checkIp($clientIp, self::LOOPBACK_RANGES)) {
            $this->blockedRequests->record($request, 'client');
            abort(Response::HTTP_FORBIDDEN, 'El monitor sólo acepta conexiones desde este equipo.');
        }

        return $next($request);
    }
}

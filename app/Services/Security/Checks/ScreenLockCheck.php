<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Bloqueo automático de pantalla en GNOME.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class ScreenLockCheck extends SystemCheck
{
    /**
     * Segundos máximos de inactividad recomendados antes de bloquear la pantalla.
     */
    private const int MAX_IDLE_SECONDS = 900;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Bloqueo de pantalla';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Sistema';
    }

    /**
     * Lee de GNOME si el bloqueo está activo y tras cuánto tiempo de inactividad se aplica;
     * desactivado es crítico y más de 15 minutos es advertencia.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        if (! $this->system->hasCommand('gsettings')) {
            return CheckResult::unknown('gsettings no está disponible.');
        }

        $lock = $this->system->run(['gsettings', 'get', 'org.gnome.desktop.screensaver', 'lock-enabled']);
        $idle = $this->system->run(['gsettings', 'get', 'org.gnome.desktop.session', 'idle-delay']);

        if ($lock->failed() || $idle->failed()) {
            return CheckResult::unknown('No se pudo leer la configuración de GNOME.');
        }

        $idleSeconds = (int) preg_replace('/\D/', '', $idle->output());

        if (trim($lock->output()) !== 'true') {
            return CheckResult::critical('El bloqueo automático de pantalla está desactivado.');
        }

        if ($idleSeconds === 0) {
            return CheckResult::warning('La pantalla nunca se apaga por inactividad, por lo que no se bloquea.');
        }

        $minutes = intdiv($idleSeconds, 60);

        if ($idleSeconds > self::MAX_IDLE_SECONDS) {
            return CheckResult::warning("La pantalla se bloquea tras {$minutes} minutos; se recomienda 15 o menos.");
        }

        return CheckResult::ok("La pantalla se bloquea tras {$minutes} minutos de inactividad.");
    }
}

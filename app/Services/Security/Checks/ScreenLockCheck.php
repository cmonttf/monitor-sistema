<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;

/**
 * Bloqueo automático de pantalla en GNOME.
 *
 * @package App\Services\Security\Checks
 */
class ScreenLockCheck extends SystemCheck
{
    private const int MAX_IDLE_SECONDS = 900;

    public function name(): string
    {
        return 'Bloqueo de pantalla';
    }

    public function category(): string
    {
        return 'Sistema';
    }

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

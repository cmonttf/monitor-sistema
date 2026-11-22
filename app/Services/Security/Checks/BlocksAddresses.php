<?php

namespace App\Services\Security\Checks;

use App\Services\Security\FixStep;

/**
 * Pasos para bloquear una dirección IP con el cortafuegos de Linux disponible (UFW o firewalld).
 * Requiere la propiedad $system (SystemInspector) de SystemCheck.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
trait BlocksAddresses
{
    /**
     * Arma el paso que bloquea todo el tráfico entrante de una IP.
     *
     * @param string $ip Dirección a bloquear.
     *
     * @return FixStep Paso con el comando para el cortafuegos del equipo.
     */
    protected function blockAddressStep(string $ip): FixStep
    {
        if (! $this->system->hasCommand('ufw') && $this->system->hasCommand('firewall-cmd')) {
            $family = str_contains($ip, ':') ? 'ipv6' : 'ipv4';

            return FixStep::command(
                "Bloquea todo el tráfico entrante desde {$ip}.",
                "sudo firewall-cmd --permanent --add-rich-rule='rule family=\"{$family}\" "
                    . "source address=\"{$ip}\" drop'"
                    . ' && sudo firewall-cmd --reload'
            );
        }

        return FixStep::command("Bloquea todo el tráfico entrante desde {$ip}.", "sudo ufw insert 1 deny from {$ip}");
    }
}

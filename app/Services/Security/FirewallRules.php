<?php

namespace App\Services\Security;

/**
 * Reglas de un cortafuegos de Linux capaces de decidir si un puerto es accesible desde la red.
 *
 * @phpstan-type Verdict array{allowed: bool, reason: string, source: 'inactive'|'rule'|'default', rule: string|null}
 *
 * @package App\Services\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
interface FirewallRules
{
    /**
     * Decide si un puerto es accesible desde la red en la familia indicada.
     *
     * @param int    $port     Número de puerto.
     * @param string $protocol Protocolo: tcp o udp.
     * @param bool   $v6       true para IPv6, false para IPv4.
     *
     * @return Verdict Si está permitido, el motivo en español, qué lo decidió y la regla que coincidió.
     */
    public function evaluate(int $port, string $protocol, bool $v6): array;

    /**
     * Pasos para cerrar los puertos accesibles, según qué los dejó abiertos.
     *
     * @param list<Verdict> $openVerdicts Veredictos de los puertos accesibles.
     *
     * @return list<FixStep> Pasos específicos de este cortafuegos.
     */
    public function closeSteps(array $openVerdicts): array;
}

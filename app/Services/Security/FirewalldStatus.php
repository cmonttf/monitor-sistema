<?php

namespace App\Services\Security;

/**
 * Estado de firewalld para la zona por defecto: puertos y servicios permitidos. Lo que no está permitido
 * en la zona se bloquea (comportamiento de las zonas habituales, como «public»).
 *
 * @phpstan-import-type Verdict from FirewallRules
 *
 * @package App\Services\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
final readonly class FirewalldStatus implements FirewallRules
{
    /**
     * Crea el estado de firewalld.
     *
     * @param bool                        $isRunning Si firewalld está en ejecución.
     * @param string                      $zone      Zona por defecto.
     * @param list<string>                $ports     Puertos permitidos, por ejemplo "8080/tcp" o "9000-9100/udp".
     * @param array<string, list<string>> $services  Servicio permitido => sus puertos.
     */
    public function __construct(
        public bool $isRunning,
        public string $zone = 'public',
        public array $ports = [],
        public array $services = [],
    ) {
    }

    /**
     * Extrae los puertos de la salida de `firewall-cmd --info-service=<servicio>` (línea "ports: ...").
     *
     * @param string $info Salida del comando.
     *
     * @return list<string> Puertos del servicio.
     */
    public static function parseServicePorts(string $info): array
    {
        if (preg_match('/^\s*ports:\s*(.*)$/m', $info, $match) !== 1) {
            return [];
        }

        return array_values(array_filter(explode(' ', trim($match[1]))));
    }

    /**
     * Decide si un puerto es accesible: permitido si está en los puertos de la zona o en los de un servicio
     * permitido; si no, bloqueado por la zona. Las reglas de firewalld aplican igual a IPv4 e IPv6.
     *
     * @param int    $port     Número de puerto.
     * @param string $protocol Protocolo: tcp o udp.
     * @param bool   $v6       true para IPv6, false para IPv4 (no cambia el resultado).
     *
     * @return Verdict Si está permitido, el motivo en español, qué lo decidió y la regla que coincidió.
     */
    public function evaluate(int $port, string $protocol, bool $v6): array
    {
        if (! $this->isRunning) {
            return ['allowed' => true, 'reason' => 'cortafuegos detenido', 'source' => 'inactive', 'rule' => null];
        }

        foreach ($this->ports as $spec) {
            if ($this->specMatches($spec, $port, $protocol)) {
                return [
                    'allowed' => true,
                    'reason' => "permitido por el puerto «{$spec}» de la zona «{$this->zone}»",
                    'source' => 'rule',
                    'rule' => "port:{$spec}",
                ];
            }
        }

        foreach ($this->services as $service => $specs) {
            foreach ($specs as $spec) {
                if ($this->specMatches($spec, $port, $protocol)) {
                    return [
                        'allowed' => true,
                        'reason' => "permitido por el servicio «{$service}» de la zona «{$this->zone}»",
                        'source' => 'rule',
                        'rule' => "service:{$service}",
                    ];
                }
            }
        }

        return [
            'allowed' => false,
            'reason' => "bloqueado por la zona «{$this->zone}»",
            'source' => 'default',
            'rule' => null,
        ];
    }

    /**
     * Pasos para cerrar los puertos: iniciar firewalld si está detenido y quitar de la zona los servicios
     * o puertos que los abren.
     *
     * @param list<Verdict> $openVerdicts Veredictos de los puertos accesibles.
     *
     * @return list<FixStep> Pasos de solución.
     */
    public function closeSteps(array $openVerdicts): array
    {
        $steps = [FixStep::command('Identifica qué programa usa cada puerto.', 'sudo ss -tlnp')];

        if (in_array('inactive', array_column($openVerdicts, 'source'), true)) {
            $steps[] = FixStep::command(
                'Inicia firewalld y haz que arranque con el equipo.',
                'sudo systemctl enable --now firewalld'
            );
        }

        foreach (array_unique(array_filter(array_column($openVerdicts, 'rule'))) as $rule) {
            [$kind, $name] = explode(':', $rule, 2);
            $option = $kind === 'service' ? '--remove-service' : '--remove-port';
            $steps[] = FixStep::command(
                'Si no necesitas ' . (
                    $kind === 'service' ? "el servicio «{$name}»" : "el puerto «{$name}»"
                ) . ', quítalo de la zona.',
                "sudo firewall-cmd --permanent --zone={$this->zone} {$option}={$name} && sudo firewall-cmd --reload"
            );
        }

        return $steps;
    }

    /**
     * Compara un puerto contra una especificación de firewalld como "22/tcp" o "9000-9100/udp".
     *
     * @param string $spec     Especificación de puertos.
     * @param int    $port     Número de puerto.
     * @param string $protocol Protocolo: tcp o udp.
     *
     * @return bool true si el puerto y el protocolo están cubiertos.
     */
    private function specMatches(string $spec, int $port, string $protocol): bool
    {
        if (preg_match('/^(\d+)(?:-(\d+))?\/(tcp|udp)$/', $spec, $parts) !== 1 || $parts[3] !== $protocol) {
            return false;
        }

        $end = $parts[2] !== '' ? (int) $parts[2] : (int) $parts[1];

        return $port >= (int) $parts[1] && $port <= $end;
    }
}

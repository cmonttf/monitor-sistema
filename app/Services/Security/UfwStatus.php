<?php

namespace App\Services\Security;

/**
 * Interpreta la salida de `ufw status verbose` y decide si un puerto
 * es alcanzable desde la red (primera regla que coincide, como UFW).
 *
 * @phpstan-type Rule array{to: string, action: string, from: string, v6: bool}
 * @phpstan-type Verdict array{allowed: bool, reason: string}
 *
 * @package App\Services\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
final readonly class UfwStatus
{
    /**
     * Expresión de una especificación de puertos de UFW: "80", "80,443/tcp" o "8000:8100/udp".
     */
    private const string PORT_PATTERN = '/^([\d,:]+)(?:\/(tcp|udp))?$/';

    /**
     * Crea el estado del cortafuegos.
     *
     * @param bool                  $isActive        Si el cortafuegos está activo.
     * @param string                $defaultIncoming Política por defecto de entrada (deny, reject, allow).
     * @param list<Rule>            $rules           Reglas en el orden en que UFW las evalúa.
     * @param array<string, string> $appPorts        Perfil de aplicación => especificación de puertos.
     */
    public function __construct(
        public bool $isActive,
        public string $defaultIncoming,
        public array $rules,
        public array $appPorts = [],
    ) {
    }

    /**
     * Construye el estado a partir de la salida de `ufw status verbose` en inglés.
     *
     * @param string                $output   Salida del comando.
     * @param array<string, string> $appPorts Perfil de aplicación => especificación de puertos.
     *
     * @return self|null Estado interpretado, o null si la salida no se reconoce.
     */
    public static function parse(string $output, array $appPorts = []): ?self
    {
        if (preg_match('/^Status:\s*(\w+)/m', $output, $status) !== 1) {
            return null;
        }

        preg_match('/^Default:\s*(\w+)\s*\(incoming\)/m', $output, $default);

        $rules = [];
        $inRules = false;

        foreach (explode("\n", $output) as $line) {
            if (str_starts_with(trim($line), '--')) {
                $inRules = true;

                continue;
            }

            $columns = preg_split('/\s{2,}/', trim($line)) ?: [];

            if (! $inRules || count($columns) < 3) {
                continue;
            }

            [$to, $action, $from] = $columns;

            $rules[] = [
                'to' => trim(str_replace('(v6)', '', $to)),
                'action' => strtoupper($action),
                'from' => trim(str_replace('(v6)', '', $from)),
                'v6' => str_contains($to, '(v6)'),
            ];
        }

        return new self($status[1] === 'active', strtolower($default[1] ?? 'deny'), $rules, $appPorts);
    }

    /**
     * Decide si un puerto es accesible desde la red en la familia indicada, aplicando la primera
     * regla de entrada que coincide o, si ninguna coincide, la política por defecto.
     *
     * @param int    $port     Número de puerto.
     * @param string $protocol Protocolo: tcp o udp.
     * @param bool   $v6       true para IPv6, false para IPv4.
     *
     * @return Verdict Si está permitido y el motivo en español.
     */
    public function evaluate(int $port, string $protocol, bool $v6): array
    {
        if (! $this->isActive) {
            return ['allowed' => true, 'reason' => 'cortafuegos desactivado'];
        }

        foreach ($this->rules as $rule) {
            if (
                $rule['v6'] !== $v6
                || ! $this->isIncoming($rule['action'])
                || ! $this->matches($rule['to'], $port, $protocol)
            ) {
                continue;
            }

            $isAllowed = str_starts_with($rule['action'], 'ALLOW') || str_starts_with($rule['action'], 'LIMIT');
            $verb = $isAllowed ? 'permitido' : 'bloqueado';

            return ['allowed' => $isAllowed, 'reason' => "{$verb} por la regla «{$rule['to']}» desde {$rule['from']}"];
        }

        $isAllowed = $this->defaultIncoming === 'allow';

        return [
            'allowed' => $isAllowed,
            'reason' => ($isAllowed ? 'permitido' : 'bloqueado')
                . " por la política por defecto ({$this->defaultIncoming})",
        ];
    }

    /**
     * Indica si la acción de una regla aplica al tráfico entrante (no OUT ni FWD).
     *
     * @param string $action Acción de la regla, por ejemplo "ALLOW IN".
     *
     * @return bool true si la regla aplica a conexiones entrantes.
     */
    private function isIncoming(string $action): bool
    {
        return ! str_contains($action, 'OUT') && ! str_contains($action, 'FWD');
    }

    /**
     * Indica si el destino de una regla cubre el puerto: "Anywhere", una especificación de puertos
     * (opcionalmente precedida de una IP) o un perfil de aplicación.
     *
     * @param string $to       Columna "To" de la regla.
     * @param int    $port     Número de puerto.
     * @param string $protocol Protocolo: tcp o udp.
     *
     * @return bool true si la regla aplica al puerto.
     */
    private function matches(string $to, int $port, string $protocol): bool
    {
        $to = trim(preg_replace('/\s+on\s+\S+$/', '', $to) ?? $to);

        if ($to === 'Anywhere') {
            return true;
        }

        $lastToken = substr($to, (int) strrpos(" {$to}", ' '));

        if (preg_match(self::PORT_PATTERN, $lastToken) === 1) {
            return $this->specMatches($lastToken, $port, $protocol);
        }

        $profile = $this->appPorts[$to] ?? null;

        if ($profile === null) {
            return false;
        }

        foreach (explode('|', $profile) as $spec) {
            if ($this->specMatches(trim($spec), $port, $protocol)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Compara un puerto contra una especificación como "80", "80,443/tcp" o "8000:8100/udp".
     *
     * @param string $spec     Especificación de puertos.
     * @param int    $port     Número de puerto.
     * @param string $protocol Protocolo: tcp o udp.
     *
     * @return bool true si el puerto y el protocolo están cubiertos.
     */
    private function specMatches(string $spec, int $port, string $protocol): bool
    {
        if (preg_match(self::PORT_PATTERN, $spec, $parts) !== 1) {
            return false;
        }

        if (isset($parts[2]) && $parts[2] !== $protocol) {
            return false;
        }

        foreach (explode(',', $parts[1]) as $item) {
            [$start, $end] = array_pad(explode(':', $item), 2, $item);

            if ($port >= (int) $start && $port <= (int) $end) {
                return true;
            }
        }

        return false;
    }
}

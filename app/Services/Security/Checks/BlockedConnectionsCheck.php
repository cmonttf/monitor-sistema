<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Conexiones entrantes que el cortafuegos de Linux bloqueó en las últimas 24 horas, leídas de los
 * mensajes del kernel: detecta escaneos de puertos y orígenes insistentes. Se ignora el tráfico de
 * multidifusión y difusión, que es ruido normal de la red local.
 *
 * @phpstan-type Sources array<string, array{count: int, ports: list<int>}>
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class BlockedConnectionsCheck extends SystemCheck
{
    use BlocksAddresses;

    /**
     * Puertos distintos probados por un mismo origen a partir de los cuales se considera un escaneo.
     */
    public const int SCAN_DISTINCT_PORTS = 10;

    /**
     * Conexiones bloqueadas desde un mismo origen a partir de las cuales se advierte.
     */
    public const int INSISTENT_SOURCE_ATTEMPTS = 20;

    /**
     * Cantidad máxima de orígenes listados en los detalles.
     */
    private const int MAX_LISTED = 10;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Escaneos y conexiones bloqueadas';
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
     * Crítico si un origen probó 10 o más puertos distintos (escaneo); advertencia si un origen insistió 20
     * o más veces; sin datos si el cortafuegos no registra los bloqueos.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $loggingProblem = $this->loggingProblem();

        if ($loggingProblem !== null) {
            return $loggingProblem;
        }

        $result = $this->system->run(['journalctl', '-k', '--since=-24h', '--no-pager', '-o', 'cat'], 30);

        if ($result->failed()) {
            return CheckResult::unknown('No se pudieron leer los mensajes del cortafuegos.', [], [
                FixStep::command(
                    'Agrega tu usuario al grupo adm, que permite leer los registros '
                        . '(luego cierra sesión y vuelve a entrar).',
                    'sudo usermod -aG adm $USER'
                ),
            ]);
        }

        $sources = self::parse($result->output());
        uasort($sources, fn (array $a, array $b): int => $b['count'] <=> $a['count']);
        $details = array_map(
            fn (string $ip, array $source): string => "{$ip}: {$source['count']} bloqueadas, "
                . count($source['ports']) . ' puertos (' . implode(', ', array_slice($source['ports'], 0, 8)) . ')',
            array_keys(array_slice($sources, 0, self::MAX_LISTED, true)),
            array_slice($sources, 0, self::MAX_LISTED, true)
        );

        foreach ($sources as $ip => $source) {
            if (count($source['ports']) >= self::SCAN_DISTINCT_PORTS) {
                return CheckResult::critical(
                    "Escaneo de puertos desde {$ip}: probó " . count($source['ports']) . ' puertos distintos.',
                    $details,
                    [
                        $this->blockAddressStep((string) $ip),
                        FixStep::note(
                            'Si la IP es de tu red local, identifica qué equipo es: puede estar comprometido.'
                        ),
                    ]
                );
            }
        }

        foreach ($sources as $ip => $source) {
            if ($source['count'] >= self::INSISTENT_SOURCE_ATTEMPTS) {
                return CheckResult::warning(
                    "{$ip} intentó conectarse {$source['count']} veces y fue bloqueado.",
                    $details,
                    [$this->blockAddressStep((string) $ip)]
                );
            }
        }

        $total = array_sum(array_column($sources, 'count'));

        return CheckResult::ok(
            $total === 0
                ? 'El cortafuegos no bloqueó conexiones entrantes en las últimas 24 horas.'
                : "El cortafuegos bloqueó {$total} conexiones en 24 horas, sin patrones de ataque.",
            $details
        );
    }

    /**
     * Agrupa por origen los bloqueos registrados por UFW o firewalld, ignorando multidifusión y difusión.
     *
     * @param string $log Mensajes del kernel (formato «cat»).
     *
     * @return Sources Origen => cantidad de bloqueos y puertos de destino.
     */
    public static function parse(string $log): array
    {
        $sources = [];

        foreach (explode("\n", $log) as $line) {
            $blocked = self::classify($line);

            if ($blocked === null) {
                continue;
            }

            $sources[$blocked['source']]['count'] = ($sources[$blocked['source']]['count'] ?? 0) + 1;
            $sources[$blocked['source']]['ports'][$blocked['port']] = $blocked['port'];
        }

        foreach ($sources as $ip => $data) {
            ksort($data['ports']);
            $sources[$ip]['ports'] = array_values($data['ports']);
        }

        return $sources;
    }

    /**
     * Clasifica un mensaje del kernel: una conexión entrante bloqueada hacia un puerto, sin contar la
     * multidifusión, la difusión ni los paquetes sin puerto.
     *
     * @param string $line Mensaje del kernel.
     *
     * @return array{source: string, port: int}|null Origen y puerto, o null si no es un bloqueo relevante.
     */
    public static function classify(string $line): ?array
    {
        if (
            preg_match('/BLOCK|REJECT|DROP/i', $line) !== 1
            || preg_match('/\bIN=(\S+)/', $line) !== 1
            || preg_match('/\bSRC=(\S+)/', $line, $source) !== 1
            || preg_match('/\bDST=(\S+)/', $line, $destination) !== 1
            || preg_match('/\bDPT=(\d+)/', $line, $port) !== 1
            || self::isBroadcast($destination[1])
        ) {
            return null;
        }

        return ['source' => $source[1], 'port' => (int) $port[1]];
    }

    /**
     * Indica si un destino es de multidifusión o difusión (tráfico normal de la red local).
     *
     * @param string $address Dirección de destino.
     *
     * @return bool true si es multidifusión o difusión.
     */
    private static function isBroadcast(string $address): bool
    {
        if (str_contains($address, ':')) {
            return str_starts_with(strtolower($address), 'ff');
        }

        $firstOctet = (int) explode('.', $address)[0];

        return ($firstOctet >= 224 && $firstOctet <= 239) || str_ends_with($address, '.255');
    }

    /**
     * Revisa que el cortafuegos activo registre las conexiones bloqueadas.
     *
     * @return CheckResult|null Resultado sin datos si no hay registro de bloqueos; null si está bien.
     */
    private function loggingProblem(): ?CheckResult
    {
        if ($this->system->hasCommand('ufw')) {
            $config = $this->system->readFile('/etc/ufw/ufw.conf') ?? '';

            if (preg_match('/^\s*LOGLEVEL\s*=\s*off/mi', $config) === 1) {
                return CheckResult::unknown('UFW no registra las conexiones bloqueadas.', [], [
                    FixStep::command('Activa el registro de bloqueos con nivel bajo.', 'sudo ufw logging low'),
                ]);
            }

            return null;
        }

        if ($this->system->hasCommand('firewall-cmd')) {
            if (trim($this->system->run(['firewall-cmd', '--get-log-denied'])->output()) === 'off') {
                return CheckResult::unknown('firewalld no registra las conexiones bloqueadas.', [], [
                    FixStep::command('Activa el registro de bloqueos.', 'sudo firewall-cmd --set-log-denied=unicast'),
                ]);
            }

            return null;
        }

        return CheckResult::unknown('No hay un cortafuegos que registre conexiones bloqueadas.', [], [
            FixStep::note('Activa un cortafuegos (ver la tarjeta «Cortafuegos»).'),
        ]);
    }
}

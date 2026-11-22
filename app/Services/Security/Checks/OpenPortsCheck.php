<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\UfwStatus;

/**
 * Puertos TCP escuchando fuera de la interfaz local, cruzados con las reglas de UFW
 * para avisar sólo de los que realmente son alcanzables desde la red.
 *
 * @package App\Services\Security\Checks
 */
class OpenPortsCheck extends SystemCheck
{
    public const string SUDOERS_FILE = '/etc/sudoers.d/monitor-seguridad';

    public const array UFW_COMMAND = ['/usr/sbin/ufw', 'status', 'verbose'];

    public function name(): string
    {
        return 'Puertos abiertos a la red';
    }

    public function category(): string
    {
        return 'Red';
    }

    public function run(): CheckResult
    {
        $result = $this->system->run(['ss', '-tlnH']);

        if ($result->failed()) {
            return CheckResult::unknown('No se pudo listar los puertos.');
        }

        $listeners = $this->exposedListeners($result->output());

        if ($listeners === []) {
            return CheckResult::ok('Ningún servicio escucha fuera del equipo.');
        }

        $firewall = $this->firewallStatus();

        if ($firewall === null) {
            return CheckResult::warning(
                count($listeners) . ' puertos TCP escuchan en la red (no se pudieron leer las reglas de UFW).',
                [...array_map(fn (int $port): string => "{$port}/tcp", array_keys($listeners)), ...$this->sudoersHint()],
            );
        }

        $open = [];
        $blocked = [];

        foreach ($listeners as $port => $families) {
            $verdicts = array_map(fn (bool $v6): array => $firewall->evaluate($port, 'tcp', $v6), $families);
            $allowed = array_values(array_filter($verdicts, fn (array $verdict): bool => $verdict['allowed']));

            if ($allowed !== []) {
                $open[] = "⚠ {$port}/tcp — {$allowed[0]['reason']}";
            } else {
                $blocked[] = "✓ {$port}/tcp — {$verdicts[0]['reason']}";
            }
        }

        if ($open !== []) {
            return CheckResult::warning(count($open) . ' puertos son accesibles desde la red a través del cortafuegos.', [...$open, ...$blocked]);
        }

        return CheckResult::ok(count($blocked) . ' servicios escuchan en la red, pero el cortafuegos los bloquea.', $blocked);
    }

    /**
     * Puertos expuestos y familias de red en que escuchan (false = IPv4, true = IPv6).
     *
     * @return array<int, list<bool>>
     */
    private function exposedListeners(string $output): array
    {
        $listeners = [];

        foreach (array_filter(explode("\n", trim($output))) as $line) {
            $address = preg_split('/\s+/', trim($line))[3] ?? '';
            $separator = strrpos($address, ':');

            if ($separator === false) {
                continue;
            }

            $host = explode('%', trim(substr($address, 0, $separator), '[]'))[0];
            $port = (int) substr($address, $separator + 1);

            if (str_starts_with($host, '127.') || $host === '::1') {
                continue;
            }

            $families = match (true) {
                $host === '*' => [false, true],
                str_contains($host, ':') => [true],
                default => [false],
            };

            $listeners[$port] = array_values(array_unique([...($listeners[$port] ?? []), ...$families]));
        }

        ksort($listeners);

        return $listeners;
    }

    /**
     * @return UfwStatus|null
     */
    private function firewallStatus(): ?UfwStatus
    {
        $result = $this->system->run(['sudo', '-n', ...self::UFW_COMMAND]);

        return $result->successful() ? UfwStatus::parse($result->output(), $this->appProfiles()) : null;
    }

    /**
     * Perfiles de aplicación de UFW ("Apache Full" => "80,443/tcp").
     *
     * @return array<string, string>
     */
    private function appProfiles(): array
    {
        $profiles = [];
        $files = [...$this->system->glob('/etc/ufw/applications.d/*'), ...$this->system->glob('/etc/ufw/applications.d/*/*')];

        foreach ($files as $file) {
            $sections = parse_ini_string($this->system->readFile($file) ?? '', true, INI_SCANNER_RAW) ?: [];

            foreach ($sections as $name => $values) {
                if (is_array($values) && isset($values['ports'])) {
                    $profiles[(string) $name] = (string) $values['ports'];
                }
            }
        }

        return $profiles;
    }

    /**
     * @return list<string>
     */
    private function sudoersHint(): array
    {
        $user = getenv('USER') ?: get_current_user();
        $command = implode(' ', self::UFW_COMMAND);

        return [
            'Para cruzar con UFW, permite al monitor leer el estado del cortafuegos (una sola vez):',
            "echo '{$user} ALL=(root) NOPASSWD: {$command}' | sudo tee " . self::SUDOERS_FILE . ' && sudo chmod 440 ' . self::SUDOERS_FILE,
        ];
    }
}

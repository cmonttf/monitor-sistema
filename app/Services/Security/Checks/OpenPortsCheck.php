<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FirewalldStatus;
use App\Services\Security\FirewallRules;
use App\Services\Security\FixStep;
use App\Services\Security\UfwStatus;

/**
 * Puertos TCP escuchando fuera de la interfaz local, cruzados con las reglas de UFW
 * para avisar sólo de los que realmente son alcanzables desde la red.
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class OpenPortsCheck extends SystemCheck
{
    /**
     * Archivo de sudoers que permite al monitor leer el estado de UFW sin contraseña.
     */
    public const string SUDOERS_FILE = '/etc/sudoers.d/monitor-seguridad';

    /**
     * Comando de sólo lectura que entrega el estado y las reglas de UFW.
     */
    public const array UFW_COMMAND = ['/usr/sbin/ufw', 'status', 'verbose'];

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Puertos abiertos a la red';
    }

    /**
     * Categoría del panel en la que se agrupa el chequeo.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Red';
    }

    /**
     * Lista los puertos TCP expuestos con `ss` y los evalúa contra las reglas de UFW: advierte si alguno
     * es accesible desde la red, o si no se pudieron leer las reglas.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
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

        $usesFirewalld = $this->system->hasCommand('firewall-cmd') && ! $this->system->hasCommand('ufw');
        $firewall = $usesFirewalld ? $this->firewalldStatus() : $this->ufwStatus();

        if ($firewall === null) {
            return CheckResult::warning(
                count($listeners) . ' puertos TCP escuchan en la red (no se pudieron leer las reglas de '
                    . ($usesFirewalld ? 'firewalld' : 'UFW') . ').',
                array_map(fn (int $port): string => "{$port}/tcp", array_keys($listeners)),
                $usesFirewalld ? $this->firewalldUnreadableSteps() : $this->sudoersSteps()
            );
        }

        $open = [];
        $blocked = [];
        $openVerdicts = [];

        foreach ($listeners as $port => $families) {
            $verdicts = array_map(fn (bool $v6): array => $firewall->evaluate($port, 'tcp', $v6), $families);
            $allowed = array_values(array_filter($verdicts, fn (array $verdict): bool => $verdict['allowed']));

            if ($allowed !== []) {
                $open[] = "⚠ {$port}/tcp — {$allowed[0]['reason']}";
                $openVerdicts[] = $allowed[0];
            } else {
                $blocked[] = "✓ {$port}/tcp — {$verdicts[0]['reason']}";
            }
        }

        if ($open !== []) {
            return CheckResult::warning(
                count($open) . ' puertos son accesibles desde la red a través del cortafuegos.',
                [...$open, ...$blocked],
                $firewall->closeSteps($openVerdicts)
            );
        }

        return CheckResult::ok(
            count($blocked) . ' servicios escuchan en la red, pero el cortafuegos los bloquea.',
            $blocked
        );
    }

    /**
     * Extrae de la salida de `ss` los puertos que escuchan fuera de la interfaz local.
     *
     * @param string $output Salida de `ss -tlnH`.
     *
     * @return array<int, list<bool>> Puerto => familias en que escucha (false = IPv4, true = IPv6).
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
     * Lee el estado de UFW con `sudo -n`, sin pedir contraseña.
     *
     * @return UfwStatus|null Estado interpretado, o null si falta el permiso o la salida no se reconoce.
     */
    private function ufwStatus(): ?UfwStatus
    {
        $result = $this->system->run(['sudo', '-n', ...self::UFW_COMMAND]);

        return $result->successful() ? UfwStatus::parse($result->output(), $this->appProfiles()) : null;
    }

    /**
     * Lee la zona por defecto de firewalld con sus puertos y servicios permitidos. Las consultas de
     * firewall-cmd no requieren privilegios en una sesión de escritorio.
     *
     * @return FirewallRules|null Estado interpretado, o null si alguna consulta falló.
     */
    private function firewalldStatus(): ?FirewallRules
    {
        if (trim($this->system->run(['firewall-cmd', '--state'])->output()) !== 'running') {
            return new FirewalldStatus(false);
        }

        $zoneResult = $this->system->run(['firewall-cmd', '--get-default-zone']);
        $zone = trim($zoneResult->output());
        $portsResult = $this->system->run(['firewall-cmd', "--zone={$zone}", '--list-ports']);
        $servicesResult = $this->system->run(['firewall-cmd', "--zone={$zone}", '--list-services']);

        if ($zoneResult->failed() || $portsResult->failed() || $servicesResult->failed()) {
            return null;
        }

        $services = [];

        foreach (array_filter(explode(' ', trim($servicesResult->output()))) as $service) {
            $info = $this->system->run(['firewall-cmd', "--info-service={$service}"])->output();
            $services[$service] = FirewalldStatus::parseServicePorts($info);
        }

        return new FirewalldStatus(
            true,
            $zone,
            array_values(array_filter(explode(' ', trim($portsResult->output())))),
            $services
        );
    }

    /**
     * Pasos cuando no se pudieron consultar las reglas de firewalld.
     *
     * @return list<FixStep> Pasos para revisar las reglas a mano.
     */
    private function firewalldUnreadableSteps(): array
    {
        return [
            FixStep::command('Revisa las reglas de la zona activa.', 'sudo firewall-cmd --list-all'),
            FixStep::command('Identifica qué programa usa cada puerto.', 'sudo ss -tlnp'),
        ];
    }

    /**
     * Lee los perfiles de aplicación de UFW desde /etc/ufw/applications.d.
     *
     * @return array<string, string> Perfil => especificación de puertos ("Apache Full" => "80,443/tcp").
     */
    private function appProfiles(): array
    {
        $profiles = [];
        $files = [
            ...$this->system->glob('/etc/ufw/applications.d/*'),
            ...$this->system->glob('/etc/ufw/applications.d/*/*'),
        ];

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
     * Arma los pasos para crear la regla de sudoers que permite leer UFW, con el usuario actual.
     *
     * @return list<FixStep> Pasos para habilitar la lectura de las reglas.
     */
    private function sudoersSteps(): array
    {
        $user = getenv('USER') ?: get_current_user();
        $command = implode(' ', self::UFW_COMMAND);

        return [
            FixStep::command(
                'Permite al monitor leer el estado del cortafuegos (sólo ese comando de lectura, una sola vez).',
                "echo '{$user} ALL=(root) NOPASSWD: {$command}' | sudo tee " . self::SUDOERS_FILE
                    . ' && sudo chmod 440 ' . self::SUDOERS_FILE
            ),
            FixStep::command('Comprueba que la regla quedó bien escrita (debe decir «parsed OK»).', 'sudo visudo -cf '
                . self::SUDOERS_FILE),
            FixStep::command('Mientras tanto, revisa a mano qué programa usa cada puerto.', 'sudo ss -tlnp'),
        ];
    }
}

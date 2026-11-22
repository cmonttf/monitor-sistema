<?php

namespace App\Services\Security\Checks;

use App\Services\Security\CheckResult;
use App\Services\Security\FixStep;

/**
 * Intentos fallidos de inicio de sesión en Linux (SSH y locales) en las últimas 24 horas, leídos del
 * journal de autenticación: detecta ataques de fuerza bruta y accesos exitosos tras varios intentos.
 *
 * @phpstan-type Attempts array{
 *     remote: array<string, array{failures: int, users: list<string>}>,
 *     local: array<string, int>,
 *     accepted: array<string, list<string>>
 * }
 *
 * @package App\Services\Security\Checks
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class LoginFailuresCheck extends SystemCheck
{
    use BlocksAddresses;

    /**
     * Intentos fallidos desde una misma IP a partir de los cuales se considera fuerza bruta.
     */
    public const int BRUTE_FORCE_ATTEMPTS = 5;

    /**
     * Intentos fallidos previos que vuelven sospechoso un acceso exitoso desde la misma IP.
     */
    public const int SUSPICIOUS_SUCCESS_ATTEMPTS = 3;

    /**
     * Intentos fallidos locales (sudo, pantalla de inicio) a partir de los cuales se advierte.
     */
    public const int LOCAL_WARNING_ATTEMPTS = 10;

    /**
     * Nombre visible del chequeo en el panel.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Intentos de inicio de sesión';
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
     * Crítico si alguien entró tras varios intentos fallidos o si una IP acumula 5 o más fallos (fuerza
     * bruta); advertencia con fallos remotos aislados o con 10 o más fallos locales.
     *
     * @return CheckResult Estado, resumen y detalles del chequeo.
     */
    public function run(): CheckResult
    {
        $result = $this->system->hasCommand('journalctl')
            ? $this->system->run(
                ['journalctl', '--since=-24h', '--facility=auth,authpriv', '--no-pager', '-o', 'cat'],
                30
            )
            : null;

        if ($result === null || $result->failed()) {
            return CheckResult::unknown('No se pudo leer el registro de autenticación.', [], [
                FixStep::command(
                    'Agrega tu usuario al grupo adm, que permite leer los registros '
                        . '(luego cierra sesión y vuelve a entrar).',
                    'sudo usermod -aG adm $USER'
                ),
            ]);
        }

        $attempts = self::parse($result->output());

        foreach ($attempts['accepted'] as $ip => $users) {
            $failures = $attempts['remote'][$ip]['failures'] ?? 0;

            if ($failures >= self::SUSPICIOUS_SUCCESS_ATTEMPTS) {
                return CheckResult::critical(
                    "Alguien entró desde {$ip} tras {$failures} intentos fallidos.",
                    $this->details($attempts),
                    [
                        FixStep::note(
                            'Si no fuiste tú, cambia de inmediato la contraseña de: ' . implode(', ', $users) . '.'
                        ),
                        FixStep::command('Revisa los últimos accesos al equipo.', 'last -n 20'),
                        $this->blockAddressStep($ip),
                    ]
                );
            }
        }

        $attackers = array_filter(
            $attempts['remote'],
            fn (array $source): bool => $source['failures'] >= self::BRUTE_FORCE_ATTEMPTS
        );

        if ($attackers !== []) {
            uasort($attackers, fn (array $a, array $b): int => $b['failures'] <=> $a['failures']);
            $ip = (string) array_key_first($attackers);

            return CheckResult::critical(
                "Posible ataque de fuerza bruta: {$attackers[$ip]['failures']} intentos fallidos desde {$ip}.",
                $this->details($attempts),
                [
                    $this->blockAddressStep($ip),
                    $this->platform->installStep('Instala fail2ban, que bloquea automáticamente estas IP.', 'fail2ban'),
                    FixStep::note(
                        'Desactiva el acceso por contraseña en SSH (PasswordAuthentication no) y usa llaves.'
                    ),
                ]
            );
        }

        if ($attempts['remote'] !== []) {
            return CheckResult::warning(
                'Hubo ' . array_sum(
                    array_column($attempts['remote'], 'failures')
                ) . ' intentos fallidos de acceso remoto.',
                $this->details($attempts),
                [FixStep::note(
                    'Si no reconoces estos intentos, revisa que el servidor SSH no esté expuesto a internet.'
                )]
            );
        }

        $localFailures = array_sum($attempts['local']);

        if ($localFailures >= self::LOCAL_WARNING_ATTEMPTS) {
            return CheckResult::warning(
                "Hubo {$localFailures} intentos fallidos de inicio de sesión local.",
                $this->details($attempts),
                [
                    FixStep::note(
                        'Si no fuiste tú, alguien podría estar intentando adivinar tu contraseña con acceso '
                            . 'físico al equipo.'
                    ),
                ]
            );
        }

        return CheckResult::ok(
            'Sin intentos sospechosos de inicio de sesión en las últimas 24 horas.',
            $this->details($attempts)
        );
    }

    /**
     * Interpreta el registro de autenticación: fallos de SSH por IP, fallos locales de PAM por servicio y
     * accesos SSH aceptados por IP.
     *
     * @param string $log Mensajes del journal (formato «cat»).
     *
     * @return Attempts Intentos agrupados.
     */
    public static function parse(string $log): array
    {
        $attempts = ['remote' => [], 'local' => [], 'accepted' => []];

        foreach (explode("\n", $log) as $line) {
            if (
                preg_match(
                    '/Failed (?:password|publickey|keyboard-interactive\S*) for (?:invalid user )?(\S+) from (\S+)/',
                    $line,
                    $match
                ) === 1
            ) {
                $attempts['remote'][$match[2]]['failures'] = ($attempts['remote'][$match[2]]['failures'] ?? 0) + 1;
                $attempts['remote'][$match[2]]['users'][] = $match[1];
            } elseif (preg_match('/Accepted \S+ for (\S+) from (\S+)/', $line, $match) === 1) {
                $attempts['accepted'][$match[2]][] = $match[1];
            } elseif (preg_match('/pam_unix\((?!sshd)([\w-]+):auth\): authentication failure/', $line, $match) === 1) {
                $attempts['local'][$match[1]] = ($attempts['local'][$match[1]] ?? 0) + 1;
            }
        }

        foreach ($attempts['remote'] as $ip => $source) {
            $attempts['remote'][$ip]['users'] = array_values(array_unique($source['users']));
        }

        return $attempts;
    }

    /**
     * Resume los intentos para los detalles de la tarjeta.
     *
     * @param Attempts $attempts Intentos agrupados.
     *
     * @return list<string> Una línea por origen.
     */
    private function details(array $attempts): array
    {
        $details = [];

        foreach ($attempts['remote'] as $ip => $source) {
            $details[] = "{$ip}: {$source['failures']} fallidos (usuarios: " . implode(
                ', ',
                array_slice($source['users'], 0, 5)
            ) . ')';
        }

        foreach ($attempts['local'] as $service => $count) {
            $details[] = "Local ({$service}): {$count} fallidos";
        }

        foreach ($attempts['accepted'] as $ip => $users) {
            $details[] = "Acceso SSH aceptado desde {$ip}: " . implode(', ', array_unique($users));
        }

        return $details;
    }
}

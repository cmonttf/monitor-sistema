<?php

namespace App\Services\Security;

use App\Enums\LinuxFamily;
use App\Services\Security\Checks\BlockedConnectionsCheck;
use App\Services\Security\Checks\LoginFailuresCheck;
use App\Services\Security\Checks\MalwareDetectionsCheck;

/**
 * Línea de tiempo de la actividad de ataques para el gráfico en tiempo real: cada evento con su hora y su
 * tipo. Usa los mismos criterios que las tarjetas de detección (clasificación compartida de las líneas).
 *
 * @phpstan-type AttackEvent array{t: int, type: string}
 * @phpstan-type Timeline array{events: list<AttackEvent>, unavailable: list<string>}
 *
 * @package App\Services\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class AttackTimeline
{
    /**
     * Tipo de evento: intento fallido de inicio de sesión (remoto o local).
     */
    public const string LOGIN = 'login';

    /**
     * Tipo de evento: conexión entrante bloqueada por el cortafuegos.
     */
    public const string BLOCKED = 'blocked';

    /**
     * Tipo de evento: amenaza detectada por el antivirus.
     */
    public const string MALWARE = 'malware';

    /**
     * Tipo de evento: solicitud al panel rechazada por el middleware de acceso local.
     */
    public const string PANEL = 'panel';

    /**
     * Cantidad máxima de eventos por tipo (los más recientes), para acotar la respuesta.
     */
    private const int MAX_EVENTS_PER_TYPE = 5000;

    /**
     * Lee en Windows la hora de los inicios de sesión fallidos, los bloqueos del firewall y las detecciones
     * de Defender; cada lista es null si no se pudo leer (por ejemplo, sin permisos de administrador).
     */
    private const string WINDOWS_SCRIPT = <<<'PS'
        $since = (Get-Date).AddHours(-__HOURS__)
        $logins = $null
        try {
            $filter = @{ LogName = 'Security'; Id = 4625; StartTime = $since }
            $logins = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
                ForEach-Object { ([DateTimeOffset]$_.TimeCreated).ToUnixTimeSeconds() })
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $logins = @() }
        }
        $blocked = $null
        try {
            $path = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log'
            $start = $since.ToString('yyyy-MM-dd HH:mm:ss')
            $blocked = @(Get-Content -LiteralPath $path -Tail 20000 -ErrorAction Stop |
                Where-Object { $_ -match ' DROP ' -and $_ -match 'RECEIVE' -and $_.Substring(0, 19) -ge $start } |
                ForEach-Object { $_.Substring(0, 19) })
        } catch {}
        $malware = $null
        try {
            $malware = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -gt $since } |
                ForEach-Object { ([DateTimeOffset]$_.InitialDetectionTime).ToUnixTimeSeconds() })
        } catch {}
        [pscustomobject]@{ logins = $logins; blocked = $blocked; malware = $malware }
        PS;

    /**
     * Recibe el acceso al sistema, la plataforma y el registro de solicitudes rechazadas.
     *
     * @param SystemInspector   $system          Acceso a comandos y archivos del sistema.
     * @param Platform          $platform        Plataforma en la que corre el monitor.
     * @param BlockedRequestLog $blockedRequests Registro de solicitudes rechazadas por el panel.
     */
    public function __construct(
        private SystemInspector $system,
        private Platform $platform,
        private BlockedRequestLog $blockedRequests,
    ) {
    }

    /**
     * Eventos de ataque de las últimas horas, ordenados por hora, y los tipos que no se pudieron leer.
     *
     * @param int $hours Horas hacia atrás.
     *
     * @return Timeline Eventos y tipos sin datos.
     */
    public function events(int $hours): array
    {
        $byType = $this->platform->isWindows() ? $this->windowsEvents($hours) : $this->linuxEvents($hours);
        $byType[self::PANEL] = array_map(
            fn (array $attempt): int => $attempt['time'],
            $this->blockedRequests->recent($hours)
        );

        $events = [];
        $unavailable = [];

        foreach ($byType as $type => $times) {
            if ($times === null) {
                $unavailable[] = $type;

                continue;
            }

            foreach (array_slice($times, -self::MAX_EVENTS_PER_TYPE) as $time) {
                $events[] = ['t' => $time, 'type' => $type];
            }
        }

        usort($events, fn (array $a, array $b): int => $a['t'] <=> $b['t']);

        return ['events' => $events, 'unavailable' => $unavailable];
    }

    /**
     * Lee los eventos de Linux desde el journal: autenticación, mensajes del kernel y ClamAV.
     *
     * @param int $hours Horas hacia atrás.
     *
     * @return array<string, list<int>|null> Tipo => horas Unix de sus eventos (null si no se pudo leer).
     */
    private function linuxEvents(int $hours): array
    {
        $clamd = $this->platform->family === LinuxFamily::RedHat ? 'clamd@scan' : 'clamav-daemon';

        return [
            self::LOGIN => $this->journalTimes(
                ['--facility=auth,authpriv'],
                $hours,
                fn (string $message): bool => in_array(
                    LoginFailuresCheck::classify($message)['kind'] ?? null,
                    ['failure', 'local'],
                    true
                )
            ),
            self::BLOCKED => $this->journalTimes(
                ['-k'],
                $hours,
                fn (string $message): bool => BlockedConnectionsCheck::classify($message) !== null
            ),
            self::MALWARE => $this->journalTimes(
                ['-u', $clamd, '-u', 'clamav-clamonacc'],
                $hours,
                fn (string $message): bool => MalwareDetectionsCheck::classify($message) !== null
            ),
        ];
    }

    /**
     * Lee del journal (formato short-unix) la hora de los mensajes que cumplen el criterio.
     *
     * @param list<string>           $filters  Filtros de journalctl.
     * @param int                    $hours    Horas hacia atrás.
     * @param callable(string): bool $matches  Criterio aplicado al mensaje.
     *
     * @return list<int>|null Horas Unix de los mensajes que coinciden, o null si no se pudo leer el journal.
     */
    private function journalTimes(array $filters, int $hours, callable $matches): ?array
    {
        if (! $this->system->hasCommand('journalctl')) {
            return null;
        }

        $result = $this->system->run(
            ['journalctl', ...$filters, "--since=-{$hours}h", '--no-pager', '-o', 'short-unix'],
            30
        );

        if ($result->failed()) {
            return null;
        }

        $times = [];

        foreach (explode("\n", $result->output()) as $line) {
            if (preg_match('/^(\d+)(?:\.\d+)?\s+\S+\s+(.*)$/', $line, $match) === 1 && $matches($match[2])) {
                $times[] = (int) $match[1];
            }
        }

        return $times;
    }

    /**
     * Lee los eventos de Windows con una sola llamada a PowerShell.
     *
     * @param int $hours Horas hacia atrás.
     *
     * @return array<string, list<int>|null> Tipo => horas Unix de sus eventos (null si no se pudo leer).
     */
    private function windowsEvents(int $hours): array
    {
        $data = $this->system->powershell(str_replace('__HOURS__', (string) $hours, self::WINDOWS_SCRIPT), 60) ?? [];
        $toTimes = fn (mixed $values): ?array => is_array($values) ? array_map('intval', $values) : null;

        return [
            self::LOGIN => $toTimes($data['logins'] ?? null),
            self::BLOCKED => is_array($data['blocked'] ?? null)
                ? array_map(fn (string $date): int => (int) strtotime($date), $data['blocked'])
                : null,
            self::MALWARE => $toTimes($data['malware'] ?? null),
        ];
    }
}

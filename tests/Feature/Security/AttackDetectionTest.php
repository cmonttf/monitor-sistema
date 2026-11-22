<?php

namespace Tests\Feature\Security;

use App\Enums\CheckStatus;
use App\Enums\LinuxFamily;
use App\Services\Security\BlockedRequestLog;
use App\Services\Security\Checks\BlockedConnectionsCheck;
use App\Services\Security\Checks\FileIntegrityCheck;
use App\Services\Security\Checks\LoginFailuresCheck;
use App\Services\Security\Checks\MalwareDetectionsCheck;
use App\Services\Security\Checks\PanelAccessCheck;
use App\Services\Security\Checks\WindowsBlockedConnectionsCheck;
use App\Services\Security\Checks\WindowsLoginFailuresCheck;
use App\Services\Security\Checks\WindowsMalwareDetectionsCheck;
use App\Services\Security\FixStep;
use App\Services\Security\IntegrityBaseline;
use App\Services\Security\IntegritySnapshot;
use App\Services\Security\Platform;
use App\Services\Security\SystemInspector;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Storage;
use Mockery\MockInterface;
use Tests\TestCase;

/**
 * Pruebas del detector de ataques: fuerza bruta, escaneos, malware, integridad de archivos y accesos al panel.
 *
 * @package Tests\Feature\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class AttackDetectionTest extends TestCase
{
    /**
     * Plataforma Linux de la familia Debian con la que se construyen los chequeos de Linux.
     */
    private Platform $linux;

    /**
     * Impide que las pruebas ejecuten procesos reales y prepara la plataforma.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        Process::fake([]);
        Process::preventStrayProcesses();
        $this->linux = Platform::linux(LinuxFamily::Debian, 'Ubuntu');
    }

    /**
     * Inspector real para comandos (interceptados con Process::fake) y simulado para el resto.
     *
     * @param list<string>               $commands     Ejecutables que se consideran instalados.
     * @param array<string, string|null> $files        Ruta => contenido.
     * @param array<string, string>      $fingerprints Ruta => huella.
     * @param array<string, list<string>> $globs       Patrón => rutas encontradas.
     *
     * @return SystemInspector Inspector parcialmente simulado.
     */
    private function inspector(
        array $commands = [],
        array $files = [],
        array $fingerprints = [],
        array $globs = []
    ): SystemInspector {
        $configure = function (MockInterface $mock) use ($commands, $files, $fingerprints, $globs): void {
            $mock->shouldReceive('hasCommand')
                ->andReturnUsing(fn (string $binary): bool => in_array($binary, $commands, true));
            $mock->shouldReceive('readFile')->andReturnUsing(fn (string $path): ?string => $files[$path] ?? null);
            $mock->shouldReceive('fileExists')->andReturnUsing(fn (string $path): bool => isset($files[$path]));
            $mock->shouldReceive('fingerprint')
                ->andReturnUsing(fn (string $path): ?string => $fingerprints[$path] ?? null);
            $mock->shouldReceive('glob')->andReturnUsing(fn (string $pattern): array => $globs[$pattern] ?? []);
            $mock->shouldReceive('homeDirectory')->andReturn('/home/usuario');
        };

        return $this->partialMock(SystemInspector::class, $configure);
    }

    /**
     * Comandos de una lista de pasos de solución.
     *
     * @param list<FixStep> $steps Pasos de solución.
     *
     * @return list<string> Comandos.
     */
    private static function commands(array $steps): array
    {
        return array_values(array_filter(array_map(fn (FixStep $step): ?string => $step->command, $steps)));
    }

    /**
     * Simula el journal de autenticación con las líneas indicadas.
     *
     * @param string $log Mensajes del journal.
     *
     * @return void
     */
    private function fakeAuthLog(string $log): void
    {
        Process::fake(
            [self::command(
                'journalctl --since=-24h --facility=auth,authpriv --no-pager -o cat'
            ) => Process::result($log)]
        );
    }

    /**
     * El análisis del registro separa fallos SSH por IP, fallos locales de PAM y accesos aceptados, sin
     * contar dos veces la línea de PAM de sshd.
     *
     * @return void
     */
    public function test_auth_log_is_parsed_by_source(): void
    {
        $attempts = LoginFailuresCheck::parse(implode("\n", [
            'Failed password for invalid user admin from 203.0.113.9 port 50122 ssh2',
            'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.9',
            'Failed password for root from 203.0.113.9 port 50124 ssh2',
            'Accepted publickey for usuario from 192.168.1.10 port 40000 ssh2',
            'pam_unix(sudo:auth): authentication failure; logname=usuario uid=1000 euid=0 tty=/dev/pts/1',
        ]));

        $this->assertSame(['failures' => 2, 'users' => ['admin', 'root']], $attempts['remote']['203.0.113.9']);
        $this->assertSame(['sudo' => 1], $attempts['local']);
        $this->assertSame(['192.168.1.10' => ['usuario']], $attempts['accepted']);
    }

    /**
     * Cinco o más fallos desde una IP son fuerza bruta y se sugiere bloquearla.
     *
     * @return void
     */
    public function test_brute_force_is_critical(): void
    {
        $this->fakeAuthLog(str_repeat("Failed password for root from 203.0.113.9 port 1 ssh2\n", 6));

        $result = (new LoginFailuresCheck($this->inspector(['journalctl', 'ufw']), $this->linux))->run();

        $this->assertSame(CheckStatus::Critical, $result->status);
        $this->assertSame('Posible ataque de fuerza bruta: 6 intentos fallidos desde 203.0.113.9.', $result->message);
        $this->assertContains('sudo ufw insert 1 deny from 203.0.113.9', self::commands($result->fix));
    }

    /**
     * Un acceso exitoso desde una IP con varios fallos previos es crítico.
     *
     * @return void
     */
    public function test_success_after_failures_is_critical(): void
    {
        $this->fakeAuthLog(str_repeat("Failed password for root from 203.0.113.9 port 1 ssh2\n", 3)
            . "Accepted password for root from 203.0.113.9 port 2 ssh2\n");

        $result = (new LoginFailuresCheck($this->inspector(['journalctl']), $this->linux))->run();

        $this->assertSame(CheckStatus::Critical, $result->status);
        $this->assertSame('Alguien entró desde 203.0.113.9 tras 3 intentos fallidos.', $result->message);
    }

    /**
     * Fallos remotos aislados o muchos fallos locales son advertencia; pocos fallos locales son normales.
     *
     * @return void
     */
    public function test_isolated_or_local_failures(): void
    {
        $local = 'pam_unix(gdm-password:auth): authentication failure; logname= uid=0';
        $check = new LoginFailuresCheck($this->inspector(['journalctl']), $this->linux);

        $this->fakeAuthLog("Failed password for root from 198.51.100.4 port 1 ssh2\n");
        $this->assertSame(CheckStatus::Warning, $check->run()->status);

        Process::fake([]);
        $this->fakeAuthLog(str_repeat("{$local}\n", 12));
        $this->assertSame(CheckStatus::Warning, $check->run()->status);

        Process::fake([]);
        $this->fakeAuthLog("{$local}\n");
        $this->assertSame(CheckStatus::Ok, $check->run()->status);
    }

    /**
     * Sin journalctl el chequeo queda sin datos y explica cómo obtener permiso de lectura.
     *
     * @return void
     */
    public function test_unreadable_auth_log_is_unknown(): void
    {
        $result = (new LoginFailuresCheck($this->inspector(), $this->linux))->run();

        $this->assertSame(CheckStatus::Unknown, $result->status);
        $this->assertSame('sudo usermod -aG adm $USER', $result->fix[0]->command);
    }

    /**
     * Los bloqueos se agrupan por origen, ignorando multidifusión, difusión y paquetes sin puerto.
     *
     * @return void
     */
    public function test_blocked_connections_ignore_broadcast_noise(): void
    {
        $sources = BlockedConnectionsCheck::parse(implode("\n", [
            '[UFW BLOCK] IN=wlp4s0 OUT= SRC=192.168.1.123 DST=224.0.0.251 LEN=32 PROTO=2',
            '[UFW BLOCK] IN=wlp4s0 OUT= SRC=192.168.1.20 DST=192.168.1.255 PROTO=UDP SPT=137 DPT=137',
            '[UFW BLOCK] IN=wlp4s0 OUT= SRC=203.0.113.9 DST=192.168.1.82 PROTO=TCP SPT=40000 DPT=22',
            '[UFW BLOCK] IN=wlp4s0 OUT= SRC=203.0.113.9 DST=192.168.1.82 PROTO=TCP SPT=40001 DPT=3389',
            '[UFW ALLOW] IN=wlp4s0 OUT= SRC=10.0.0.5 DST=192.168.1.82 PROTO=TCP SPT=1 DPT=80',
        ]));

        $this->assertSame(['203.0.113.9' => ['count' => 2, 'ports' => [22, 3389]]], $sources);
    }

    /**
     * Un origen que prueba 10 o más puertos distintos es un escaneo.
     *
     * @return void
     */
    public function test_port_scan_is_critical(): void
    {
        $lines = array_map(
            fn (int $port): string => '[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.9 DST=10.0.0.2 PROTO=TCP '
                . "SPT=5 DPT={$port}",
            range(20, 34)
        );
        Process::fake(
            [self::command('journalctl -k --since=-24h --no-pager -o cat') => Process::result(implode("\n", $lines))]
        );

        $result = (
            new BlockedConnectionsCheck(
                $this->inspector(['ufw'], ['/etc/ufw/ufw.conf' => "LOGLEVEL=low\n"]),
                $this->linux
            )
        )->run();

        $this->assertSame(CheckStatus::Critical, $result->status);
        $this->assertSame('Escaneo de puertos desde 203.0.113.9: probó 15 puertos distintos.', $result->message);
    }

    /**
     * Si UFW no registra bloqueos, el chequeo queda sin datos e indica cómo activarlo.
     *
     * @return void
     */
    public function test_disabled_firewall_logging_is_unknown(): void
    {
        $result = (
            new BlockedConnectionsCheck(
                $this->inspector(['ufw'], ['/etc/ufw/ufw.conf' => "LOGLEVEL=off\n"]),
                $this->linux
            )
        )->run();

        $this->assertSame(CheckStatus::Unknown, $result->status);
        $this->assertSame('sudo ufw logging low', $result->fix[0]->command);
    }

    /**
     * ClamAV: una amenaza real es crítica, sólo EICAR es advertencia y sin detecciones es correcto.
     *
     * @return void
     */
    public function test_malware_detections(): void
    {
        $command = self::command('journalctl -u clamav-daemon -u clamav-clamonacc --since=-7d --no-pager -o short-iso');
        $eicar = '2026-11-22T02:55:20-03:00 equipo clamd[1]: Sun Nov 22 02:55:20 2026 -> '
            . '/tmp/eicar.txt: Eicar-Test-Signature FOUND';
        $trojan = '2026-11-22T03:10:00-03:00 equipo clamd[1]: Sun Nov 22 03:10:00 2026 -> '
            . '/home/usuario/Descargas/factura.exe: Win.Trojan.Agent-123 FOUND';
        Process::fake([$command => Process::sequence()
            ->push(Process::result("{$eicar}\n{$trojan}\n"))
            ->push(Process::result("{$eicar}\n"))
            ->push(Process::result("-- No entries --\n")),
        ]);
        $inspector = $this->inspector(['clamd'], ['/home/usuario/Descargas/factura.exe' => 'MZ']);
        $check = new MalwareDetectionsCheck($inspector, $this->linux);

        $real = $check->run();
        $this->assertSame(CheckStatus::Critical, $real->status);
        $this->assertStringContainsString('[el archivo sigue en el disco]', $real->details[0]);
        $this->assertStringContainsString(
            "mv '/home/usuario/Descargas/factura.exe' ~/cuarentena/",
            implode("\n", self::commands($real->fix))
        );
        $this->assertSame(CheckStatus::Warning, $check->run()->status);
        $this->assertSame(CheckStatus::Ok, $check->run()->status);
    }

    /**
     * Huella simulada de un equipo Linux para el monitor de integridad.
     *
     * @param array<string, string> $changes Ruta => huella que reemplaza a la base.
     * @param array<string, string> $files   Contenido de archivos legibles.
     *
     * @return IntegritySnapshot Toma de huellas con el inspector simulado.
     */
    private function linuxSnapshot(array $changes = [], array $files = []): IntegritySnapshot
    {
        $fingerprints = [...[
            '/etc/passwd' => 'sha256:aaa',
            '/etc/shadow' => 'meta:1488:1700000000',
            '/etc/hosts' => 'sha256:bbb',
            '/etc/sudoers.d/README' => 'sha256:ccc',
        ], ...$changes];
        $globs = ['/etc/sudoers.d/*' => array_values(array_filter(
            array_keys($fingerprints),
            fn (string $path): bool => str_starts_with($path, '/etc/sudoers.d/')
        ))];
        Process::fake([self::command('crontab -l') => Process::result('', 'no crontab for usuario', 1)]);

        return new IntegritySnapshot(
            $this->inspector(
                [],
                ['/etc/passwd' => "root:x:0:0:root:/root:/bin/bash\n", ...$files],
                $fingerprints,
                $globs
            ),
            $this->linux
        );
    }

    /**
     * La primera ejecución registra la línea base; sin cambios después, es correcto.
     *
     * @return void
     */
    public function test_integrity_baseline_is_created_then_compared(): void
    {
        Storage::fake('local');
        $check = new FileIntegrityCheck($this->linuxSnapshot(), new IntegrityBaseline(), $this->linux);

        $this->assertSame('Se registró la línea base: 4 elementos vigilados desde ahora.', $check->run()->message);
        $this->assertStringStartsWith('Sin cambios desde el', $check->run()->message);
    }

    /**
     * Un cambio en un archivo sensible o un archivo nuevo en sudoers.d es crítico; en uno común, advertencia.
     *
     * @return void
     */
    public function test_integrity_changes_are_classified(): void
    {
        Storage::fake('local');
        $baseline = new IntegrityBaseline();
        (new FileIntegrityCheck($this->linuxSnapshot(), $baseline, $this->linux))->run();

        $passwd = (
            new FileIntegrityCheck($this->linuxSnapshot(['/etc/passwd' => 'sha256:zzz']), $baseline, $this->linux)
        )->run();
        $sudoers = (
            new FileIntegrityCheck(
                $this->linuxSnapshot(['/etc/sudoers.d/puerta' => 'sha256:x']),
                $baseline,
                $this->linux
            )
        )->run();
        $hosts = (
            new FileIntegrityCheck($this->linuxSnapshot(['/etc/hosts' => 'sha256:yyy']), $baseline, $this->linux)
        )->run();

        $this->assertSame(CheckStatus::Critical, $passwd->status);
        $this->assertContains('Modificado: /etc/passwd', $passwd->details);
        $this->assertSame(CheckStatus::Critical, $sudoers->status);
        $this->assertContains('Nuevo: /etc/sudoers.d/puerta', $sudoers->details);
        $this->assertSame(CheckStatus::Warning, $hosts->status);
        $this->assertContains('php artisan monitor:integrity --accept', self::commands($hosts->fix));
    }

    /**
     * Una cuenta extra con UID 0 o la existencia de /etc/ld.so.preload son críticas de inmediato.
     *
     * @return void
     */
    public function test_backdoor_indicators_are_critical(): void
    {
        Storage::fake('local');
        $extraRoot = $this->linuxSnapshot(
            [],
            ['/etc/passwd' => "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/:/bin/sh\n"]
        );
        $preload = $this->linuxSnapshot(['/etc/ld.so.preload' => 'sha256:ppp']);

        $root = (new FileIntegrityCheck($extraRoot, new IntegrityBaseline(), $this->linux))->run();
        $rootkit = (new FileIntegrityCheck($preload, new IntegrityBaseline(), $this->linux))->run();

        $this->assertSame('Hay cuentas con privilegios de root además de root: toor.', $root->message);
        $this->assertSame(CheckStatus::Critical, $rootkit->status);
        $this->assertStringContainsString('/etc/ld.so.preload', $rootkit->message);
    }

    /**
     * El comando monitor:integrity --accept guarda el estado actual como nueva línea base.
     *
     * @return void
     */
    public function test_accept_command_updates_the_baseline(): void
    {
        Storage::fake('local');
        $this->app->instance(IntegritySnapshot::class, $this->linuxSnapshot(['/etc/hosts' => 'sha256:nuevo']));
        (new IntegrityBaseline())->save(['/etc/hosts' => ['fingerprint' => 'sha256:viejo', 'sensitive' => false]]);

        $this->artisan('monitor:integrity')->expectsTable(['Cambio', 'Elemento'], [
            ['Modificado', '/etc/hosts'],
            ['Nuevo', '/etc/passwd'],
            ['Nuevo', '/etc/shadow'],
            ['Nuevo', '/etc/sudoers.d/README'],
        ])->assertSuccessful();
        $this->artisan('monitor:integrity --accept')->assertSuccessful();

        $this->assertSame('sha256:nuevo', (new IntegrityBaseline())->load()['entries']['/etc/hosts']['fingerprint']);
    }

    /**
     * En Windows los administradores locales y el inicio automático se vigilan como elementos sensibles.
     *
     * @return void
     */
    public function test_windows_integrity_items_are_captured(): void
    {
        $inspector = $this->partialMock(SystemInspector::class, function (MockInterface $mock): void {
            $mock->shouldReceive('powershell')->andReturn(['items' => [
                '!Administradores locales' => "EQUIPO\\Administrador\nEQUIPO\\usuario",
                'Archivo hosts' => 'ABC123',
            ]]);
        });

        $entries = (new IntegritySnapshot($inspector, Platform::windows()))->capture();

        $this->assertTrue($entries['Administradores locales']['sensitive']);
        $this->assertFalse($entries['Archivo hosts']['sensitive']);
    }

    /**
     * Los intentos de acceso rechazados por el middleware aparecen en su tarjeta; muchos son críticos.
     *
     * @return void
     */
    public function test_blocked_panel_requests_are_reported(): void
    {
        $check = new PanelAccessCheck(new BlockedRequestLog());
        $this->assertSame(CheckStatus::Ok, $check->run()->status);

        $this->get('http://rebind.atacante.example/estado')->assertForbidden();
        $this->withServerVariables(
            ['REMOTE_ADDR' => '192.168.1.50']
        )->get('http://127.0.0.1/estado')->assertForbidden();

        $result = $check->run();
        $this->assertSame(CheckStatus::Warning, $result->status);
        $this->assertSame(
            '2 intentos de acceso al panel bloqueados en 24 horas, 1 desde páginas web (posible DNS rebinding).',
            $result->message
        );
        $this->assertStringContainsString('dominio «rebind.atacante.example» pidió /estado', $result->details[1]);

        for ($attempt = 0; $attempt < 18; $attempt++) {
            $this->get('http://rebind.atacante.example/')->assertForbidden();
        }
        $this->assertSame(CheckStatus::Critical, $check->run()->status);
    }

    /**
     * Windows: sin permiso para el registro de Seguridad queda sin datos; 5 fallos desde una IP son críticos.
     *
     * @return void
     */
    public function test_windows_login_failures(): void
    {
        $failures = array_fill(0, 6, ['user' => 'Administrador', 'ip' => '203.0.113.9']);
        $inspector = $this->partialMock(SystemInspector::class, function (MockInterface $mock) use ($failures): void {
            $mock->shouldReceive('powershell')->andReturn(
                ['readable' => false, 'failures' => []],
                ['readable' => true, 'failures' => $failures],
                ['readable' => true, 'failures' => []],
            );
        });
        $check = new WindowsLoginFailuresCheck($inspector, Platform::windows());

        $this->assertSame(CheckStatus::Unknown, $check->run()->status);
        $this->assertSame(CheckStatus::Critical, $check->run()->status);
        $this->assertSame(CheckStatus::Ok, $check->run()->status);
    }

    /**
     * Windows: sin registro de bloqueos queda sin datos; un escaneo en pfirewall.log es crítico.
     *
     * @return void
     */
    public function test_windows_blocked_connections(): void
    {
        $lines = array_map(
            fn (int $port): string => "2026-11-22 10:00:00 DROP TCP 203.0.113.9 192.168.1.82 40000 {$port} "
                . '52 S 0 0 0 - - - RECEIVE',
            range(20, 31)
        );
        $inspector = $this->partialMock(SystemInspector::class, function (MockInterface $mock) use ($lines): void {
            $mock->shouldReceive('powershell')->andReturn(
                ['logging' => false, 'readable' => false, 'lines' => []],
                ['logging' => true, 'readable' => true, 'lines' => $lines],
            );
        });
        $check = new WindowsBlockedConnectionsCheck($inspector, Platform::windows());

        $this->assertSame('Set-NetFirewallProfile -All -LogBlocked True', $check->run()->fix[0]->command);
        $this->assertSame('Escaneo de puertos desde 203.0.113.9: probó 12 puertos distintos.', $check->run()->message);
    }

    /**
     * Windows: amenazas activas son críticas, neutralizadas son advertencia y sin historial queda sin datos.
     *
     * @return void
     */
    public function test_windows_malware_detections(): void
    {
        $detection = [
            'threat' => 'Trojan:Win32/Agent',
            'resources' => ['file:_C:\\Users\\u\\a.exe'],
            'time' => '2026-11-22T10:00:00',
        ];
        $inspector = $this->partialMock(SystemInspector::class, function (MockInterface $mock) use ($detection): void {
            $mock->shouldReceive('powershell')->andReturn(
                ['readable' => true, 'detections' => [[...$detection, 'status' => 1]]],
                ['readable' => true, 'detections' => [[...$detection, 'status' => 3]]],
                ['readable' => false, 'detections' => []],
            );
        });
        $check = new WindowsMalwareDetectionsCheck($inspector, Platform::windows());

        $this->assertSame(CheckStatus::Critical, $check->run()->status);
        $this->assertSame(CheckStatus::Warning, $check->run()->status);
        $this->assertSame(CheckStatus::Unknown, $check->run()->status);
    }
}

<?php

namespace Tests\Feature\Security;

use App\Mail\SecurityAlertMail;
use App\Services\Security\AlertState;
use App\Services\Security\CheckResult;
use App\Services\Security\DesktopNotifier;
use App\Services\Security\FixStep;
use App\Services\Security\Platform;
use App\Services\Security\SystemInspector;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Storage;
use Mockery\MockInterface;
use Tests\TestCase;

/**
 * Pruebas de las alertas programadas: detección de cambios, correo, notificación de escritorio y programación.
 *
 * @package Tests\Feature\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class AlertsTest extends TestCase
{
    /**
     * Notificaciones de escritorio enviadas durante la prueba: [título, texto, urgente].
     *
     * @var list<array{string, string, bool}>
     */
    private array $desktopNotifications = [];

    /**
     * Prepara un chequeo simulado, el correo y el almacenamiento falsos, y un notificador que registra los avisos.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        Mail::fake();
        Storage::fake('local');
        FakeCheck::$results = [];
        config([
            'security-monitor.checks' => [FakeCheck::class],
            'security-monitor.alerts.enabled' => true,
            'security-monitor.alerts.email' => 'admin@example.com',
            'security-monitor.alerts.desktop' => true,
        ]);

        $this->partialMock(DesktopNotifier::class, function (MockInterface $mock): void {
            $mock->shouldReceive('notify')->andReturnUsing(function (
                string $title,
                string $body,
                bool $critical = false
            ): bool {
                $this->desktopNotifications[] = [$title, $body, $critical];

                return true;
            });
        });
    }

    /**
     * Fila de reporte con la clave y el estado indicados.
     *
     * @param string $key    Clave del chequeo.
     * @param string $status Estado.
     *
     * @return array<string, mixed> Fila del reporte.
     */
    private static function row(string $key, string $status): array
    {
        return ['key' => $key, 'name' => $key, 'status' => $status];
    }

    /**
     * Sólo empeorar a advertencia o crítico avisa; volver a «al día» desde un problema se informa como resuelto.
     *
     * @return void
     */
    public function test_changes_detect_worsened_and_resolved_checks(): void
    {
        $changes = AlertState::changes([
            self::row('a', 'warning'),
            self::row('b', 'critical'),
            self::row('c', 'warning'),
            self::row('d', 'unknown'),
            self::row('e', 'ok'),
            self::row('nuevo', 'critical'),
        ], ['a' => 'ok', 'b' => 'warning', 'c' => 'critical', 'd' => 'ok', 'e' => 'warning']);

        $this->assertSame(['b', 'nuevo', 'a'], array_column($changes['worsened'], 'key'));
        $this->assertSame(['e'], array_column($changes['resolved'], 'key'));
    }

    /**
     * Un problema nuevo envía un correo y una notificación de escritorio, y no se repite en la revisión siguiente.
     *
     * @return void
     */
    public function test_new_problem_is_notified_once(): void
    {
        $failing = CheckResult::critical(
            'El cortafuegos está desactivado.',
            [],
            [FixStep::command('Actívalo.', 'sudo ufw enable')]
        );
        FakeCheck::$results = [$failing, $failing];

        $this->artisan('monitor:alert')->assertSuccessful();
        $this->artisan('monitor:alert')->expectsOutputToContain('Sin cambios que avisar.')->assertSuccessful();

        Mail::assertSent(SecurityAlertMail::class, 1);
        Mail::assertSent(SecurityAlertMail::class, function (SecurityAlertMail $mail): bool {
            return $mail->hasTo('admin@example.com')
                && str_starts_with($mail->envelope()->subject, '🔴 Crítico: 1 problema de seguridad en ')
                && $mail->worsened[0]['message'] === 'El cortafuegos está desactivado.';
        });
        $this->assertCount(1, $this->desktopNotifications);
        $this->assertSame('1 problema de seguridad nuevo', $this->desktopNotifications[0][0]);
        $this->assertTrue($this->desktopNotifications[0][2]);
    }

    /**
     * Cuando un problema se resuelve, se avisa con el asunto de resueltos.
     *
     * @return void
     */
    public function test_resolved_problem_is_notified(): void
    {
        FakeCheck::$results = [CheckResult::warning('Firmas antiguas.'), CheckResult::ok('Firmas al día.')];

        $this->artisan('monitor:alert')->assertSuccessful();
        $this->artisan('monitor:alert')->assertSuccessful();

        Mail::assertSent(SecurityAlertMail::class, fn (SecurityAlertMail $mail): bool => $mail->resolved !== []
            && str_starts_with($mail->envelope()->subject, 'Problemas de seguridad resueltos en '));
    }

    /**
     * Si el correo falla, se reintenta en la revisión siguiente sin repetir la notificación de escritorio.
     *
     * @return void
     */
    public function test_failed_mail_is_retried_without_repeating_the_desktop_notification(): void
    {
        $failing = CheckResult::critical('Problema.');
        FakeCheck::$results = [$failing, $failing];
        Mail::shouldReceive('to')->twice()->andReturnSelf();
        Mail::shouldReceive('send')->once()->andThrow(
            new \RuntimeException('534 Application-specific password required')
        );
        Mail::shouldReceive('send')->once();

        $this->artisan('monitor:alert')->assertFailed();
        $this->artisan('monitor:alert')->assertSuccessful();

        $this->assertCount(1, $this->desktopNotifications);
    }

    /**
     * Sin destinatario configurado no se envía correo, pero sí la notificación de escritorio.
     *
     * @return void
     */
    public function test_without_recipient_only_desktop_is_notified(): void
    {
        config(['security-monitor.alerts.email' => null]);
        FakeCheck::$results = [CheckResult::warning('Algo cambió.')];

        $this->artisan('monitor:alert')->assertSuccessful();

        Mail::assertNothingSent();
        $this->assertCount(1, $this->desktopNotifications);
    }

    /**
     * Con las alertas desactivadas no se ejecuta ninguna revisión ni se avisa.
     *
     * @return void
     */
    public function test_disabled_alerts_do_nothing(): void
    {
        config(['security-monitor.alerts.enabled' => false]);
        FakeCheck::$results = [CheckResult::critical('Problema.')];

        $this->artisan('monitor:alert')->assertSuccessful();

        Mail::assertNothingSent();
        $this->assertCount(1, FakeCheck::$results);
    }

    /**
     * El aviso de prueba envía un correo de prueba y una notificación de escritorio.
     *
     * @return void
     */
    public function test_test_option_sends_a_test_alert(): void
    {
        $this->artisan('monitor:alert --test')->assertSuccessful();

        Mail::assertSent(SecurityAlertMail::class, fn (SecurityAlertMail $mail): bool => $mail->isTest
            && str_starts_with($mail->envelope()->subject, 'Prueba de alertas del monitor en '));
        $this->assertCount(1, $this->desktopNotifications);
    }

    /**
     * El correo muestra cada problema con sus pasos de solución y los comandos.
     *
     * @return void
     */
    public function test_alert_mail_renders_fix_steps(): void
    {
        $check = [
            'key' => 'firewall-check', 'name' => 'Cortafuegos', 'category' => 'Protección', 'status' => 'critical',
            'label' => 'Crítico', 'message' => 'El cortafuegos está desactivado.', 'details' => [],
            'fix' => [['text' => 'Actívalo.', 'command' => 'sudo ufw enable']],
        ];

        $html = (new SecurityAlertMail([$check], [], 'equipo', 'Ubuntu 26.04'))->render();

        $this->assertStringContainsString('Cortafuegos', $html);
        $this->assertStringContainsString('El cortafuegos está desactivado.', $html);
        $this->assertStringContainsString('sudo ufw enable', $html);
    }

    /**
     * La revisión está programada con la frecuencia configurada y sin solaparse.
     *
     * @return void
     */
    public function test_alert_command_is_scheduled(): void
    {
        $events = collect(app(Schedule::class)->events())
            ->filter(fn ($event): bool => str_contains((string) $event->command, 'monitor:alert'));

        $this->assertCount(1, $events);
        $this->assertSame('*/5 * * * *', $events->first()->expression);
        $this->assertTrue($events->first()->withoutOverlapping);
    }

    /**
     * En Linux la notificación usa notify-send con la urgencia indicada.
     *
     * @return void
     */
    public function test_linux_desktop_notification_uses_notify_send(): void
    {
        Process::fake();
        $inspector = $this->partialMock(SystemInspector::class, function (MockInterface $mock): void {
            $mock->shouldReceive('hasCommand')->with('notify-send')->andReturn(true);
        });

        $sent = (
            new DesktopNotifier($inspector, Platform::linux(\App\Enums\LinuxFamily::Debian))
        )->notify('Título', 'Texto', true);

        $this->assertTrue($sent);
        Process::assertRan(
            fn ($process): bool => str_contains((string) json_encode($process->command), '--urgency=critical')
        );
    }

    /**
     * En Windows el texto de la notificación se cita como cadena literal de PowerShell.
     *
     * @return void
     */
    public function test_windows_notification_script_quotes_text(): void
    {
        $script = app(DesktopNotifier::class)->windowsScript('Monitor', "Firmas de O'Brien");

        $this->assertStringContainsString("CreateTextNode('Firmas de O''Brien')", $script);
        $this->assertStringContainsString('ToastNotificationManager', $script);
    }
}

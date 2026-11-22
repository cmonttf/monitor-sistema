<?php

namespace App\Console\Commands;

use App\Mail\SecurityAlertMail;
use App\Services\Security\AlertState;
use App\Services\Security\DesktopNotifier;
use App\Services\Security\Platform;
use App\Services\Security\SecurityMonitor;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Mail;
use Throwable;

/**
 * Revisión programada: ejecuta los chequeos y, si alguno empeoró desde el último aviso, avisa por correo
 * y con una notificación de escritorio. Si el correo falla, se reintenta en la próxima revisión sin repetir
 * la notificación de escritorio. Con --test envía un aviso de prueba para verificar la configuración.
 *
 * @phpstan-import-type CheckRow from SecurityMonitor
 *
 * @package App\Console\Commands
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
#[Signature('monitor:alert {--test : Envía un aviso de prueba por correo y al escritorio}')]
#[Description('Revisa el equipo y avisa por correo y al escritorio si algún elemento de seguridad empeoró')]
class AlertCommand extends Command
{
    /**
     * Ejecuta la revisión y envía los avisos que correspondan.
     *
     * @param SecurityMonitor $monitor  Monitor que ejecuta los chequeos.
     * @param AlertState      $state    Último estado notificado.
     * @param DesktopNotifier $notifier Notificaciones de escritorio.
     * @param Platform        $platform Plataforma en la que corre el monitor.
     *
     * @return int Código de salida.
     */
    public function handle(
        SecurityMonitor $monitor,
        AlertState $state,
        DesktopNotifier $notifier,
        Platform $platform
    ): int {
        if (! config('security-monitor.alerts.enabled')) {
            $this->components->info('Las alertas están desactivadas (SECURITY_MONITOR_ALERTS=false).');

            return self::SUCCESS;
        }

        if ($this->option('test')) {
            return $this->sendTest($notifier, $platform);
        }

        $report = $monitor->report(fresh: true);
        $desktopChanges = AlertState::changes($report['checks'], $state->load(AlertState::DESKTOP));
        $mailChanges = AlertState::changes($report['checks'], $state->load(AlertState::MAIL));

        if ($desktopChanges['worsened'] !== [] || $desktopChanges['resolved'] !== []) {
            $this->notifyDesktop($notifier, $desktopChanges['worsened'], $desktopChanges['resolved']);
        }

        $state->save($report['checks'], AlertState::DESKTOP);
        $mailed = true;

        if ($mailChanges['worsened'] !== [] || $mailChanges['resolved'] !== []) {
            $mailed = $this->sendMail(new SecurityAlertMail(
                $mailChanges['worsened'],
                $mailChanges['resolved'],
                (string) gethostname(),
                $platform->name
            ));
        }

        if ($mailed) {
            $state->save($report['checks'], AlertState::MAIL);
        }

        $this->components->info(
            $mailChanges['worsened'] === [] && $mailChanges['resolved'] === [] && $desktopChanges['worsened'] === []
                ? 'Sin cambios que avisar.'
                : count(
                    $mailChanges['worsened']
                ) . ' empeoraron y ' . count($mailChanges['resolved']) . ' se resolvieron.'
        );

        return $mailed ? self::SUCCESS : self::FAILURE;
    }

    /**
     * Envía el aviso de prueba por correo y al escritorio.
     *
     * @param DesktopNotifier $notifier Notificaciones de escritorio.
     * @param Platform        $platform Plataforma en la que corre el monitor.
     *
     * @return int Código de salida.
     */
    private function sendTest(DesktopNotifier $notifier, Platform $platform): int
    {
        $desktop = $notifier->notify(
            'Monitor de Seguridad',
            'Prueba de alertas: las notificaciones de escritorio funcionan.'
        );
        $this->components->twoColumnDetail('Notificación de escritorio', $desktop ? 'enviada' : 'no disponible');

        $mailed = $this->sendMail(new SecurityAlertMail([], [], (string) gethostname(), $platform->name, isTest: true));

        if ($mailed && config('mail.default') === 'log') {
            $this->components->warn(
                'El correo se escribió en storage/logs/laravel.log porque MAIL_MAILER=log: configura SMTP en .env.'
            );
        }

        return $mailed ? self::SUCCESS : self::FAILURE;
    }

    /**
     * Envía el correo de alerta al destinatario configurado.
     *
     * @param SecurityAlertMail $mail Correo a enviar.
     *
     * @return bool true si se envió, o si no hay destinatario configurado (no es un error).
     */
    private function sendMail(SecurityAlertMail $mail): bool
    {
        $recipient = config('security-monitor.alerts.email');

        if (! is_string($recipient) || $recipient === '') {
            $this->components->twoColumnDetail('Correo', 'sin destinatario (SECURITY_MONITOR_ALERT_EMAIL)');

            return true;
        }

        try {
            Mail::to($recipient)->send($mail);
            $this->components->twoColumnDetail('Correo', "enviado a {$recipient}");

            return true;
        } catch (Throwable $exception) {
            report($exception);
            $this->components->error("No se pudo enviar el correo a {$recipient}: {$exception->getMessage()}");

            return false;
        }
    }

    /**
     * Muestra una notificación de escritorio con el resumen de los cambios.
     *
     * @param DesktopNotifier $notifier Notificaciones de escritorio.
     * @param list<CheckRow>  $worsened Chequeos que empeoraron.
     * @param list<CheckRow>  $resolved Chequeos que se resolvieron.
     *
     * @return void
     */
    private function notifyDesktop(DesktopNotifier $notifier, array $worsened, array $resolved): void
    {
        if (! config('security-monitor.alerts.desktop')) {
            return;
        }

        $body = $worsened === []
            ? 'Resueltos: ' . implode(', ', array_column($resolved, 'name')) . '.'
            : implode("\n", array_map(fn (array $check): string => "{$check['label']}: {$check['name']}", $worsened));
        $title = $worsened === []
            ? 'Problemas de seguridad resueltos'
            : count($worsened) . (
                count($worsened) === 1 ? ' problema de seguridad nuevo' : ' problemas de seguridad nuevos'
            );

        $notifier->notify($title, $body, in_array('critical', array_column($worsened, 'status'), true));
    }
}

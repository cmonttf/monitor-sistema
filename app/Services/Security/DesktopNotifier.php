<?php

namespace App\Services\Security;

/**
 * Notificaciones de escritorio: notify-send en Linux y notificaciones nativas de Windows (con PowerShell).
 *
 * @package App\Services\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class DesktopNotifier
{
    /**
     * Identificador de aplicación de Windows PowerShell, necesario para mostrar notificaciones nativas.
     */
    private const string WINDOWS_APP_ID =
        '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe';

    /**
     * Recibe el acceso al sistema y la plataforma.
     *
     * @param SystemInspector $system   Acceso a comandos del sistema.
     * @param Platform        $platform Plataforma en la que corre el monitor.
     */
    public function __construct(private SystemInspector $system, private Platform $platform)
    {
    }

    /**
     * Muestra una notificación de escritorio.
     *
     * @param string $title    Título.
     * @param string $body     Texto.
     * @param bool   $critical true para una notificación urgente (no desaparece sola en Linux).
     *
     * @return bool true si la notificación se envió.
     */
    public function notify(string $title, string $body, bool $critical = false): bool
    {
        if ($this->platform->isWindows()) {
            return ($this->system->powershell($this->windowsScript($title, $body))['ok'] ?? false) === true;
        }

        if (! $this->system->hasCommand('notify-send')) {
            return false;
        }

        return $this->system->run([
            'notify-send',
            '--app-name=Monitor de Seguridad',
            '--icon=security-high',
            '--urgency=' . ($critical ? 'critical' : 'normal'),
            $title,
            $body,
        ])->successful();
    }

    /**
     * Script de PowerShell que muestra una notificación nativa de Windows con el título y el texto.
     *
     * @param string $title Título.
     * @param string $body  Texto.
     *
     * @return string Script de PowerShell.
     */
    public function windowsScript(string $title, string $body): string
    {
        return implode("\n", [
            '$manager = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, '
                . 'ContentType = WindowsRuntime]',
            '$template = $manager::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)',
            "\$texts = \$template.GetElementsByTagName('text')",
            '[void]$texts.Item(0).AppendChild($template.CreateTextNode(' . WindowsAutostart::quote($title) . '))',
            '[void]$texts.Item(1).AppendChild($template.CreateTextNode(' . WindowsAutostart::quote($body) . '))',
            '$toast = [Windows.UI.Notifications.ToastNotification]::new($template)',
            '$manager::CreateToastNotifier(' . WindowsAutostart::quote(self::WINDOWS_APP_ID) . ').Show($toast)',
            '[pscustomobject]@{ ok = $true }',
        ]);
    }
}

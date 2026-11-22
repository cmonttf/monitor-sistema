<?php

namespace App\Mail;

use App\Services\Security\SecurityMonitor;
use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;

/**
 * Correo de alerta: los chequeos que empeoraron (con sus pasos de solución) y los que se resolvieron.
 *
 * @phpstan-import-type CheckRow from SecurityMonitor
 *
 * @package App\Mail
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class SecurityAlertMail extends Mailable
{
    /**
     * Crea el correo de alerta.
     *
     * @param list<CheckRow> $worsened Chequeos que empeoraron a advertencia o crítico.
     * @param list<CheckRow> $resolved Chequeos que volvieron a estar al día.
     * @param string         $hostname Nombre del equipo.
     * @param string         $platform Sistema operativo del equipo.
     * @param bool           $isTest   true para el correo de prueba de la configuración.
     */
    public function __construct(
        public array $worsened,
        public array $resolved,
        public string $hostname,
        public string $platform,
        public bool $isTest = false,
    ) {
    }

    /**
     * Asunto del correo, según la gravedad de lo que cambió.
     *
     * @return Envelope Sobre del correo.
     */
    public function envelope(): Envelope
    {
        $count = count($this->worsened);
        $isCritical = in_array('critical', array_column($this->worsened, 'status'), true);

        $subject = match (true) {
            $this->isTest => "Prueba de alertas del monitor en {$this->hostname}",
            $count === 0 => "Problemas de seguridad resueltos en {$this->hostname}",
            default => ($isCritical ? '🔴 Crítico' : '🟠 Atención') . ": {$count} "
                . ($count === 1 ? 'problema de seguridad' : 'problemas de seguridad') . " en {$this->hostname}",
        };

        return new Envelope(subject: $subject);
    }

    /**
     * Contenido del correo (plantilla Markdown).
     *
     * @return Content Contenido.
     */
    public function content(): Content
    {
        return new Content(markdown: 'mail.security-alert');
    }
}

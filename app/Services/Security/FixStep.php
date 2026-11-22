<?php

namespace App\Services\Security;

/**
 * Paso para solucionar un problema detectado: una explicación y, opcionalmente, el comando a ejecutar.
 *
 * @package App\Services\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
final readonly class FixStep
{
    /**
     * Crea un paso de solución.
     *
     * @param string      $text    Explicación breve del paso.
     * @param string|null $command Comando a ejecutar en una terminal, o null si el paso es sólo una indicación.
     */
    public function __construct(
        public string $text,
        public ?string $command = null,
    ) {
    }

    /**
     * Crea un paso que consiste en ejecutar un comando.
     *
     * @param string $text    Qué hace el comando.
     * @param string $command Comando a ejecutar en una terminal.
     *
     * @return self Paso con comando.
     */
    public static function command(string $text, string $command): self
    {
        return new self($text, $command);
    }

    /**
     * Crea un paso que es sólo una indicación, sin comando.
     *
     * @param string $text Indicación para el usuario.
     *
     * @return self Paso sin comando.
     */
    public static function note(string $text): self
    {
        return new self($text);
    }

    /**
     * Convierte el paso al formato del reporte JSON.
     *
     * @return array{text: string, command: string|null} Explicación y comando.
     */
    public function toArray(): array
    {
        return ['text' => $this->text, 'command' => $this->command];
    }
}

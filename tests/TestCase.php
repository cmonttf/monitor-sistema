<?php

namespace Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Symfony\Component\Process\Process;

/**
 * Clase base de las pruebas de la aplicación.
 *
 * @package Tests
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
abstract class TestCase extends BaseTestCase
{
    /**
     * Patrón de Process::fake para un comando ejecutado como array. Usa el mismo escapado que Symfony
     * aplica al armar la línea de comandos (comillas simples en Linux, otro formato en Windows), para que
     * las pruebas funcionen en ambos sistemas.
     *
     * @param string $command Comando con argumentos separados por espacios.
     *
     * @return string Línea de comandos tal como la ejecutaría el proceso.
     */
    protected static function command(string $command): string
    {
        return (new Process(explode(' ', $command)))->getCommandLine();
    }
}

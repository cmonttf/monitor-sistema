<?php

namespace UCSC\Sniffs\Functions;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Detecta parámetros obligatorios declarados después de parámetros opcionales o nulables con valor por defecto.
 *
 * PHP 8 marca esa firma como obsoleta (incluido "?int $id = null" antes de un obligatorio desde PHP 8.3);
 * el parámetro opcional debe moverse al final y deben actualizarse todas las llamadas.
 *
 * @package UCSC\Sniffs\Functions
 * @author  Camilo Montt Fierro <cmonttf@gmail.com>
 */
class ParametrosOpcionalesAlFinalSniff implements Sniff
{
    /**
     * Registra declaraciones de funciones, métodos, closures y funciones flecha.
     *
     * @return array<int, int|string> Tokens que activan el sniff.
     */
    public function register()
    {
        return [T_FUNCTION, T_CLOSURE, T_FN];
    }

    /**
     * Informa cada parámetro obligatorio que aparece después de uno opcional.
     *
     * @param File $archivoAnalizado Archivo que se está analizando.
     * @param int  $posicionToken    Posición de la declaración de la función.
     *
     * @return void
     */
    public function process(File $archivoAnalizado, int $posicionToken)
    {
        $existeParametroOpcionalPrevio = false;
        $nombreUltimoOpcional = '';

        foreach ($archivoAnalizado->getMethodParameters($posicionToken) as $parametroFuncion) {
            if (isset($parametroFuncion['default'])) {
                $existeParametroOpcionalPrevio = true;
                $nombreUltimoOpcional = $parametroFuncion['name'];
                continue;
            }

            if ($existeParametroOpcionalPrevio && $parametroFuncion['variable_length'] === false) {
                $archivoAnalizado->addError(
                    'El parámetro obligatorio %s está después del opcional %s (obsoleto en PHP 8). '
                        . 'Mover el opcional al final y actualizar las llamadas.',
                    $parametroFuncion['token'],
                    'OpcionalAntesDeObligatorio',
                    [$parametroFuncion['name'], $nombreUltimoOpcional]
                );
            }
        }
    }
}

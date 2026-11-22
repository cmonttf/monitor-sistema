<?php

namespace UCSC\Sniffs\Commenting;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Exige un bloque PHPDoc antes de cada constante declarada en una clase, interfaz, trait o enum.
 *
 * Las constantes representan reglas o valores estables del sistema; su significado debe quedar
 * documentado donde se declaran para no depender del nombre como única explicación.
 *
 * @package UCSC\Sniffs\Commenting
 * @author  Camilo Montt Fierro <cmonttf@gmail.com>
 */
class ConstantesClaseComentadasSniff implements Sniff
{
    /**
     * Tokens que pueden aparecer entre el PHPDoc y la palabra clave const.
     */
    private const TOKENS_MODIFICADORES_CONSTANTE = [
        T_WHITESPACE,
        T_PUBLIC,
        T_PROTECTED,
        T_PRIVATE,
        T_FINAL,
    ];

    /**
     * Tokens que delimitan un ámbito orientado a objetos.
     */
    private const TOKENS_AMBITO_OBJETOS = [T_CLASS, T_INTERFACE, T_TRAIT, T_ENUM, T_ANON_CLASS];

    /**
     * Registra el token de declaración de constantes.
     *
     * @return array<int, int|string> Tokens que activan el sniff.
     */
    public function register()
    {
        return [T_CONST];
    }

    /**
     * Informa un error cuando una constante de clase no tiene PHPDoc inmediatamente anterior.
     *
     * @param File $archivoAnalizado Archivo que se está analizando.
     * @param int  $posicionToken    Posición del token const en la pila de tokens.
     *
     * @return void
     */
    public function process(File $archivoAnalizado, int $posicionToken)
    {
        $tokensArchivo = $archivoAnalizado->getTokens();
        $condicionesToken = $tokensArchivo[$posicionToken]['conditions'];

        if ($condicionesToken === [] || !in_array(end($condicionesToken), self::TOKENS_AMBITO_OBJETOS, true)) {
            return;
        }

        $posicionAnterior = $archivoAnalizado->findPrevious(
            self::TOKENS_MODIFICADORES_CONSTANTE,
            $posicionToken - 1,
            null,
            true
        );

        while ($posicionAnterior !== false && $tokensArchivo[$posicionAnterior]['code'] === T_ATTRIBUTE_END) {
            $posicionAnterior = $archivoAnalizado->findPrevious(
                self::TOKENS_MODIFICADORES_CONSTANTE,
                $tokensArchivo[$posicionAnterior]['attribute_opener'] - 1,
                null,
                true
            );
        }

        if ($posicionAnterior !== false && $tokensArchivo[$posicionAnterior]['code'] === T_DOC_COMMENT_CLOSE_TAG) {
            return;
        }

        $posicionNombre = $archivoAnalizado->findNext(T_STRING, $posicionToken + 1);
        $archivoAnalizado->addError(
            'La constante de clase %s debe tener un bloque PHPDoc que explique su significado.',
            $posicionToken,
            'FaltaDocumentacion',
            [$posicionNombre === false ? '' : $tokensArchivo[$posicionNombre]['content']]
        );
    }
}

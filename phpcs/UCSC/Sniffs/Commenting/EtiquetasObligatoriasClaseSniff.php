<?php

namespace UCSC\Sniffs\Commenting;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Exige PHPDoc de clase con @package igual al namespace real y @author con nombre y correo.
 *
 * @package UCSC\Sniffs\Commenting
 * @author  Camilo Montt Fierro <cmonttf@gmail.com>
 */
class EtiquetasObligatoriasClaseSniff implements Sniff
{
    /**
     * Tokens que pueden aparecer entre el PHPDoc y la declaración de la clase.
     */
    private const TOKENS_MODIFICADORES_CLASE = [T_WHITESPACE, T_FINAL, T_ABSTRACT, T_READONLY];

    /**
     * Expresión regular que valida un correo electrónico dentro de la etiqueta @author.
     */
    private const PATRON_CORREO_AUTOR = '/[\w.+-]+@[\w-]+(\.[\w-]+)+/';

    /**
     * Registra las declaraciones de clases, interfaces, traits y enums.
     *
     * @return array<int, int|string> Tokens que activan el sniff.
     */
    public function register()
    {
        return [T_CLASS, T_INTERFACE, T_TRAIT, T_ENUM];
    }

    /**
     * Valida la existencia del PHPDoc de clase y de sus etiquetas @package y @author.
     *
     * @param File $archivoAnalizado Archivo que se está analizando.
     * @param int  $posicionToken    Posición del token de declaración en la pila de tokens.
     *
     * @return void
     */
    public function process(File $archivoAnalizado, int $posicionToken)
    {
        $tokensArchivo = $archivoAnalizado->getTokens();
        $posicionCierreDocumentacion = $this->buscarCierreDocumentacionClase($archivoAnalizado, $posicionToken);

        if ($posicionCierreDocumentacion === null) {
            $archivoAnalizado->addError(
                'La declaración debe tener PHPDoc con descripción, @package y @author.',
                $posicionToken,
                'FaltaDocumentacion'
            );

            return;
        }

        $etiquetasDocumentacion = $this->obtenerEtiquetasDocumentacion(
            $tokensArchivo,
            $tokensArchivo[$posicionCierreDocumentacion]['comment_opener'],
            $posicionCierreDocumentacion
        );
        $namespaceArchivo = $this->obtenerNamespaceArchivo($archivoAnalizado, $posicionToken);

        if (!isset($etiquetasDocumentacion['@package'])) {
            $archivoAnalizado->addError(
                'Falta la etiqueta @package en el PHPDoc de clase.',
                $posicionToken,
                'FaltaPackage'
            );
        } elseif ($namespaceArchivo !== '' && $etiquetasDocumentacion['@package'] !== $namespaceArchivo) {
            $archivoAnalizado->addError(
                '@package "%s" no coincide con el namespace real "%s".',
                $posicionToken,
                'PackageDistintoNamespace',
                [$etiquetasDocumentacion['@package'], $namespaceArchivo]
            );
        }

        if (!isset($etiquetasDocumentacion['@author'])) {
            $archivoAnalizado->addError(
                'Falta la etiqueta @author en el PHPDoc de clase.',
                $posicionToken,
                'FaltaAutor'
            );
        } elseif (preg_match(self::PATRON_CORREO_AUTOR, $etiquetasDocumentacion['@author']) !== 1) {
            $archivoAnalizado->addError(
                '@author debe incluir nombre y correo electrónico.',
                $posicionToken,
                'AutorSinCorreo'
            );
        }
    }

    /**
     * Busca el cierre del PHPDoc que precede a la declaración, saltando modificadores y atributos.
     *
     * @param File $archivoAnalizado Archivo que se está analizando.
     * @param int  $posicionToken    Posición del token de declaración.
     *
     * @return int|null Posición del cierre del PHPDoc, o null si la declaración no está documentada.
     */
    private function buscarCierreDocumentacionClase(File $archivoAnalizado, int $posicionToken): ?int
    {
        $tokensArchivo = $archivoAnalizado->getTokens();
        $posicionAnterior = $archivoAnalizado->findPrevious(
            self::TOKENS_MODIFICADORES_CLASE,
            $posicionToken - 1,
            null,
            true
        );

        while ($posicionAnterior !== false && $tokensArchivo[$posicionAnterior]['code'] === T_ATTRIBUTE_END) {
            $posicionAnterior = $archivoAnalizado->findPrevious(
                self::TOKENS_MODIFICADORES_CLASE,
                $tokensArchivo[$posicionAnterior]['attribute_opener'] - 1,
                null,
                true
            );
        }

        if ($posicionAnterior === false || $tokensArchivo[$posicionAnterior]['code'] !== T_DOC_COMMENT_CLOSE_TAG) {
            return null;
        }

        return $posicionAnterior;
    }

    /**
     * Obtiene las etiquetas de un bloque PHPDoc con el texto que las acompaña.
     *
     * @param array<int, array<string, mixed>> $tokensArchivo     Pila de tokens del archivo.
     * @param int                              $posicionApertura  Posición de apertura del PHPDoc.
     * @param int                              $posicionCierre    Posición de cierre del PHPDoc.
     *
     * @return array<string, string> Texto de cada etiqueta indexado por su nombre (por ejemplo @package).
     */
    private function obtenerEtiquetasDocumentacion(
        array $tokensArchivo,
        int $posicionApertura,
        int $posicionCierre
    ): array {
        $etiquetasDocumentacion = [];

        for ($posicion = $posicionApertura; $posicion < $posicionCierre; $posicion++) {
            if ($tokensArchivo[$posicion]['code'] !== T_DOC_COMMENT_TAG) {
                continue;
            }

            $textoEtiqueta = '';
            $posicionTexto = $posicion + 2;
            if (
                isset($tokensArchivo[$posicionTexto])
                && $tokensArchivo[$posicionTexto]['code'] === T_DOC_COMMENT_STRING
                && $tokensArchivo[$posicionTexto]['line'] === $tokensArchivo[$posicion]['line']
            ) {
                $textoEtiqueta = trim($tokensArchivo[$posicionTexto]['content']);
            }

            $etiquetasDocumentacion[$tokensArchivo[$posicion]['content']] = $textoEtiqueta;
        }

        return $etiquetasDocumentacion;
    }

    /**
     * Obtiene el namespace declarado en el archivo antes de la posición indicada.
     *
     * @param File $archivoAnalizado Archivo que se está analizando.
     * @param int  $posicionToken    Posición de la declaración de clase.
     *
     * @return string Namespace completo, o cadena vacía si el archivo no declara namespace.
     */
    private function obtenerNamespaceArchivo(File $archivoAnalizado, int $posicionToken): string
    {
        $tokensArchivo = $archivoAnalizado->getTokens();
        $posicionNamespace = $archivoAnalizado->findPrevious(T_NAMESPACE, $posicionToken - 1);

        if ($posicionNamespace === false) {
            return '';
        }

        $posicionFin = $archivoAnalizado->findNext([T_SEMICOLON, T_OPEN_CURLY_BRACKET], $posicionNamespace);

        $cantidadTokensNombre = $posicionFin - $posicionNamespace - 1;

        return trim($archivoAnalizado->getTokensAsString($posicionNamespace + 1, $cantidadTokensNombre));
    }
}

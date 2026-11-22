<?php

namespace Tests\Feature\Security;

use App\Services\Security\CheckResult;
use App\Services\Security\Checks\SecurityCheck;
use Throwable;

/**
 * Chequeo de prueba que devuelve (o lanza) los resultados en cola.
 *
 * @package Tests\Feature\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class FakeCheck implements SecurityCheck
{
    /**
     * Resultados o excepciones que entregarán las próximas ejecuciones, en orden.
     *
     * @var list<CheckResult|Throwable>
     */
    public static array $results = [];

    /**
     * Nombre visible del chequeo de prueba.
     *
     * @return string Nombre del chequeo.
     */
    public function name(): string
    {
        return 'Chequeo de prueba';
    }

    /**
     * Categoría del chequeo de prueba.
     *
     * @return string Nombre de la categoría.
     */
    public function category(): string
    {
        return 'Pruebas';
    }

    /**
     * Entrega el siguiente resultado en cola, o un resultado correcto si la cola está vacía.
     *
     * @return CheckResult Resultado en cola.
     *
     * @throws Throwable Cuando el siguiente elemento de la cola es una excepción.
     */
    public function run(): CheckResult
    {
        $result = array_shift(self::$results) ?? CheckResult::ok('Sin datos de prueba');

        if ($result instanceof Throwable) {
            throw $result;
        }

        return $result;
    }
}

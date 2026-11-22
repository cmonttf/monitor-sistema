<?php

namespace Tests\Feature\Security;

use App\Services\Security\CheckResult;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * Pruebas de que el panel sólo responde al propio equipo: nombres de host locales (contra DNS rebinding)
 * y clientes de loopback.
 *
 * @package Tests\Feature\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class LocalAccessTest extends TestCase
{
    /**
     * Deja un chequeo simulado como único chequeo configurado.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        FakeCheck::$results = [];
        config(['security-monitor.checks' => [FakeCheck::class]]);
    }

    /**
     * Rutas del monitor que deben estar protegidas.
     *
     * @return array<string, array{string}> Caso => [ruta].
     */
    public static function protectedPaths(): array
    {
        return [
            'panel' => ['/'],
            'estado' => ['/estado'],
            'recursos' => ['/recursos'],
            'salud' => ['/up'],
        ];
    }

    /**
     * Un dominio externo que resuelve a 127.0.0.1 (DNS rebinding) no puede leer el panel.
     *
     * @param string $path Ruta solicitada.
     *
     * @return void
     */
    #[DataProvider('protectedPaths')]
    public function test_foreign_host_header_is_rejected(string $path): void
    {
        $response = $this->get("http://atacante.example:8787{$path}");

        $response->assertForbidden();
        $this->assertStringNotContainsString('Chequeo de prueba', (string) $response->getContent());
    }

    /**
     * Una conexión desde otro equipo se rechaza aunque falsifique el encabezado Host.
     *
     * @param string $path Ruta solicitada.
     *
     * @return void
     */
    #[DataProvider('protectedPaths')]
    public function test_remote_client_is_rejected(string $path): void
    {
        $response = $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.50'])->get("http://127.0.0.1:8787{$path}");

        $response->assertForbidden();
    }

    /**
     * Una solicitud con un host no permitido no llega a ejecutar los chequeos.
     *
     * @return void
     */
    public function test_rejected_request_does_not_run_checks(): void
    {
        FakeCheck::$results = [CheckResult::critical('No debería ejecutarse')];

        $this->get('http://atacante.example/estado?refresh=1');

        $this->assertCount(1, FakeCheck::$results);
    }

    /**
     * El propio equipo accede con 127.0.0.1, localhost o [::1].
     *
     * @return void
     */
    public function test_local_hosts_are_allowed(): void
    {
        FakeCheck::$results = [CheckResult::ok('Bien'), CheckResult::ok('Bien'), CheckResult::ok('Bien')];

        $this->getJson('http://127.0.0.1:8787/estado')->assertOk();
        $this->getJson('http://localhost:8787/estado?refresh=1')->assertOk();
        $this->withServerVariables(['REMOTE_ADDR' => '::1'])->getJson('http://[::1]:8787/estado?refresh=1')->assertOk();
    }
}

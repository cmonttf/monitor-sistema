<?php

namespace Tests\Feature\Security;

use App\Services\Security\CheckResult;
use RuntimeException;
use Tests\TestCase;

/**
 * Pruebas del panel y del endpoint de estado con chequeos simulados.
 *
 * @package Tests\Feature\Security
 * @author  Camilo Montt <cmonttf@gmail.com>
 */
class SecurityDashboardTest extends TestCase
{
    /**
     * Reinicia la cola del chequeo simulado y lo deja como único chequeo configurado.
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
     * El panel se muestra y el contenido del reporte llega escapado (sin HTML inyectado).
     *
     * @return void
     */
    public function test_dashboard_page_renders_the_report(): void
    {
        FakeCheck::$results = [CheckResult::critical('Cortafuegos <b>apagado</b>')];

        $response = $this->get(route('security.dashboard'));

        $response->assertOk();
        $response->assertSee('Verificar ahora');
        $response->assertSee('Chequeo de prueba');
        $response->assertDontSee('Cortafuegos <b>apagado</b>', false);
    }

    /**
     * El estado global es el peor de los chequeos y el resumen cuenta cada estado.
     *
     * @return void
     */
    public function test_status_endpoint_reports_the_worst_status_and_a_summary(): void
    {
        config(['security-monitor.checks' => [FakeCheck::class, FakeCheck::class, FakeCheck::class]]);
        FakeCheck::$results = [
            CheckResult::ok('Bien'),
            CheckResult::critical('Mal', ['detalle']),
            CheckResult::warning('Regular'),
        ];

        $response = $this->getJson(route('security.status'));

        $response->assertOk();
        $response->assertJsonPath('overall.status', 'critical');
        $response->assertJsonPath('overall.label', 'Crítico');
        $response->assertJsonPath('summary', ['ok' => 1, 'warning' => 1, 'critical' => 1, 'unknown' => 0]);
        $response->assertJsonPath('checks.1', [
            'key' => 'fake-check',
            'name' => 'Chequeo de prueba',
            'category' => 'Pruebas',
            'status' => 'critical',
            'label' => 'Crítico',
            'message' => 'Mal',
            'details' => ['detalle'],
        ]);
    }

    /**
     * Un chequeo que lanza una excepción queda sin datos y no impide ejecutar los demás.
     *
     * @return void
     */
    public function test_a_failing_check_is_reported_as_unknown_without_breaking_the_others(): void
    {
        config(['security-monitor.checks' => [FakeCheck::class, FakeCheck::class]]);
        FakeCheck::$results = [new RuntimeException('comando no encontrado'), CheckResult::ok('Bien')];

        $response = $this->getJson(route('security.status'));

        $response->assertOk();
        $response->assertJsonPath('checks.0.status', 'unknown');
        $response->assertJsonPath('checks.0.details', ['comando no encontrado']);
        $response->assertJsonPath('checks.1.status', 'ok');
        $response->assertJsonPath('overall.status', 'unknown');
    }

    /**
     * El reporte se sirve desde la caché hasta que se pide ?refresh=1.
     *
     * @return void
     */
    public function test_status_is_cached_until_a_refresh_is_requested(): void
    {
        FakeCheck::$results = [
            CheckResult::ok('Primero'),
            CheckResult::warning('Segundo'),
            CheckResult::critical('Tercero'),
        ];

        $this->getJson(route('security.status'))->assertJsonPath('checks.0.message', 'Primero');
        $this->getJson(route('security.status'))->assertJsonPath('checks.0.message', 'Primero');
        $this->getJson(route('security.status', ['refresh' => 1]))->assertJsonPath('checks.0.message', 'Segundo');
    }
}

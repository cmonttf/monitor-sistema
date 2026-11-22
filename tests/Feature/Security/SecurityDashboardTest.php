<?php

namespace Tests\Feature\Security;

use App\Services\Security\CheckResult;
use App\Services\Security\Checks\SecurityCheck;
use RuntimeException;
use Tests\TestCase;

class SecurityDashboardTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        FakeCheck::$results = [];
        config(['security-monitor.checks' => [FakeCheck::class]]);
    }

    public function test_dashboard_page_renders_the_report(): void
    {
        FakeCheck::$results = [CheckResult::critical('Cortafuegos <b>apagado</b>')];

        $response = $this->get(route('security.dashboard'));

        $response->assertOk();
        $response->assertSee('Verificar ahora');
        $response->assertSee('Chequeo de prueba');
        $response->assertDontSee('Cortafuegos <b>apagado</b>', false);
    }

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

    public function test_status_is_cached_until_a_refresh_is_requested(): void
    {
        FakeCheck::$results = [CheckResult::ok('Primero'), CheckResult::warning('Segundo'), CheckResult::critical('Tercero')];

        $this->getJson(route('security.status'))->assertJsonPath('checks.0.message', 'Primero');
        $this->getJson(route('security.status'))->assertJsonPath('checks.0.message', 'Primero');
        $this->getJson(route('security.status', ['refresh' => 1]))->assertJsonPath('checks.0.message', 'Segundo');
    }
}

/**
 * Chequeo de prueba que devuelve (o lanza) los resultados en cola.
 */
class FakeCheck implements SecurityCheck
{
    /**
 * @var list<CheckResult|\Throwable>
*/
    public static array $results = [];

    public function name(): string
    {
        return 'Chequeo de prueba';
    }

    public function category(): string
    {
        return 'Pruebas';
    }

    public function run(): CheckResult
    {
        $result = array_shift(self::$results) ?? CheckResult::ok('Sin datos de prueba');

        if ($result instanceof \Throwable) {
            throw $result;
        }

        return $result;
    }
}

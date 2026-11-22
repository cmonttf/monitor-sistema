<?php

namespace App\Console\Commands;

use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Sleep;

/**
 * Espera a que el servidor del monitor responda y abre el panel en el navegador.
 *
 * @package App\Console\Commands
 */
#[Signature('monitor:open {--wait=60 : Segundos máximos de espera al servidor}')]
#[Description('Abre el monitor de seguridad en el navegador predeterminado')]
class OpenDashboardCommand extends Command
{
    /**
     * Ejecuta el comando.
     *
     * @return int
     */
    public function handle(): int
    {
        $baseUrl = 'http://'.config('security-monitor.host').':'.config('security-monitor.port');

        if (! $this->waitForServer($baseUrl, (int) $this->option('wait'))) {
            $this->components->error("El monitor no responde en {$baseUrl}. Revisa: systemctl --user status ".InstallAutostartCommand::SERVICE_NAME);

            return self::FAILURE;
        }

        Process::run(['sh', '-c', 'setsid xdg-open "$1" >/dev/null 2>&1 &', 'sh', $baseUrl]);

        return self::SUCCESS;
    }

    /**
     * @return bool
     */
    private function waitForServer(string $baseUrl, int $seconds): bool
    {
        for ($attempt = 0; $attempt <= $seconds; $attempt++) {
            try {
                if (Http::timeout(2)->get($baseUrl.'/up')->successful()) {
                    return true;
                }
            } catch (ConnectionException) {
                // El servidor aún no está escuchando.
            }

            Sleep::for(1)->second();
        }

        return false;
    }
}

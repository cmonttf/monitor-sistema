<?php

use Illuminate\Support\Facades\Schedule;

/*
|--------------------------------------------------------------------------
| Tareas programadas
|--------------------------------------------------------------------------
|
| Revisión periódica del equipo con avisos por correo y al escritorio cuando
| algún elemento de seguridad empeora (ver config/security-monitor.php).
|
*/

Schedule::command('monitor:alert')
    ->cron('*/' . config('security-monitor.alerts.minutes') . ' * * * *')
    ->withoutOverlapping(30);

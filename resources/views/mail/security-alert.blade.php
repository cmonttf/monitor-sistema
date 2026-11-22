<x-mail::message>
@if ($isTest)
# Las alertas funcionan

Este es un correo de prueba del **Monitor de Seguridad** de **{{ $hostname }}** ({{ $platform }}). Desde ahora recibirás un aviso cuando algún elemento de seguridad empeore.
@else
# {{ count($worsened) > 0 ? 'Cambios en la seguridad de ' . $hostname : 'Problemas resueltos en ' . $hostname }}

{{ $platform }} · {{ now()->format('d-m-Y H:i') }}
@endif

@foreach ($worsened as $check)
## {{ $check['status'] === 'critical' ? '🔴' : '🟠' }} {{ $check['name'] }}

**{{ $check['label'] }}** — {{ $check['message'] }}

@if (count($check['fix']) > 0)
**Cómo solucionarlo:**

@foreach ($check['fix'] as $step)
{{ $loop->iteration }}. {{ $step['text'] }}@if ($step['command'])<br>`{{ $step['command'] }}`@endif

@endforeach
@endif
@endforeach

@if (count($resolved) > 0)
## 🟢 Resueltos

@foreach ($resolved as $check)
- **{{ $check['name'] }}**: {{ $check['message'] }}
@endforeach
@endif

<x-mail::subcopy>
Revisa el detalle en el panel del monitor, en el propio equipo: {{ 'http://' . config('security-monitor.host') . ':' . config('security-monitor.port') }}
</x-mail::subcopy>
</x-mail::message>

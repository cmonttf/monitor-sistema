<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ config('app.name') }}</title>
    <link rel="icon" id="favicon" href="data:,">
    <script>
        {{-- Modo claro u oscuro según el sistema, antes de pintar para evitar parpadeos. --}}
        (() => {
            const query = window.matchMedia('(prefers-color-scheme: dark)');
            const apply = () => document.documentElement.setAttribute('data-bs-theme', query.matches ? 'dark' : 'light');
            apply();
            query.addEventListener('change', apply);
        })();
    </script>
    @vite('resources/js/dashboard.js')
</head>
<body>
    <div
        id="app"
        data-app-name="{{ config('app.name') }}"
        data-hostname="{{ gethostname() }}"
        data-status-url="{{ route('security.status') }}"
        data-resources-url="{{ route('security.resources') }}"
        data-refresh-ms="{{ $refreshSeconds * 1000 }}"
        data-resources-refresh-ms="{{ $resourcesRefreshSeconds * 1000 }}"
        data-history-ms="{{ $resourcesHistoryMinutes * 60 * 1000 }}"
        data-thresholds="{{ json_encode($resourceThresholds) }}"
        data-report="{{ json_encode($report) }}"
    >
        <noscript>
            <div class="container py-4">El panel necesita JavaScript habilitado.</div>
        </noscript>
    </div>
</body>
</html>

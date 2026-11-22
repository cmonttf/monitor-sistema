<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ config('app.name') }}</title>
    <link rel="icon" id="favicon" href="data:,">
    @vite('resources/js/resources-monitor.js')
    <style>
        :root {
            --bg: #f3f5f8;
            --surface: #ffffff;
            --text: #1b2330;
            --muted: #5d6878;
            --border: #dfe4ea;
            --ok: #1f9d55;
            --ok-soft: #e3f6eb;
            --warning: #c77700;
            --warning-soft: #fff3dc;
            --critical: #d42a2a;
            --critical-soft: #fde6e6;
            --unknown: #6b7280;
            --unknown-soft: #eceef1;
            --series: #2a78d6;
            --series-track: #cde2fb;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg: #0f141b;
                --surface: #18202b;
                --text: #e6ebf2;
                --muted: #98a3b3;
                --border: #29323f;
                --ok: #3ccf7a;
                --ok-soft: #12301f;
                --warning: #f0a83a;
                --warning-soft: #3a2a10;
                --critical: #ff6363;
                --critical-soft: #3d1717;
                --unknown: #9aa3af;
                --unknown-soft: #262d38;
                --series: #3987e5;
                --series-track: #1c3557;
            }
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Ubuntu, sans-serif;
        }

        .container { max-width: 1200px; margin: 0 auto; padding: 24px 16px 48px; }

        header {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
        }

        h1 { margin: 0; font-size: 1.5rem; }
        .subtitle { color: var(--muted); font-size: .9rem; }

        button {
            border: 1px solid var(--border);
            background: var(--surface);
            color: var(--text);
            padding: 8px 16px;
            border-radius: 8px;
            font: inherit;
            cursor: pointer;
        }
        button:hover { border-color: var(--muted); }
        button:disabled { opacity: .6; cursor: progress; }

        .banner {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 18px 20px;
            border-radius: 12px;
            margin-bottom: 16px;
            background: var(--status-soft);
            border: 1px solid var(--status);
        }
        .banner .icon { width: 44px; height: 44px; font-size: 1.4rem; }
        .banner strong { display: block; font-size: 1.15rem; color: var(--status); }

        .summary { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 28px; }
        .chip {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 12px;
            border-radius: 999px;
            background: var(--surface);
            border: 1px solid var(--border);
            font-size: .9rem;
        }
        .chip .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--status); }

        h2 {
            font-size: .8rem;
            text-transform: uppercase;
            letter-spacing: .08em;
            color: var(--muted);
            margin: 28px 0 10px;
        }

        .grid {
            display: grid;
            gap: 12px;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            align-items: start;
        }

        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-left: 5px solid var(--status);
            border-radius: 10px;
            padding: 14px 16px;
        }
        .card-head { display: flex; align-items: flex-start; gap: 12px; }
        .card-title { font-weight: 600; flex: 1; }
        .card-message { margin: 6px 0 0 44px; color: var(--muted); }

        .icon {
            flex: none;
            display: grid;
            place-items: center;
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: var(--status-soft);
            color: var(--status);
            font-weight: 700;
        }

        .badge {
            flex: none;
            font-size: .75rem;
            font-weight: 600;
            padding: 2px 10px;
            border-radius: 999px;
            background: var(--status-soft);
            color: var(--status);
        }

        details { margin: 8px 0 0 44px; font-size: .88rem; }
        summary { cursor: pointer; color: var(--muted); }
        details ul { margin: 6px 0 0; padding-left: 18px; }
        details li { word-break: break-word; font-family: ui-monospace, "Ubuntu Mono", monospace; }

        .fix {
            margin: 10px 0 0 44px;
            padding: 10px 12px;
            border-radius: 8px;
            background: var(--status-soft);
            font-size: .88rem;
        }
        .fix-title { font-weight: 600; color: var(--status); margin-bottom: 6px; }
        .fix ol { margin: 0; padding-left: 20px; }
        .fix li + li { margin-top: 8px; }
        .command {
            display: flex;
            align-items: stretch;
            margin-top: 4px;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: var(--surface);
            overflow: hidden;
        }
        .command code {
            flex: 1;
            padding: 6px 8px;
            font-family: ui-monospace, "Ubuntu Mono", monospace;
            font-size: .82rem;
            overflow-wrap: anywhere;
        }
        .command button {
            flex: none;
            border: 0;
            border-left: 1px solid var(--border);
            border-radius: 0;
            padding: 4px 10px;
            font-size: .78rem;
        }

        .status-ok { --status: var(--ok); --status-soft: var(--ok-soft); }
        .status-warning { --status: var(--warning); --status-soft: var(--warning-soft); }
        .status-critical { --status: var(--critical); --status-soft: var(--critical-soft); }
        .status-unknown { --status: var(--unknown); --status-soft: var(--unknown-soft); }

        .status-critical.banner .icon { animation: pulse 1.6s ease-in-out infinite; }
        @keyframes pulse { 50% { transform: scale(1.12); } }
        @media (prefers-reduced-motion: reduce) { .status-critical.banner .icon { animation: none; } }

        .error { color: var(--critical); font-size: .9rem; margin-top: 4px; }

        /* Recursos en vivo */
        .resources { margin-bottom: 8px; }
        .resource-body { margin: 10px 0 0 44px; }
        .resource-figure { font-size: .95rem; color: var(--muted); margin-bottom: 8px; }
        .resource-figure strong { font-size: 1.35rem; color: var(--text); font-weight: 600; margin-right: 4px; }
        .resource-facts {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
            gap: 6px 16px;
            margin: 10px 0 0;
            font-size: .85rem;
        }
        .resource-facts dt { color: var(--muted); }
        .resource-facts dd { margin: 0; font-weight: 600; }
        .disk-row + .disk-row { margin-top: 12px; }
        .disk-head { display: flex; justify-content: space-between; gap: 8px; font-size: .88rem; margin-bottom: 4px; }
        .disk-name { font-weight: 600; font-family: ui-monospace, "Ubuntu Mono", monospace; }
        .disk-value { color: var(--muted); text-align: right; }

        .meter { height: 8px; border-radius: 999px; background: var(--series-track); overflow: hidden; }
        .meter span { display: block; height: 100%; border-radius: inherit; background: var(--series); }
        .meter[data-level="warning"] { background: var(--warning-soft); }
        .meter[data-level="warning"] span { background: var(--warning); }
        .meter[data-level="critical"] { background: var(--critical-soft); }
        .meter[data-level="critical"] span { background: var(--critical); }

        .chart-card { grid-column: 1 / -1; border-left-width: 1px; }
        .chart-head { display: flex; flex-wrap: wrap; gap: 8px; align-items: flex-start; justify-content: space-between; }
        .chart-subtitle { color: var(--muted); font-size: .85rem; }
        .range { display: inline-flex; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
        .range button { border: 0; border-radius: 0; padding: 4px 12px; font-size: .85rem; }
        .range button + button { border-left: 1px solid var(--border); }
        .range button[aria-pressed="true"] { background: var(--series); color: #fff; }
        .chart { position: relative; margin-top: 12px; min-height: 220px; outline-offset: 4px; }
        .chart svg { display: block; overflow: visible; }
        .chart text { font-size: 12px; fill: var(--muted); }
        .chart .grid { stroke: var(--border); stroke-width: 1; }
        .chart .area { fill: var(--series); opacity: .1; }
        .chart .line { fill: none; stroke: var(--series); stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
        .chart .end-dot, .chart .cross-dot { fill: var(--series); stroke: var(--surface); stroke-width: 2; }
        .chart .end-label { fill: var(--text); font-weight: 600; }
        .chart .cross { stroke: var(--muted); stroke-width: 1; }
        .chart-empty { position: absolute; inset: 0; display: grid; place-items: center; margin: 0; color: var(--muted); }
        .chart-tooltip {
            position: absolute;
            top: 8px;
            pointer-events: none;
            min-width: 150px;
            padding: 8px 10px;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--surface);
            box-shadow: 0 4px 14px rgb(0 0 0 / 12%);
            font-size: .82rem;
        }
        .chart-tooltip .tooltip-time { color: var(--muted); margin-bottom: 2px; }
        .chart-tooltip .tooltip-value { font-weight: 600; }
        .chart-stats { margin: 8px 0 0; color: var(--muted); font-size: .85rem; }
        .chart-card details { margin-left: 0; }
        .chart-card table { border-collapse: collapse; margin-top: 6px; font-size: .85rem; }
        .chart-card th, .chart-card td { padding: 3px 14px 3px 0; text-align: left; }
        .chart-card th { color: var(--muted); font-weight: 600; }
    </style>
</head>
<body>
<div class="container">
    <header>
        <div>
            <h1>🛡️ {{ config('app.name') }}</h1>
            <div class="subtitle">
                Equipo <strong>{{ gethostname() }}</strong> · {{ $report['platform'] }} · <span id="updated">—</span>
            </div>
            <div class="error" id="error" hidden></div>
        </div>
        <button type="button" id="refresh">Verificar ahora</button>
    </header>

    <main id="app">
        <div id="overview"></div>

        <h2>Recursos</h2>
        <div
            id="resources-monitor"
            data-url="{{ route('security.resources') }}"
            data-refresh-ms="{{ $resourcesRefreshSeconds * 1000 }}"
            data-history-ms="{{ $resourcesHistoryMinutes * 60 * 1000 }}"
            data-thresholds="{{ json_encode($resourceThresholds) }}"
        ></div>

        <div id="sections"></div>
    </main>
</div>

<script>
    const STATUS_URL = @json(route('security.status'));
    const REFRESH_MS = @json($refreshSeconds * 1000);
    const APP_NAME = @json(config('app.name'));
    let report = @json($report);

    const ICONS = { ok: '✓', warning: '!', critical: '✕', unknown: '?' };
    const COLORS = { ok: '#1f9d55', warning: '#c77700', critical: '#d42a2a', unknown: '#6b7280' };
    const BANNERS = {
        ok: ['Todo en orden', 'Todos los elementos de seguridad están al día.'],
        warning: ['Requiere atención', 'Hay elementos que conviene revisar.'],
        critical: ['Problemas críticos', 'Hay elementos de seguridad desactualizados o desactivados.'],
        unknown: ['Estado incompleto', 'Algunos elementos no se pudieron verificar.'],
    };
    const SEVERITY = { critical: 3, warning: 2, unknown: 1, ok: 0 };
    const RESOURCES_CATEGORY = 'Recursos';

    const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => (
        { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]
    ));

    function renderFix(steps) {
        if (!steps || !steps.length) {
            return '';
        }

        const items = steps.map((step) => {
            const command = step.command
                ? `<div class="command"><code>${escapeHtml(step.command)}</code><button type="button" class="copy" data-command="${escapeHtml(step.command)}">Copiar</button></div>`
                : '';
            return `<li>${escapeHtml(step.text)}${command}</li>`;
        }).join('');

        return `<div class="fix"><div class="fix-title">Cómo solucionarlo</div><ol>${items}</ol></div>`;
    }

    function renderCard(check) {
        const details = check.details.length
            ? `<details><summary>Detalles (${check.details.length})</summary><ul>${check.details.map((d) => `<li>${escapeHtml(d)}</li>`).join('')}</ul></details>`
            : '';
        const fix = check.status === 'ok' ? '' : renderFix(check.fix);

        return `
            <article class="card status-${check.status}">
                <div class="card-head">
                    <span class="icon">${ICONS[check.status]}</span>
                    <span class="card-title">${escapeHtml(check.name)}</span>
                    <span class="badge">${escapeHtml(check.label)}</span>
                </div>
                <p class="card-message">${escapeHtml(check.message)}</p>
                ${fix}
                ${details}
            </article>`;
    }

    function render() {
        const status = report.overall.status;
        const [title, text] = BANNERS[status];
        const categories = [...new Set(report.checks.map((c) => c.category))]
            .filter((category) => category !== RESOURCES_CATEGORY);

        const chips = ['critical', 'warning', 'unknown', 'ok']
            .filter((s) => report.summary[s] > 0)
            .map((s) => {
                const label = report.checks.find((c) => c.status === s).label;
                return `<span class="chip status-${s}"><span class="dot"></span>${report.summary[s]} ${escapeHtml(label)}</span>`;
            }).join('');

        const sections = categories.map((category) => {
            const cards = report.checks
                .filter((c) => c.category === category)
                .sort((a, b) => SEVERITY[b.status] - SEVERITY[a.status])
                .map(renderCard).join('');
            return `<h2>${escapeHtml(category)}</h2><section class="grid">${cards}</section>`;
        }).join('');

        document.getElementById('overview').innerHTML = `
            <div class="banner status-${status}">
                <span class="icon">${ICONS[status]}</span>
                <div><strong>${title}</strong>${text}</div>
            </div>
            <div class="summary">${chips}</div>`;
        document.getElementById('sections').innerHTML = sections;

        const alerts = (report.summary.critical || 0) + (report.summary.warning || 0);
        document.title = (alerts ? `(${alerts}) ` : '') + APP_NAME;
        setFavicon(COLORS[status]);
        renderUpdated();
    }

    function setFavicon(color) {
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="${color}"/></svg>`;
        document.getElementById('favicon').href = 'data:image/svg+xml,' + encodeURIComponent(svg);
    }

    function renderUpdated() {
        const date = new Date(report.generated_at);
        document.getElementById('updated').textContent =
            'Última verificación: ' + date.toLocaleString('es-CL', { dateStyle: 'short', timeStyle: 'medium' });
    }

    async function load(fresh = false) {
        const button = document.getElementById('refresh');
        const error = document.getElementById('error');

        if (fresh) {
            button.disabled = true;
            button.textContent = 'Verificando…';
        }

        try {
            const response = await fetch(STATUS_URL + (fresh ? '?refresh=1' : ''), { headers: { Accept: 'application/json' } });
            if (!response.ok) {
                throw new Error('HTTP ' + response.status);
            }
            report = await response.json();
            error.hidden = true;
            render();
        } catch (e) {
            error.textContent = 'No se pudo contactar al monitor (' + e.message + '). Se reintentará automáticamente.';
            error.hidden = false;
        } finally {
            button.disabled = false;
            button.textContent = 'Verificar ahora';
        }
    }

    async function copyCommand(button) {
        try {
            await navigator.clipboard.writeText(button.dataset.command);
            button.textContent = 'Copiado ✓';
        } catch (e) {
            button.textContent = 'Selecciona y copia';
        }
        setTimeout(() => { button.textContent = 'Copiar'; }, 2000);
    }

    document.getElementById('app').addEventListener('click', (event) => {
        const button = event.target.closest('button.copy');
        if (button) {
            copyCommand(button);
        }
    });
    document.getElementById('refresh').addEventListener('click', () => load(true));
    setInterval(() => load(), REFRESH_MS);
    render();
</script>
</body>
</html>

<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ config('app.name') }}</title>
    <link rel="icon" id="favicon" href="data:,">
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

        .grid { display: grid; gap: 12px; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); }

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

        .status-ok { --status: var(--ok); --status-soft: var(--ok-soft); }
        .status-warning { --status: var(--warning); --status-soft: var(--warning-soft); }
        .status-critical { --status: var(--critical); --status-soft: var(--critical-soft); }
        .status-unknown { --status: var(--unknown); --status-soft: var(--unknown-soft); }

        .status-critical.banner .icon { animation: pulse 1.6s ease-in-out infinite; }
        @keyframes pulse { 50% { transform: scale(1.12); } }
        @media (prefers-reduced-motion: reduce) { .status-critical.banner .icon { animation: none; } }

        .error { color: var(--critical); font-size: .9rem; margin-top: 4px; }
    </style>
</head>
<body>
<div class="container">
    <header>
        <div>
            <h1>🛡️ {{ config('app.name') }}</h1>
            <div class="subtitle">
                Equipo <strong>{{ gethostname() }}</strong> · <span id="updated">—</span>
            </div>
            <div class="error" id="error" hidden></div>
        </div>
        <button type="button" id="refresh">Verificar ahora</button>
    </header>

    <main id="app"></main>
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

    const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => (
        { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]
    ));

    function renderCard(check) {
        const details = check.details.length
            ? `<details><summary>Detalles (${check.details.length})</summary><ul>${check.details.map((d) => `<li>${escapeHtml(d)}</li>`).join('')}</ul></details>`
            : '';

        return `
            <article class="card status-${check.status}">
                <div class="card-head">
                    <span class="icon">${ICONS[check.status]}</span>
                    <span class="card-title">${escapeHtml(check.name)}</span>
                    <span class="badge">${escapeHtml(check.label)}</span>
                </div>
                <p class="card-message">${escapeHtml(check.message)}</p>
                ${details}
            </article>`;
    }

    function render() {
        const status = report.overall.status;
        const [title, text] = BANNERS[status];
        const categories = [...new Set(report.checks.map((c) => c.category))];

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

        document.getElementById('app').innerHTML = `
            <div class="banner status-${status}">
                <span class="icon">${ICONS[status]}</span>
                <div><strong>${title}</strong>${text}</div>
            </div>
            <div class="summary">${chips}</div>
            ${sections}`;

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

    document.getElementById('refresh').addEventListener('click', () => load(true));
    setInterval(() => load(), REFRESH_MS);
    render();
</script>
</body>
</html>

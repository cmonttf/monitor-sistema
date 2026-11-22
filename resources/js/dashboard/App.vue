<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import AttackTimeline from './AttackTimeline.vue';
import CheckCard from './CheckCard.vue';
import ResourcesMonitor from './ResourcesMonitor.vue';
import { STATUS_ICONS, STATUS_SEVERITY, STATUS_VARIANTS } from './status.js';

/**
 * Panel completo: encabezado, aviso con el estado global, resumen por estado, recursos en tiempo real y
 * las tarjetas de seguridad agrupadas por categoría. Consulta /estado periódicamente.
 */
const props = defineProps({
    appName: { type: String, required: true },
    hostname: { type: String, required: true },
    statusUrl: { type: String, required: true },
    resourcesUrl: { type: String, required: true },
    attacksUrl: { type: String, required: true },
    attacksRefreshMs: { type: Number, required: true },
    refreshMs: { type: Number, required: true },
    resourcesRefreshMs: { type: Number, required: true },
    historyMs: { type: Number, required: true },
    thresholds: { type: Object, required: true },
    initialReport: { type: Object, required: true },
    alerts: { type: Object, required: true },
});

const RESOURCES_CATEGORY = 'Recursos';
const ATTACKS_CATEGORY = 'Detección de ataques';
const BANNERS = {
    ok: ['Todo en orden', 'Todos los elementos de seguridad están al día.'],
    warning: ['Requiere atención', 'Hay elementos que conviene revisar.'],
    critical: ['Problemas críticos', 'Hay elementos de seguridad desactualizados o desactivados.'],
    unknown: ['Estado incompleto', 'Algunos elementos no se pudieron verificar.'],
};
const FAVICON_COLORS = { ok: '#198754', warning: '#ffc107', critical: '#dc3545', unknown: '#6c757d' };

const report = ref(props.initialReport);

const alertsSummary = computed(() => {
    const { enabled, minutes, email, mailConfigured, desktop } = props.alerts;

    if (!enabled) {
        return { text: 'Alertas desactivadas', warn: true };
    }

    const channels = [];
    if (email) {
        channels.push(mailConfigured ? `correo a ${email}` : 'correo sin configurar (MAIL_MAILER en .env)');
    }
    if (desktop) {
        channels.push('escritorio');
    }

    return {
        text: `Alertas cada ${minutes} min: ${channels.length ? channels.join(' · ') : 'sin canales'}`,
        warn: !channels.length || (email && !mailConfigured),
    };
});
const isRefreshing = ref(false);
const error = ref(null);
let timer = null;

const status = computed(() => report.value.overall.status);
const banner = computed(() => BANNERS[status.value]);
const checkedAt = computed(() => new Date(report.value.generated_at)
    .toLocaleString('es-CL', { dateStyle: 'short', timeStyle: 'medium' }));

const summary = computed(() => ['critical', 'warning', 'unknown', 'ok']
    .filter((key) => report.value.summary[key] > 0)
    .map((key) => ({
        key,
        count: report.value.summary[key],
        label: report.value.checks.find((check) => check.status === key)?.label ?? key,
    })));

const sections = computed(() => {
    const categories = [...new Set(report.value.checks.map((check) => check.category))]
        .filter((category) => category !== RESOURCES_CATEGORY);

    return categories.map((category) => ({
        category,
        checks: report.value.checks
            .filter((check) => check.category === category)
            .sort((a, b) => STATUS_SEVERITY[b.status] - STATUS_SEVERITY[a.status]),
    }));
});

/**
 * Consulta el estado; con fresh vuelve a ejecutar los chequeos en el servidor.
 *
 * @param {boolean} fresh true para forzar una verificación nueva.
 */
async function load(fresh = false) {
    isRefreshing.value = fresh;

    try {
        const response = await fetch(props.statusUrl + (fresh ? '?refresh=1' : ''), {
            headers: { Accept: 'application/json' },
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        report.value = await response.json();
        error.value = null;
    } catch (exception) {
        error.value = exception.message;
    } finally {
        isRefreshing.value = false;
    }
}

/**
 * Actualiza el título de la pestaña (con la cantidad de alertas) y el ícono con el color del estado.
 */
function updateTabIndicators() {
    const alerts = (report.value.summary.critical || 0) + (report.value.summary.warning || 0);
    document.title = (alerts ? `(${alerts}) ` : '') + props.appName;

    const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
        + `<path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="${FAVICON_COLORS[status.value]}"/></svg>`;
    document.getElementById('favicon').href = 'data:image/svg+xml,' + encodeURIComponent(svg);
}

watch(report, updateTabIndicators);

onMounted(() => {
    updateTabIndicators();
    timer = setInterval(() => load(), props.refreshMs);
});

onBeforeUnmount(() => clearInterval(timer));
</script>

<template>
    <div class="container-xl py-4">
        <header class="d-flex flex-wrap justify-content-between align-items-center gap-3 mb-4">
            <div>
                <h1 class="h3 mb-1">🛡️ {{ appName }}</h1>
                <div class="small text-body-secondary">
                    Equipo <strong>{{ hostname }}</strong> · {{ report.platform }} · Última verificación: {{ checkedAt }}
                </div>
                <div class="small" :class="alertsSummary.warn ? 'text-warning-emphasis' : 'text-body-secondary'">
                    🔔 {{ alertsSummary.text }}
                </div>
            </div>
            <button type="button" class="btn btn-outline-secondary" :disabled="isRefreshing" @click="load(true)">
                <span v-if="isRefreshing" class="spinner-border spinner-border-sm me-1" aria-hidden="true"></span>
                {{ isRefreshing ? 'Verificando…' : 'Verificar ahora' }}
            </button>
        </header>

        <div v-if="error" class="alert alert-danger py-2" role="alert">
            No se pudo contactar al monitor ({{ error }}). Se reintentará automáticamente.
        </div>

        <div class="alert d-flex align-items-center gap-3" :class="`alert-${STATUS_VARIANTS[status]}`" role="status">
            <span class="status-icon status-icon-lg" :class="`bg-${STATUS_VARIANTS[status]} text-white`" aria-hidden="true">
                {{ STATUS_ICONS[status] }}
            </span>
            <div>
                <div class="fw-semibold fs-5">{{ banner[0] }}</div>
                <div>{{ banner[1] }}</div>
            </div>
        </div>

        <div class="d-flex flex-wrap gap-2 mb-4">
            <span
                v-for="item in summary"
                :key="item.key"
                class="badge rounded-pill fs-6 fw-normal"
                :class="`text-bg-${STATUS_VARIANTS[item.key]}`"
            >
                {{ item.count }} {{ item.label }}
            </span>
        </div>

        <h2 class="section-title">Recursos</h2>
        <ResourcesMonitor
            :url="resourcesUrl"
            :refresh-ms="resourcesRefreshMs"
            :history-ms="historyMs"
            :thresholds="thresholds"
        />

        <section v-for="section in sections" :key="section.category">
            <h2 class="section-title">{{ section.category }}</h2>
            <AttackTimeline
                v-if="section.category === ATTACKS_CATEGORY"
                :url="attacksUrl"
                :refresh-ms="attacksRefreshMs"
            />
            <div class="row row-cols-1 row-cols-md-2 row-cols-xl-3 g-3">
                <div v-for="check in section.checks" :key="check.key" class="col">
                    <CheckCard :check="check" />
                </div>
            </div>
        </section>
    </div>
</template>

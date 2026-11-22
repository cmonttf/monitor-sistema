<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import RamChart from './RamChart.vue';
import CheckCard from './CheckCard.vue';
import UsageMeter from './UsageMeter.vue';
import { formatBytes, formatTime } from './format.js';

/**
 * Monitor de recursos en tiempo real: consulta /recursos cada pocos segundos, guarda el historial de RAM
 * en el navegador y muestra las tarjetas de memoria y disco y el gráfico.
 */
const props = defineProps({
    url: { type: String, required: true },
    refreshMs: { type: Number, required: true },
    historyMs: { type: Number, required: true },
    thresholds: { type: Object, required: true },
});

const WINDOWS = [
    { minutes: 1, label: '1 min' },
    { minutes: 5, label: '5 min' },
    { minutes: 15, label: '15 min' },
];
const WINDOW_STORAGE_KEY = 'monitor-ram-window';
const TABLE_ROWS = 10;

const latest = ref(null);
const samples = ref([]);
const error = ref(null);
const windowMinutes = ref(readStoredWindow());
let timer = null;
let isFetching = false;

const memory = computed(() => latest.value?.memory ?? null);
const disks = computed(() => latest.value?.disks ?? []);
const memoryCheck = computed(() => latest.value?.checks.find((check) => check.key === 'memory-check') ?? null);
const diskCheck = computed(() => latest.value?.checks.find((check) => check.key === 'disk-space-check') ?? null);
const windowMs = computed(() => Math.min(windowMinutes.value * 60000, props.historyMs));

const memoryPercent = computed(() => (memory.value ? (memory.value.used / memory.value.total) * 100 : 0));
const memoryLevel = computed(() => levelFor(memoryPercent.value, props.thresholds.memory));
const swapLabel = computed(() => {
    if (!memory.value || memory.value.swap_total === 0) {
        return 'no configurada';
    }

    return `${formatBytes(memory.value.swap_used)} de ${formatBytes(memory.value.swap_total)}`;
});

const windowSamples = computed(() => {
    const end = samples.value.at(-1)?.t ?? 0;

    return samples.value.filter((sample) => sample.t >= end - windowMs.value);
});

const stats = computed(() => {
    const used = windowSamples.value.map((sample) => sample.used);

    if (used.length < 2) {
        return null;
    }

    return {
        min: Math.min(...used),
        max: Math.max(...used),
        average: used.reduce((sum, value) => sum + value, 0) / used.length,
    };
});

const tableRows = computed(() => samples.value.slice(-TABLE_ROWS).reverse());

/**
 * Nivel de un medidor de uso según los umbrales de advertencia y crítico (en porcentaje usado).
 *
 * @param {number} usedPercent Porcentaje usado.
 * @param {{warning: number, critical: number}} limits Umbrales.
 * @returns {string} normal, warning o critical.
 */
function levelFor(usedPercent, limits) {
    if (usedPercent >= limits.critical) {
        return 'critical';
    }

    return usedPercent >= limits.warning ? 'warning' : 'normal';
}

/**
 * Nivel de un disco con las mismas reglas que DiskSpaceCheck en PHP.
 *
 * @param {object} disk Disco de la muestra.
 * @returns {string} normal, warning o critical.
 */
function diskLevel(disk) {
    const limits = props.thresholds.disk;
    const freePercent = 100 - disk.used_percent;
    const isNearlyFull = disk.size >= limits.absolute_min_size && disk.available < limits.critical_free_bytes;

    if (freePercent < limits.critical_free_percent || isNearlyFull) {
        return 'critical';
    }

    return freePercent < limits.warning_free_percent ? 'warning' : 'normal';
}

/**
 * Lee la ventana de tiempo elegida antes; el almacenamiento puede no estar disponible.
 *
 * @returns {number} Minutos de la ventana.
 */
function readStoredWindow() {
    try {
        const stored = Number(localStorage.getItem(WINDOW_STORAGE_KEY));
        return WINDOWS.some((option) => option.minutes === stored) ? stored : 5;
    } catch {
        return 5;
    }
}

/**
 * Cambia la ventana de tiempo del gráfico y la recuerda para la próxima visita.
 *
 * @param {number} minutes Minutos de la ventana.
 */
function selectWindow(minutes) {
    windowMinutes.value = minutes;
    try {
        localStorage.setItem(WINDOW_STORAGE_KEY, String(minutes));
    } catch {
        // Sin almacenamiento disponible: la elección dura sólo esta visita.
    }
}

/**
 * Toma una muestra de /recursos, la agrega al historial y descarta las que salieron de la ventana máxima.
 * No lanza una consulta nueva mientras la anterior siga en curso.
 */
async function takeSample() {
    if (isFetching) {
        return;
    }

    isFetching = true;

    try {
        const response = await fetch(props.url, { headers: { Accept: 'application/json' } });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        const now = Date.now();
        latest.value = data;
        error.value = null;

        if (data.memory) {
            samples.value = [
                ...samples.value.filter((sample) => sample.t >= now - props.historyMs),
                { t: now, used: data.memory.used, total: data.memory.total, available: data.memory.available },
            ];
        }
    } catch (exception) {
        error.value = exception.message;
    } finally {
        isFetching = false;
    }
}

onMounted(() => {
    takeSample();
    timer = setInterval(takeSample, props.refreshMs);
});

onBeforeUnmount(() => clearInterval(timer));
</script>

<template>
    <div class="row row-cols-1 row-cols-md-2 g-3">
        <div class="col">
            <CheckCard title="Memoria RAM" :check="memoryCheck" :show-message="false" :show-details="false">
                <template v-if="memory">
                    <div class="mt-3 mb-2 text-body-secondary">
                        <span class="fs-4 fw-semibold text-body me-1">{{ formatBytes(memory.used) }}</span>
                        en uso de {{ formatBytes(memory.total) }} ({{ Math.round(memoryPercent) }} %)
                    </div>
                    <UsageMeter :percent="memoryPercent" :level="memoryLevel" label="RAM en uso" />
                    <dl class="row row-cols-3 g-2 small mt-2 mb-0">
                        <div class="col">
                            <dt class="fw-normal text-body-secondary">Disponible</dt>
                            <dd class="fw-semibold mb-0">{{ formatBytes(memory.available) }}</dd>
                        </div>
                        <div v-if="memory.cached !== null" class="col">
                            <dt class="fw-normal text-body-secondary">Caché liberable</dt>
                            <dd class="fw-semibold mb-0">{{ formatBytes(memory.cached) }}</dd>
                        </div>
                        <div class="col">
                            <dt class="fw-normal text-body-secondary">Swap</dt>
                            <dd class="fw-semibold mb-0">{{ swapLabel }}</dd>
                        </div>
                    </dl>
                </template>
                <p v-else class="text-body-secondary mt-3 mb-0">Cargando…</p>
            </CheckCard>
        </div>

        <div class="col">
            <CheckCard title="Espacio en disco" :check="diskCheck" :show-message="false" :show-details="false">
                <div v-for="disk in disks" :key="disk.device" class="mt-3">
                    <div class="d-flex justify-content-between gap-2 small mb-1">
                        <span class="fw-semibold font-monospace">{{ disk.mount }}</span>
                        <span class="text-body-secondary text-end">
                            <strong class="text-body">{{ formatBytes(disk.available) }}</strong>
                            libres de {{ formatBytes(disk.size) }}
                        </span>
                    </div>
                    <UsageMeter
                        :percent="disk.used_percent"
                        :level="diskLevel(disk)"
                        :label="`Espacio usado en ${disk.mount}`"
                    />
                </div>
                <p v-if="!disks.length" class="text-body-secondary mt-3 mb-0">Cargando…</p>
            </CheckCard>
        </div>

        <div class="col-12 w-100">
            <article class="card shadow-sm">
                <div class="card-body">
                    <div class="d-flex flex-wrap justify-content-between align-items-start gap-2">
                        <div>
                            <h3 class="h6 card-title mb-0">RAM en uso, en tiempo real</h3>
                            <div class="small text-body-secondary">
                                Una muestra cada {{ refreshMs / 1000 }} s · el historial se conserva mientras el
                                panel esté abierto
                            </div>
                        </div>
                        <div class="btn-group btn-group-sm" role="group" aria-label="Ventana de tiempo del gráfico">
                            <button
                                v-for="option in WINDOWS"
                                :key="option.minutes"
                                type="button"
                                class="btn"
                                :class="windowMinutes === option.minutes ? 'btn-primary' : 'btn-outline-primary'"
                                :aria-pressed="windowMinutes === option.minutes"
                                @click="selectWindow(option.minutes)"
                            >
                                {{ option.label }}
                            </button>
                        </div>
                    </div>

                    <RamChart :samples="samples" :window-ms="windowMs" />

                    <p v-if="stats" class="small text-body-secondary mt-2 mb-0">
                        Últimos {{ windowMinutes }} min: mínimo {{ formatBytes(stats.min) }} · promedio
                        {{ formatBytes(stats.average) }} · máximo {{ formatBytes(stats.max) }}
                    </p>
                    <div v-if="error" class="alert alert-danger py-1 px-2 small mt-2 mb-0">
                        No se pudo leer la memoria ({{ error }}); se reintentará.
                    </div>

                    <details class="mt-2 small">
                        <summary class="text-body-secondary">Ver tabla de las últimas muestras</summary>
                        <table class="table table-sm table-borderless w-auto mt-1 mb-0">
                            <thead>
                                <tr>
                                    <th scope="col">Hora</th>
                                    <th scope="col">En uso</th>
                                    <th scope="col">%</th>
                                    <th scope="col">Disponible</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-for="sample in tableRows" :key="sample.t">
                                    <td>{{ formatTime(sample.t) }}</td>
                                    <td>{{ formatBytes(sample.used) }}</td>
                                    <td>{{ Math.round((sample.used / sample.total) * 100) }} %</td>
                                    <td>{{ formatBytes(sample.available) }}</td>
                                </tr>
                            </tbody>
                        </table>
                    </details>
                </div>
            </article>
        </div>
    </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import AttackChart from './AttackChart.vue';
import { ATTACK_TYPES, ATTACK_WINDOWS } from './attackTypes.js';

/**
 * Actividad de ataques en tiempo real: consulta /ataques periódicamente, agrupa los eventos en intervalos
 * según la ventana elegida y muestra el gráfico, la leyenda con los totales y una tabla.
 */
const props = defineProps({
    url: { type: String, required: true },
    refreshMs: { type: Number, required: true },
});

const WINDOW_STORAGE_KEY = 'monitor-attack-window';

const events = ref([]);
const unavailable = ref([]);
const serverNow = ref(Math.floor(Date.now() / 1000));
const error = ref(null);
const windowHours = ref(readStoredWindow());
let timer = null;
let isFetching = false;

const selectedWindow = computed(() => ATTACK_WINDOWS.find((option) => option.hours === windowHours.value));

const buckets = computed(() => {
    const size = selectedWindow.value.bucketMinutes * 60;
    const count = Math.round((windowHours.value * 3600) / size);
    const end = Math.ceil(serverNow.value / size) * size;
    const start = end - count * size;
    const list = Array.from({ length: count }, (_, index) => ({
        start: start + index * size,
        end: start + (index + 1) * size,
        total: 0,
        counts: Object.fromEntries(ATTACK_TYPES.map((type) => [type.key, 0])),
    }));

    for (const event of events.value) {
        const index = Math.floor((event.t - start) / size);
        if (index >= 0 && index < count && event.type in list[index].counts) {
            list[index].counts[event.type] += 1;
            list[index].total += 1;
        }
    }

    return list;
});

const totals = computed(() => Object.fromEntries(ATTACK_TYPES.map((type) => [
    type.key,
    buckets.value.reduce((sum, bucket) => sum + bucket.counts[type.key], 0),
])));

const activeRows = computed(() => buckets.value.filter((bucket) => bucket.total > 0).reverse());

/**
 * Lee la ventana elegida antes; el almacenamiento puede no estar disponible.
 *
 * @returns {number} Horas de la ventana.
 */
function readStoredWindow() {
    try {
        const stored = Number(localStorage.getItem(WINDOW_STORAGE_KEY));
        return ATTACK_WINDOWS.some((option) => option.hours === stored) ? stored : 6;
    } catch {
        return 6;
    }
}

/**
 * Cambia la ventana del gráfico y la recuerda para la próxima visita.
 *
 * @param {number} hours Horas de la ventana.
 */
function selectWindow(hours) {
    windowHours.value = hours;
    try {
        localStorage.setItem(WINDOW_STORAGE_KEY, String(hours));
    } catch {
        // Sin almacenamiento disponible: la elección dura sólo esta visita.
    }
}

/**
 * Consulta la actividad de ataques; no lanza una consulta nueva mientras la anterior siga en curso.
 */
async function load() {
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
        events.value = data.events;
        unavailable.value = data.unavailable;
        serverNow.value = data.now;
        error.value = null;
    } catch (exception) {
        error.value = exception.message;
    } finally {
        isFetching = false;
    }
}

/**
 * Formatea el rango horario de un intervalo para la tabla.
 *
 * @param {object} bucket Intervalo.
 * @returns {string} Rango horario.
 */
function rangeLabel(bucket) {
    const format = (timestamp) => new Date(timestamp * 1000)
        .toLocaleString('es-CL', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    return `${format(bucket.start)} – ${format(bucket.end).slice(-5)}`;
}

onMounted(() => {
    load();
    timer = setInterval(load, props.refreshMs);
});

onBeforeUnmount(() => clearInterval(timer));
</script>

<template>
    <article class="card shadow-sm mb-3">
        <div class="card-body">
            <div class="d-flex flex-wrap justify-content-between align-items-start gap-2">
                <div>
                    <h3 class="h6 card-title mb-0">Actividad de ataques, en tiempo real</h3>
                    <div class="small text-body-secondary">
                        Eventos por intervalo de {{ selectedWindow.bucketMinutes }} min · se actualiza cada
                        {{ refreshMs / 1000 }} s
                    </div>
                </div>
                <div class="btn-group btn-group-sm" role="group" aria-label="Ventana de tiempo del gráfico de ataques">
                    <button
                        v-for="option in ATTACK_WINDOWS"
                        :key="option.hours"
                        type="button"
                        class="btn"
                        :class="windowHours === option.hours ? 'btn-primary' : 'btn-outline-primary'"
                        :aria-pressed="windowHours === option.hours"
                        @click="selectWindow(option.hours)"
                    >
                        {{ option.label }}
                    </button>
                </div>
            </div>

            <ul class="list-inline small mt-2 mb-0" aria-label="Leyenda">
                <li v-for="type in ATTACK_TYPES" :key="type.key" class="list-inline-item me-3">
                    <span class="legend-swatch me-1" :style="{ background: type.color }"></span>
                    {{ type.label }}:
                    <span v-if="unavailable.includes(type.key)" class="text-body-secondary">sin datos</span>
                    <strong v-else>{{ totals[type.key] }}</strong>
                </li>
            </ul>

            <AttackChart :buckets="buckets" :window-hours="windowHours" />

            <p v-if="unavailable.length" class="small text-body-secondary mt-2 mb-0">
                «Sin datos»: el sistema no permite leer ese registro sin permisos de administrador o no lo tiene activado
                (ver la tarjeta correspondiente).
            </p>
            <div v-if="error" class="alert alert-danger py-1 px-2 small mt-2 mb-0">
                No se pudo leer la actividad de ataques ({{ error }}); se reintentará.
            </div>

            <details class="mt-2 small">
                <summary class="text-body-secondary">Ver tabla de intervalos con actividad</summary>
                <p v-if="!activeRows.length" class="mt-1 mb-0 text-body-secondary">No hubo eventos en esta ventana.</p>
                <table v-else class="table table-sm table-borderless w-auto mt-1 mb-0">
                    <thead>
                        <tr>
                            <th scope="col">Intervalo</th>
                            <th v-for="type in ATTACK_TYPES" :key="type.key" scope="col">{{ type.label }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for="bucket in activeRows" :key="bucket.start">
                            <td>{{ rangeLabel(bucket) }}</td>
                            <td v-for="type in ATTACK_TYPES" :key="type.key">{{ bucket.counts[type.key] }}</td>
                        </tr>
                    </tbody>
                </table>
            </details>
        </div>
    </article>
</template>

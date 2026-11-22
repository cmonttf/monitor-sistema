<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { GB, formatBytes, formatTime } from './format.js';

/**
 * Gráfico de área de la RAM en uso a lo largo del tiempo. Una sola serie, eje Y de 0 al total de RAM,
 * etiqueta con el valor actual en la punta y línea de lectura con tooltip al pasar el cursor
 * (o con las flechas del teclado).
 */
const props = defineProps({
    samples: { type: Array, required: true },
    windowMs: { type: Number, required: true },
});

const HEIGHT = 220;
const MARGIN = { top: 22, right: 76, bottom: 26, left: 56 };
const TOOLTIP_WIDTH = 180;
const X_TICK_STEPS = { 60000: 15000, 300000: 60000, 900000: 300000 };
const Y_TICK_STEPS_GB = [1, 2, 4, 5, 8, 10, 16, 20, 32, 50, 64, 100, 128, 256, 512];

const container = ref(null);
const width = ref(640);
const hoverTime = ref(null);
let resizeObserver = null;

onMounted(() => {
    resizeObserver = new ResizeObserver(([entry]) => {
        width.value = Math.max(280, Math.floor(entry.contentRect.width));
    });
    resizeObserver.observe(container.value);
});

onBeforeUnmount(() => resizeObserver?.disconnect());

const end = computed(() => props.samples.at(-1)?.t ?? Date.now());
const start = computed(() => end.value - props.windowMs);
const visible = computed(() => props.samples.filter((sample) => sample.t >= start.value));
const last = computed(() => visible.value.at(-1) ?? null);
const total = computed(() => last.value?.total ?? GB);
const plotWidth = computed(() => width.value - MARGIN.left - MARGIN.right);
const plotBottom = HEIGHT - MARGIN.bottom;

const x = (timestamp) => MARGIN.left + ((timestamp - start.value) / props.windowMs) * plotWidth.value;
const y = (bytes) => MARGIN.top + (1 - bytes / total.value) * (plotBottom - MARGIN.top);

const yTicks = computed(() => {
    const rawStep = total.value / GB / 4;
    const step = (Y_TICK_STEPS_GB.find((candidate) => candidate >= rawStep) ?? 1024) * GB;
    const ticks = [];

    for (let value = 0; value < total.value; value += step) {
        if (y(value) - y(total.value) < 14) {
            break;
        }
        ticks.push({ value, y: y(value), label: `${(value / GB).toLocaleString('es-CL')} GB` });
    }

    return ticks;
});

const xTicks = computed(() => {
    const step = X_TICK_STEPS[props.windowMs] ?? props.windowMs / 4;
    const ticks = [];

    for (let ago = 0; ago <= props.windowMs; ago += step) {
        ticks.push({
            ago,
            x: x(end.value - ago),
            anchor: ago === 0 ? 'end' : ago === props.windowMs ? 'start' : 'middle',
            label: ago === 0 ? 'ahora' : ago < 60000 ? `−${ago / 1000} s` : `−${ago / 60000} min`,
        });
    }

    return ticks;
});

const points = computed(() => visible.value.map((sample) => [x(sample.t), y(sample.used)]));

const linePath = computed(() => {
    if (points.value.length < 2) {
        return '';
    }

    return 'M' + points.value.map(([px, py]) => `${px.toFixed(1)},${py.toFixed(1)}`).join('L');
});

const areaPath = computed(() => {
    if (points.value.length < 2) {
        return '';
    }

    const first = points.value[0];
    const lastPoint = points.value.at(-1);

    return `${linePath.value}L${lastPoint[0].toFixed(1)},${plotBottom}L${first[0].toFixed(1)},${plotBottom}Z`;
});

const hovered = computed(() => visible.value.find((sample) => sample.t === hoverTime.value) ?? null);

const tooltipStyle = computed(() => {
    const px = hovered.value ? x(hovered.value.t) : 0;
    const left = px + 12 + TOOLTIP_WIDTH > width.value ? px - 12 - TOOLTIP_WIDTH : px + 12;

    return { left: `${Math.max(0, left)}px`, width: `${TOOLTIP_WIDTH}px` };
});

const ariaLabel = computed(() => (last.value
    ? `RAM en uso: ${formatBytes(last.value.used)} de ${formatBytes(last.value.total)}. `
        + 'Usa las flechas izquierda y derecha para recorrer las muestras.'
    : 'Recolectando datos de RAM.'));

/**
 * Selecciona la muestra más cercana al puntero (la línea de lectura encuentra la X, no hay que
 * apuntar a la línea).
 *
 * @param {PointerEvent} event Movimiento del puntero sobre el gráfico.
 */
function onPointerMove(event) {
    const pointerX = event.clientX - container.value.getBoundingClientRect().left;
    let nearest = null;
    let distance = Infinity;

    for (const sample of visible.value) {
        const current = Math.abs(x(sample.t) - pointerX);
        if (current < distance) {
            distance = current;
            nearest = sample;
        }
    }

    hoverTime.value = nearest?.t ?? null;
}

/**
 * Recorre las muestras con las flechas; Escape oculta la lectura.
 *
 * @param {KeyboardEvent} event Tecla presionada con el gráfico enfocado.
 */
function onKeydown(event) {
    const list = visible.value;

    if (event.key === 'Escape') {
        hoverTime.value = null;
        return;
    }

    if (!list.length || (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight')) {
        return;
    }

    event.preventDefault();
    const index = list.findIndex((sample) => sample.t === hoverTime.value);
    const lastIndex = list.length - 1;
    const next = index < 0
        ? lastIndex
        : Math.min(lastIndex, Math.max(0, index + (event.key === 'ArrowLeft' ? -1 : 1)));
    hoverTime.value = list[next].t;
}
</script>

<template>
    <div
        ref="container"
        class="chart"
        tabindex="0"
        role="img"
        :aria-label="ariaLabel"
        @pointermove="onPointerMove"
        @pointerleave="hoverTime = null"
        @keydown="onKeydown"
        @blur="hoverTime = null"
    >
        <svg :width="width" :height="HEIGHT" :viewBox="`0 0 ${width} ${HEIGHT}`" aria-hidden="true">
            <g v-for="tick in yTicks" :key="`y${tick.value}`">
                <line class="grid" :x1="MARGIN.left" :x2="width - MARGIN.right" :y1="tick.y" :y2="tick.y" />
                <text :x="MARGIN.left - 8" :y="tick.y" text-anchor="end" dominant-baseline="middle">
                    {{ tick.label }}
                </text>
            </g>

            <line class="grid" :x1="MARGIN.left" :x2="width - MARGIN.right" :y1="y(total)" :y2="y(total)" />
            <text :x="width - MARGIN.right" :y="y(total) - 6" text-anchor="end">Total {{ formatBytes(total) }}</text>

            <text
                v-for="tick in xTicks"
                :key="`x${tick.ago}`"
                :x="tick.x"
                :y="HEIGHT - 6"
                :text-anchor="tick.anchor"
            >
                {{ tick.label }}
            </text>

            <path class="area" :d="areaPath" />
            <path class="line" :d="linePath" />

            <template v-if="last && points.length >= 2">
                <circle class="end-dot" :cx="x(last.t)" :cy="y(last.used)" r="4" />
                <text class="end-label" :x="x(last.t) + 10" :y="y(last.used)" dominant-baseline="middle">
                    {{ formatBytes(last.used) }}
                </text>
            </template>

            <template v-if="hovered">
                <line class="cross" :x1="x(hovered.t)" :x2="x(hovered.t)" :y1="MARGIN.top" :y2="plotBottom" />
                <circle class="cross-dot" :cx="x(hovered.t)" :cy="y(hovered.used)" r="5" />
            </template>
        </svg>

        <p v-if="visible.length < 2" class="chart-empty text-body-secondary">Recolectando datos…</p>

        <div v-if="hovered" class="chart-tooltip card shadow small px-2 py-1" :style="tooltipStyle">
            <div class="text-body-secondary">{{ formatTime(hovered.t) }}</div>
            <div class="fw-semibold">
                En uso: {{ formatBytes(hovered.used) }} ({{ Math.round((hovered.used / hovered.total) * 100) }} %)
            </div>
            <div>Disponible: {{ formatBytes(hovered.available) }}</div>
        </div>
    </div>
</template>

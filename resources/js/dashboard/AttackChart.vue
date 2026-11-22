<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { ATTACK_TYPES } from './attackTypes.js';

/**
 * Barras apiladas de la actividad de ataques: una barra por intervalo de tiempo, con un segmento por tipo
 * de evento separado por un espacio del color del fondo. Al pasar el cursor (o con las flechas del
 * teclado) muestra el detalle del intervalo.
 */
const props = defineProps({
    buckets: { type: Array, required: true },
    windowHours: { type: Number, required: true },
});

const HEIGHT = 200;
const MARGIN = { top: 12, right: 12, bottom: 26, left: 36 };
const MAX_BAR_WIDTH = 24;
const SEGMENT_GAP = 2;
const CORNER = 4;
const TOOLTIP_WIDTH = 230;
const Y_STEPS = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000];

const container = ref(null);
const width = ref(640);
const hoverIndex = ref(null);
let resizeObserver = null;

onMounted(() => {
    resizeObserver = new ResizeObserver(([entry]) => {
        width.value = Math.max(280, Math.floor(entry.contentRect.width));
    });
    resizeObserver.observe(container.value);
});

onBeforeUnmount(() => resizeObserver?.disconnect());

const plotWidth = computed(() => width.value - MARGIN.left - MARGIN.right);
const plotBottom = HEIGHT - MARGIN.bottom;
const slot = computed(() => plotWidth.value / Math.max(1, props.buckets.length));
const barWidth = computed(() => Math.max(2, Math.min(MAX_BAR_WIDTH, slot.value * 0.7)));
const maxTotal = computed(() => Math.max(0, ...props.buckets.map((bucket) => bucket.total)));

const yStep = computed(() => Y_STEPS.find((step) => maxTotal.value / step <= 4) ?? 10000);
const yMax = computed(() => Math.max(yStep.value, Math.ceil(maxTotal.value / yStep.value) * yStep.value));
const y = (value) => plotBottom - (value / yMax.value) * (plotBottom - MARGIN.top);
const yTicks = computed(() => {
    const ticks = [];
    for (let value = 0; value <= yMax.value; value += yStep.value) {
        ticks.push({ value, y: y(value) });
    }
    return ticks;
});

const bars = computed(() => props.buckets.map((bucket, index) => {
    const x = MARGIN.left + index * slot.value + (slot.value - barWidth.value) / 2;
    const present = ATTACK_TYPES.filter((type) => bucket.counts[type.key] > 0);
    let base = 0;

    const segments = present.map((type, position) => {
        const top = base + bucket.counts[type.key];
        const y0 = y(base);
        const y1 = y(top);
        base = top;
        const gap = position > 0 ? SEGMENT_GAP : 0;

        return {
            key: type.key,
            color: type.color,
            path: segmentPath(x, y1, barWidth.value, Math.max(1, y0 - y1 - gap), position === present.length - 1),
        };
    });

    return { index, x, segments };
}));

const xTicks = computed(() => {
    const count = props.buckets.length;
    const every = Math.max(1, Math.round(count / 6));
    const ticks = [];

    for (let index = count - 1; index >= 0; index -= every) {
        const minutesAgo = (count - 1 - index) * (props.windowHours * 60 / count);
        ticks.push({
            index,
            x: MARGIN.left + index * slot.value + slot.value / 2,
            label: index === count - 1 ? 'ahora' : minutesAgo < 60 ? `−${Math.round(minutesAgo)} min` : `−${+(minutesAgo / 60).toFixed(1)} h`,
        });
    }

    return ticks;
});

const hovered = computed(() => (hoverIndex.value === null ? null : props.buckets[hoverIndex.value] ?? null));

const tooltipStyle = computed(() => {
    const center = MARGIN.left + (hoverIndex.value ?? 0) * slot.value + slot.value / 2;
    const left = center + 12 + TOOLTIP_WIDTH > width.value ? center - 12 - TOOLTIP_WIDTH : center + 12;

    return { left: `${Math.max(0, left)}px`, width: `${TOOLTIP_WIDTH}px` };
});

const ariaLabel = computed(() => `Actividad de ataques en las últimas ${props.windowHours} horas: `
    + `${props.buckets.reduce((sum, bucket) => sum + bucket.total, 0)} eventos. `
    + 'Usa las flechas izquierda y derecha para recorrer los intervalos.');

/**
 * Trazado de un segmento: rectángulo con las esquinas superiores redondeadas si es el extremo de la barra
 * (el extremo de los datos), y cuadrado en la base.
 *
 * @param {number} x Borde izquierdo.
 * @param {number} top Borde superior.
 * @param {number} barW Ancho.
 * @param {number} height Alto.
 * @param {boolean} rounded Si redondea las esquinas superiores.
 * @returns {string} Atributo d del trazado SVG.
 */
function segmentPath(x, top, barW, height, rounded) {
    const radius = rounded ? Math.min(CORNER, barW / 2, height) : 0;
    const bottom = top + height;

    return `M${x},${bottom}V${top + radius}Q${x},${top} ${x + radius},${top}`
        + `H${x + barW - radius}Q${x + barW},${top} ${x + barW},${top + radius}V${bottom}Z`;
}

/**
 * Selecciona el intervalo bajo el puntero (toda la columna es el área sensible, no sólo la barra).
 *
 * @param {PointerEvent} event Movimiento del puntero.
 */
function onPointerMove(event) {
    const pointerX = event.clientX - container.value.getBoundingClientRect().left - MARGIN.left;
    const index = Math.floor(pointerX / slot.value);
    hoverIndex.value = index >= 0 && index < props.buckets.length ? index : null;
}

/**
 * Recorre los intervalos con las flechas; Escape oculta el detalle.
 *
 * @param {KeyboardEvent} event Tecla presionada con el gráfico enfocado.
 */
function onKeydown(event) {
    const last = props.buckets.length - 1;

    if (event.key === 'Escape') {
        hoverIndex.value = null;
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {
        event.preventDefault();
        const step = event.key === 'ArrowLeft' ? -1 : 1;
        hoverIndex.value = hoverIndex.value === null ? last : Math.min(last, Math.max(0, hoverIndex.value + step));
    }
}

/**
 * Formatea la hora de inicio y fin de un intervalo.
 *
 * @param {object} bucket Intervalo.
 * @returns {string} Rango horario, por ejemplo «11:30 – 12:00».
 */
function rangeLabel(bucket) {
    const format = (timestamp) => new Date(timestamp * 1000).toLocaleTimeString('es-CL', { hour: '2-digit', minute: '2-digit' });
    return `${format(bucket.start)} – ${format(bucket.end)}`;
}
</script>

<template>
    <div
        ref="container"
        class="chart attack-chart"
        tabindex="0"
        role="img"
        :aria-label="ariaLabel"
        @pointermove="onPointerMove"
        @pointerleave="hoverIndex = null"
        @keydown="onKeydown"
        @blur="hoverIndex = null"
    >
        <svg :width="width" :height="HEIGHT" :viewBox="`0 0 ${width} ${HEIGHT}`" aria-hidden="true">
            <g v-for="tick in yTicks" :key="`y${tick.value}`">
                <line class="grid" :x1="MARGIN.left" :x2="width - MARGIN.right" :y1="tick.y" :y2="tick.y" />
                <text :x="MARGIN.left - 6" :y="tick.y" text-anchor="end" dominant-baseline="middle">{{ tick.value }}</text>
            </g>

            <rect
                v-if="hovered"
                class="column-highlight"
                :x="MARGIN.left + hoverIndex * slot"
                :y="MARGIN.top"
                :width="slot"
                :height="plotBottom - MARGIN.top"
            />

            <g v-for="bar in bars" :key="bar.index">
                <path v-for="segment in bar.segments" :key="segment.key" :d="segment.path" :fill="segment.color" />
            </g>

            <text
                v-for="tick in xTicks"
                :key="`x${tick.index}`"
                :x="tick.x"
                :y="HEIGHT - 6"
                :text-anchor="tick.index === buckets.length - 1 ? 'end' : 'middle'"
            >
                {{ tick.label }}
            </text>
        </svg>

        <p v-if="maxTotal === 0" class="chart-empty text-body-secondary">Sin actividad sospechosa en esta ventana</p>

        <div v-if="hovered" class="chart-tooltip card shadow small px-2 py-1" :style="tooltipStyle">
            <div class="text-body-secondary">{{ rangeLabel(hovered) }}</div>
            <div v-for="type in ATTACK_TYPES" :key="type.key" class="d-flex align-items-center gap-2">
                <span class="legend-swatch" :style="{ background: type.color }"></span>
                <span class="flex-grow-1">{{ type.label }}</span>
                <span class="fw-semibold">{{ hovered.counts[type.key] }}</span>
            </div>
        </div>
    </div>
</template>

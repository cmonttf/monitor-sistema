<script setup>
import { computed } from 'vue';

/**
 * Medidor de uso con la barra de progreso de Bootstrap: azul en uso normal, amarilla en advertencia y
 * roja en crítico; la pista es un tono más claro del mismo color.
 */
const props = defineProps({
    percent: { type: Number, required: true },
    level: { type: String, default: 'normal' },
    label: { type: String, required: true },
});

const LEVEL_CLASSES = { normal: 'meter-normal', warning: 'meter-warning', critical: 'meter-critical' };
const width = computed(() => `${Math.min(100, Math.max(0, props.percent)).toFixed(1)}%`);
</script>

<template>
    <div
        class="progress meter"
        :class="LEVEL_CLASSES[level]"
        role="progressbar"
        :aria-label="label"
        aria-valuemin="0"
        aria-valuemax="100"
        :aria-valuenow="Math.round(percent)"
    >
        <div class="progress-bar" :style="{ width }"></div>
    </div>
</template>

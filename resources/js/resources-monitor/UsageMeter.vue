<script setup>
import { computed } from 'vue';

/**
 * Medidor de uso: el relleno lleva la severidad (normal, advertencia o crítico) y la pista es un tono
 * más claro de la misma rampa.
 */
const props = defineProps({
    percent: { type: Number, required: true },
    level: { type: String, default: 'normal' },
    label: { type: String, required: true },
});

const width = computed(() => `${Math.min(100, Math.max(0, props.percent)).toFixed(1)}%`);
</script>

<template>
    <div
        class="meter"
        role="meter"
        aria-valuemin="0"
        aria-valuemax="100"
        :aria-valuenow="Math.round(percent)"
        :aria-label="label"
        :data-level="level"
    >
        <span :style="{ width }"></span>
    </div>
</template>

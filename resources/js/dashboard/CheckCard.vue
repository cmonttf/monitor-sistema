<script setup>
import { computed } from 'vue';
import FixSteps from './FixSteps.vue';
import { STATUS_ICONS, STATUS_VARIANTS } from './status.js';

/**
 * Tarjeta de un chequeo: franja e insignia con el color del estado, mensaje, contenido opcional (los
 * medidores de recursos), pasos para solucionarlo si hay un problema y detalles desplegables.
 */
const props = defineProps({
    check: { type: Object, default: null },
    title: { type: String, default: null },
    showMessage: { type: Boolean, default: true },
    showDetails: { type: Boolean, default: true },
});

const status = computed(() => props.check?.status ?? 'unknown');
const variant = computed(() => STATUS_VARIANTS[status.value]);
</script>

<template>
    <article class="card h-100 shadow-sm check-card" :class="`check-card-${variant}`">
        <div class="card-body">
            <div class="d-flex align-items-start gap-2">
                <span class="status-icon" :class="`text-${variant}-emphasis bg-${variant}-subtle`" aria-hidden="true">
                    {{ STATUS_ICONS[status] }}
                </span>
                <h3 class="h6 card-title flex-grow-1 mb-0 mt-1">{{ title ?? check?.name }}</h3>
                <span class="badge rounded-pill" :class="`text-bg-${variant}`">{{ check?.label ?? 'Cargando' }}</span>
            </div>

            <div class="card-content">
                <slot />
                <p v-if="check && (showMessage || status !== 'ok')" class="card-text text-body-secondary mt-2 mb-0">
                    {{ check.message }}
                </p>
                <FixSteps v-if="check && status !== 'ok'" :steps="check.fix" :variant="variant" />
                <details v-if="showDetails && check?.details.length" class="mt-2 small">
                    <summary class="text-body-secondary">Detalles ({{ check.details.length }})</summary>
                    <ul class="mb-0 mt-1 ps-3 font-monospace">
                        <li v-for="(detail, index) in check.details" :key="index" class="text-break">{{ detail }}</li>
                    </ul>
                </details>
            </div>
        </div>
    </article>
</template>

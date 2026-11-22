<script setup>
import { computed } from 'vue';
import FixSteps from './FixSteps.vue';

/**
 * Tarjeta de recurso con el mismo aspecto que las tarjetas de seguridad: franja y insignia de estado,
 * contenido en vivo y, si hay un problema, el mensaje y los pasos para solucionarlo.
 */
const props = defineProps({
    title: { type: String, required: true },
    check: { type: Object, default: null },
});

const ICONS = { ok: '✓', warning: '!', critical: '✕', unknown: '?' };
const status = computed(() => props.check?.status ?? 'unknown');
</script>

<template>
    <article class="card" :class="`status-${status}`">
        <div class="card-head">
            <span class="icon">{{ ICONS[status] }}</span>
            <span class="card-title">{{ title }}</span>
            <span class="badge">{{ check?.label ?? 'Cargando' }}</span>
        </div>
        <div class="resource-body">
            <slot />
        </div>
        <template v-if="check && status !== 'ok'">
            <p class="card-message">{{ check.message }}</p>
            <FixSteps :steps="check.fix" />
        </template>
    </article>
</template>

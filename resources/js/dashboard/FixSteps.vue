<script setup>
import { ref } from 'vue';

/**
 * Sección «Cómo solucionarlo»: pasos numerados y, en los que tienen comando, un bloque con botón Copiar.
 */
defineProps({
    steps: { type: Array, required: true },
    variant: { type: String, default: 'secondary' },
});

const copiedIndex = ref(null);
const failedIndex = ref(null);

/**
 * Copia un comando al portapapeles y muestra la confirmación durante dos segundos.
 *
 * @param {string} command Comando a copiar.
 * @param {number} index Posición del paso.
 */
async function copy(command, index) {
    try {
        await navigator.clipboard.writeText(command);
        copiedIndex.value = index;
    } catch {
        failedIndex.value = index;
    }
    setTimeout(() => {
        copiedIndex.value = null;
        failedIndex.value = null;
    }, 2000);
}
</script>

<template>
    <div v-if="steps.length" class="mt-3 p-2 rounded-2 small" :class="`bg-${variant}-subtle`">
        <div class="fw-semibold mb-1" :class="`text-${variant}-emphasis`">Cómo solucionarlo</div>
        <ol class="mb-0 ps-3">
            <li v-for="(step, index) in steps" :key="index" class="mb-2">
                {{ step.text }}
                <div v-if="step.command" class="input-group input-group-sm mt-1">
                    <code class="form-control font-monospace text-break command-text">{{ step.command }}</code>
                    <button type="button" class="btn btn-outline-secondary bg-body" @click="copy(step.command, index)">
                        {{ copiedIndex === index ? 'Copiado ✓' : failedIndex === index ? 'Selecciona y copia' : 'Copiar' }}
                    </button>
                </div>
            </li>
        </ol>
    </div>
</template>

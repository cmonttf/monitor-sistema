<script setup>
/**
 * Sección "Cómo solucionarlo" con los pasos de un chequeo. Los botones Copiar los atiende el
 * manejador global del panel (botones con clase "copy" y atributo data-command).
 */
defineProps({
    steps: { type: Array, required: true },
});
</script>

<template>
    <div v-if="steps.length" class="fix">
        <div class="fix-title">Cómo solucionarlo</div>
        <ol>
            <li v-for="(step, index) in steps" :key="index">
                {{ step.text }}
                <div v-if="step.command" class="command">
                    <code>{{ step.command }}</code>
                    <button type="button" class="copy" :data-command="step.command">Copiar</button>
                </div>
            </li>
        </ol>
    </div>
</template>

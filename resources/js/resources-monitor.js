import { createApp } from 'vue';
import ResourcesMonitor from './resources-monitor/ResourcesMonitor.vue';

/**
 * Monta el monitor de recursos en tiempo real con la configuración que entrega la vista Blade.
 */
const element = document.getElementById('resources-monitor');

if (element) {
    createApp(ResourcesMonitor, {
        url: element.dataset.url,
        refreshMs: Number(element.dataset.refreshMs),
        historyMs: Number(element.dataset.historyMs),
        thresholds: JSON.parse(element.dataset.thresholds),
    }).mount(element);
}

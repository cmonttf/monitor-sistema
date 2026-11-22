import 'bootstrap/dist/css/bootstrap.min.css';
import '../css/dashboard.css';
import { createApp } from 'vue';
import App from './dashboard/App.vue';

/**
 * Monta el panel con la configuración y el reporte inicial que entrega la vista Blade.
 */
const element = document.getElementById('app');

if (element) {
    const data = element.dataset;

    createApp(App, {
        appName: data.appName,
        hostname: data.hostname,
        statusUrl: data.statusUrl,
        resourcesUrl: data.resourcesUrl,
        attacksUrl: data.attacksUrl,
        attacksRefreshMs: Number(data.attacksRefreshMs),
        refreshMs: Number(data.refreshMs),
        resourcesRefreshMs: Number(data.resourcesRefreshMs),
        historyMs: Number(data.historyMs),
        thresholds: JSON.parse(data.thresholds),
        initialReport: JSON.parse(data.report),
        alerts: JSON.parse(data.alerts),
    }).mount(element);
}

/**
 * Utilidades de formato en español (Chile) para el monitor de recursos.
 */

export const GB = 1024 ** 3;

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];

/**
 * Formatea bytes en unidades binarias con coma decimal, igual que ResourceSampler::formatBytes en PHP.
 *
 * @param {number} bytes Cantidad de bytes.
 * @returns {string} Cantidad legible, por ejemplo "13,1 GB".
 */
export function formatBytes(bytes) {
    const power = bytes > 0 ? Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), UNITS.length - 1) : 0;
    const digits = power >= 3 ? 1 : 0;
    const value = (bytes / 1024 ** power).toLocaleString('es-CL', {
        minimumFractionDigits: digits,
        maximumFractionDigits: digits,
    });

    return `${value} ${UNITS[power]}`;
}

/**
 * Formatea la hora de una marca de tiempo como HH:MM:SS.
 *
 * @param {number} timestamp Milisegundos desde la época.
 * @returns {string} Hora local.
 */
export function formatTime(timestamp) {
    return new Date(timestamp).toLocaleTimeString('es-CL', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

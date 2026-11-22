/**
 * Tipos de eventos del gráfico de ataques, en el orden fijo de la paleta categórica validada (azul,
 * naranja, aqua, amarillo) y de apilado (de abajo hacia arriba). El color sigue al tipo, nunca a su rango.
 */
export const ATTACK_TYPES = [
    { key: 'login', label: 'Inicios de sesión fallidos', color: 'var(--attack-login)' },
    { key: 'blocked', label: 'Conexiones bloqueadas', color: 'var(--attack-blocked)' },
    { key: 'malware', label: 'Malware detectado', color: 'var(--attack-malware)' },
    { key: 'panel', label: 'Accesos al panel bloqueados', color: 'var(--attack-panel)' },
];

/**
 * Ventanas de tiempo del gráfico y el tamaño de cada barra.
 */
export const ATTACK_WINDOWS = [
    { hours: 1, label: '1 h', bucketMinutes: 2 },
    { hours: 6, label: '6 h', bucketMinutes: 10 },
    { hours: 24, label: '24 h', bucketMinutes: 30 },
];

# Monitor de Seguridad

Panel web local que muestra si los elementos de seguridad de un equipo Ubuntu están al día, con alertas por color, junto con el uso de memoria y disco y un gráfico de la RAM en tiempo real. Se levanta solo al iniciar sesión y se abre en el navegador.

- 🟢 **Al día** · 🟠 **Atención** · 🔴 **Crítico** · ⚪ **Sin datos**
- Aviso superior con el peor estado encontrado; el título y el ícono de la pestaña cambian de color.
- Se actualiza cada 60 segundos; el botón **Verificar ahora** fuerza una revisión inmediata.
- Escucha solo en `127.0.0.1`, así que no es accesible desde la red.

## Qué revisa

| Categoría | Chequeo | Cuándo alerta |
|---|---|---|
| Actualizaciones | Paquetes del sistema (APT) | 🔴 si hay actualizaciones de seguridad pendientes, 🟠 si hay otras |
| | Lista de paquetes | 🟠 más de 3 días sin actualizarse, 🔴 más de 14 |
| | Actualizaciones automáticas | 🔴 si unattended-upgrades no está instalado o está desactivado, 🟠 si lleva más de 7 días sin ejecutarse |
| | Reinicio pendiente | 🟠 si hay un kernel más nuevo instalado o el sistema pide reiniciar |
| | Aplicaciones Snap | 🟠 si hay Snaps pendientes de actualizar |
| | Firmware (fwupd) | 🟠 si hay firmware nuevo disponible |
| Protección | Cortafuegos (UFW) | 🔴 si está desactivado o no está instalado |
| | Firmas del antivirus (ClamAV) | 🟠 más de 2 días de antigüedad, 🔴 más de 7 |
| | Actualizador del antivirus (freshclam) | 🔴 si el servicio falló, 🟠 si está detenido |
| | Escáner del antivirus (clamd) | 🔴 si el servicio falló, 🟠 si está detenido |
| Sistema | AppArmor | 🔴 si está deshabilitado |
| | Arranque seguro (Secure Boot) | 🟠 si está desactivado |
| | Cifrado de disco | 🟠 si no hay volúmenes LUKS |
| | Bloqueo de pantalla | 🔴 si está desactivado, 🟠 si tarda más de 15 minutos |
| Red | Servidor SSH | 🔴 si permite entrar como root, 🟠 si acepta contraseñas |
| | Puertos abiertos a la red | 🟠 si algún puerto es accesible a través de UFW |
| Recursos | Memoria RAM | 🟠 desde 85 % en uso o swap sobre 80 %, 🔴 desde 95 % |
| | Espacio en disco | 🟠 menos de 15 % libre, 🔴 menos de 5 % (o menos de 1 GB en discos de 10 GB o más) |

Cada tarjeta con problemas muestra una sección **Cómo solucionarlo** con los pasos a seguir y los comandos listos para copiar con un clic. Por ejemplo, la de APT arma el comando que instala exactamente los paquetes pendientes, incluidos los que `apt upgrade` deja retenidos. Los detalles (paquetes, fechas, puertos) se despliegan aparte.

## Recursos en tiempo real

La sección **Recursos** se actualiza cada 2 segundos, sin recargar la página:

- **Memoria RAM:** en uso, disponible, caché liberable y swap, con un medidor que cambia de color al acercarse al límite.
- **Espacio en disco:** espacio libre y medidor por cada disco real (se omiten los sistemas virtuales y los Snap).
- **RAM en uso, en tiempo real:** gráfico de los últimos 1, 5 o 15 minutos. Al pasar el cursor (o con las flechas del teclado, con el gráfico enfocado) muestra la hora y los valores de cada muestra; debajo están el mínimo, el promedio y el máximo, y una tabla con las últimas muestras.

El historial del gráfico se guarda en el navegador mientras el panel está abierto. Esta sección está hecha con Vue 3.

## Requisitos

- Ubuntu con escritorio GNOME y systemd.
- PHP 8.3 o superior y Composer.
- Node.js 20 o superior y npm (para compilar la interfaz).
- Opcionales, según lo que se quiera revisar: `ufw`, `clamav`, `clamav-freshclam`, `clamav-daemon`, `fwupd`, `snapd`, `mokutil`. Si alguno falta, su tarjeta lo indica.

## Instalación

```bash
git clone https://github.com/cmonttf/monitor-sistema.git
cd monitor-sistema
composer install
npm install
npm run build
cp .env.example .env
php artisan key:generate
php artisan migrate
```

Ajusta en `.env` la zona horaria (`APP_TIMEZONE`, por ejemplo `America/Santiago`) y el idioma (`APP_LOCALE=es`).

### Arranque automático

```bash
php artisan monitor:autostart
```

Este comando instala, para el usuario actual:

- Un servicio systemd de usuario (`~/.config/systemd/user/monitor-seguridad.service`) que levanta el servidor en `http://127.0.0.1:8787`.
- Una entrada de autoarranque del escritorio (`~/.config/autostart/monitor-seguridad.desktop`) que abre el panel en el navegador al iniciar sesión.
- Un lanzador en el menú de aplicaciones.

Para abrir el panel a mano: `php artisan monitor:open`. Para desinstalar el arranque automático: `php artisan monitor:autostart --remove`.

### Permiso para leer las reglas de UFW (opcional)

UFW solo deja leer sus reglas a root. Para que la tarjeta de puertos cruce los puertos abiertos con las reglas del cortafuegos, permite a tu usuario ejecutar **solo** `ufw status verbose` sin contraseña:

```bash
echo "$USER ALL=(root) NOPASSWD: /usr/sbin/ufw status verbose" | sudo tee /etc/sudoers.d/monitor-seguridad
sudo chmod 440 /etc/sudoers.d/monitor-seguridad
sudo visudo -cf /etc/sudoers.d/monitor-seguridad
```

Es un comando de solo lectura: no permite cambiar reglas ni desactivar el cortafuegos. Sin este permiso, la tarjeta lista los puertos que escuchan en la red y muestra el comando para habilitarlo. Para revocarlo: `sudo rm /etc/sudoers.d/monitor-seguridad`.

## Configuración

Variables de `.env`:

| Variable | Por defecto | Descripción |
|---|---|---|
| `SECURITY_MONITOR_PORT` | `8787` | Puerto del panel (siempre en `127.0.0.1`) |
| `SECURITY_MONITOR_CACHE_SECONDS` | `300` | Cada cuánto se vuelven a ejecutar los chequeos |
| `SECURITY_MONITOR_REFRESH_SECONDS` | `60` | Cada cuánto el navegador consulta el estado |
| `SECURITY_MONITOR_RESOURCES_REFRESH_SECONDS` | `2` | Cada cuánto se toma una muestra de memoria y discos |
| `SECURITY_MONITOR_RESOURCES_HISTORY_MINUTES` | `15` | Cuánto historial de RAM conserva el gráfico |

Si cambias el puerto, vuelve a ejecutar `php artisan monitor:autostart`.

Los chequeos activos y su orden se definen en [`config/security-monitor.php`](config/security-monitor.php).

## Agregar un chequeo

1. Crea una clase en `app/Services/Security/Checks/` que extienda `SystemCheck` e implemente `name()`, `category()` y `run()`. `run()` devuelve un `CheckResult` (`ok`, `warning`, `critical` o `unknown`) con un mensaje, detalles opcionales y, si hay un problema, los pasos para solucionarlo: `FixStep::command('Qué hace', 'comando')` o `FixStep::note('Indicación')`.
2. Usa `$this->system` (`SystemInspector`) para ejecutar comandos y leer archivos; así el chequeo se puede probar con dobles.
3. Regístrala en `config/security-monitor.php`.
4. Agrega sus pruebas en `tests/Feature/Security/SecurityChecksTest.php`.

Un chequeo que lanza una excepción aparece como ⚪ sin detener a los demás.

## Estructura

| Ruta | Contenido |
|---|---|
| `app/Services/Security/Checks/` | Un archivo por chequeo |
| `app/Services/Security/CheckResult.php`, `FixStep.php` | Resultado de un chequeo y pasos para solucionarlo |
| `app/Services/Security/SecurityMonitor.php` | Ejecuta los chequeos, calcula el estado global y guarda el reporte en caché |
| `app/Services/Security/SystemInspector.php` | Acceso a comandos y archivos del sistema |
| `app/Services/Security/UfwStatus.php` | Interpreta `ufw status verbose` y evalúa puertos contra las reglas |
| `app/Services/Security/ResourceSampler.php` | Lee el uso de memoria (`/proc/meminfo`) y de discos (`df`) |
| `app/Http/Controllers/SecurityDashboardController.php` | Panel (`/`), estado en JSON (`/estado`, `?refresh=1` para forzar) y muestra en vivo (`/recursos`) |
| `resources/views/security/dashboard.blade.php` | Interfaz del panel |
| `resources/js/resources-monitor/` | Componentes Vue del monitor de recursos en tiempo real |
| `app/Console/Commands/` | `monitor:autostart` y `monitor:open` |

## Desarrollo de la interfaz

Tras cambiar los componentes Vue, recompila con `npm run build` (o usa `npm run dev` mientras desarrollas).

## Calidad de código

```bash
composer quality   # phpcs + PHPStan + pruebas
composer phpcs     # estilo PSR-12 y PHPDoc obligatorio (phpcs.xml)
composer phpcbf    # corrige automáticamente lo que phpcs puede arreglar
composer phpstan   # análisis estático nivel 5 con Larastan (phpstan.neon)
php artisan test   # pruebas
```

Las pruebas simulan los comandos y archivos del sistema y bloquean la ejecución de procesos reales, así que no dependen del equipo en que se ejecutan.

## Autor

Camilo Montt — cmonttf@gmail.com

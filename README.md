# Monitor de Seguridad

Panel web local que muestra si los elementos de seguridad de un equipo **Linux o Windows** están al día, con alertas por color, junto con el uso de memoria y disco y un gráfico de la RAM en tiempo real. Se levanta solo al iniciar sesión y se abre en el navegador.

- 🟢 **Al día** · 🟠 **Atención** · 🔴 **Crítico** · ⚪ **Sin datos**
- Aviso superior con el peor estado encontrado; el título y el ícono de la pestaña cambian de color.
- Cada tarjeta con problemas muestra **Cómo solucionarlo**, con los comandos listos para copiar.
- Se actualiza cada 60 segundos; el botón **Verificar ahora** fuerza una revisión inmediata.
- Escucha solo en `127.0.0.1`, así que no es accesible desde la red.

## Sistemas compatibles

El monitor detecta el sistema operativo y, en Linux, la familia de la distribución. Cada chequeo declara en qué plataformas aplica y en cada equipo solo se muestran los que corresponden.

| Sistema | Familia | Herramientas que revisa |
|---|---|---|
| Debian, Ubuntu, Linux Mint, Pop!_OS… | Debian | APT, unattended-upgrades, UFW, AppArmor |
| Fedora, RHEL, Rocky, AlmaLinux, CentOS… | Fedora/RHEL | DNF, dnf-automatic, firewalld, SELinux |
| Arch, Manjaro, EndeavourOS… | Arch | pacman (`checkupdates`), UFW, AppArmor si está habilitado |
| Otras distribuciones Linux | — | Solo los chequeos genéricos de Linux |
| Windows 10 y 11 | — | Windows Update, Seguridad de Windows, BitLocker, UAC, RDP |

En Windows el monitor corre **como usuario normal**, sin permisos de administrador. Todo lo que revisa se puede leer así; cuando algo no se puede leer (por ejemplo, BitLocker en algunas ediciones), la tarjeta queda en ⚪ e indica cómo revisarlo a mano.

## Qué revisa

### Linux

| Categoría | Chequeo | Cuándo alerta |
|---|---|---|
| Actualizaciones | Paquetes del sistema (APT, DNF o pacman) | 🔴 si hay actualizaciones de seguridad pendientes (APT y DNF), 🟠 si hay otras |
| | Lista de paquetes (Debian) | 🟠 más de 3 días sin actualizarse, 🔴 más de 14 |
| | Actualizaciones automáticas (unattended-upgrades o dnf-automatic) | 🔴 si están desactivadas (Debian), 🟠 si no se ejecutan o no están activadas (Fedora) |
| | Reinicio pendiente | 🟠 si hay un kernel más nuevo, faltan los módulos del kernel en uso o el sistema pide reiniciar |
| | Aplicaciones Snap | 🟠 si hay Snaps pendientes de actualizar |
| | Firmware (fwupd) | 🟠 si hay firmware nuevo disponible |
| Protección | Cortafuegos (UFW o firewalld) | 🔴 si está desactivado o no hay ninguno instalado |
| | Firmas del antivirus (ClamAV) | 🟠 más de 2 días de antigüedad, 🔴 más de 7 |
| | Actualizador del antivirus (freshclam) | 🔴 si el servicio falló, 🟠 si está detenido |
| | Escáner del antivirus (clamd) | 🔴 si el servicio falló, 🟠 si está detenido |
| Sistema | Control de acceso (AppArmor o SELinux) | 🔴 si está deshabilitado (Debian y Fedora), 🟠 si SELinux está en modo permisivo |
| | Arranque seguro (Secure Boot) | 🟠 si está desactivado |
| | Cifrado de disco | 🟠 si no hay volúmenes LUKS |
| | Bloqueo de pantalla (GNOME) | 🔴 si está desactivado, 🟠 si tarda más de 15 minutos |
| Red | Servidor SSH | 🔴 si permite entrar como root, 🟠 si acepta contraseñas |
| | Puertos abiertos a la red | 🟠 si algún puerto es accesible a través del cortafuegos |

### Windows

| Categoría | Chequeo | Cuándo alerta |
|---|---|---|
| Actualizaciones | Windows Update | 🔴 si hay actualizaciones de seguridad pendientes, 🟠 si hay otras |
| | Reinicio pendiente | 🟠 si Windows espera un reinicio para completar actualizaciones |
| Protección | Antivirus (Centro de seguridad y Defender) | 🔴 si no hay antivirus activo o Defender no protege en tiempo real; 🟠/🔴 si las firmas tienen más de 2/7 días |
| | Firewall de Windows | 🔴 si algún perfil está desactivado, 🟠 si alguno permite conexiones entrantes por defecto |
| Sistema | Cifrado de disco (BitLocker) | 🟠 si la unidad del sistema está sin cifrar o con la protección suspendida |
| | Arranque seguro (Secure Boot) | 🟠 si está desactivado |
| | Bloqueo de pantalla | 🟠 si la sesión no se bloquea por inactividad en 15 minutos o menos |
| | Control de cuentas de usuario (UAC) | 🔴 si está deshabilitado, 🟠 si eleva privilegios sin preguntar |
| Red | Escritorio remoto (RDP) | 🔴 si está activo sin NLA, 🟠 si está activo |
| | Puertos abiertos a la red | 🟠 si hay puertos expuestos con el firewall desactivado |

### Ambos sistemas

| Categoría | Chequeo | Cuándo alerta |
|---|---|---|
| Recursos | Memoria RAM | 🟠 desde 85 % en uso o swap sobre 80 %, 🔴 desde 95 % |
| | Espacio en disco | 🟠 menos de 15 % libre, 🔴 menos de 5 % (o menos de 1 GB en discos de 10 GB o más) |

## Recursos en tiempo real

La sección **Recursos** se actualiza sin recargar la página (cada 2 segundos en Linux y cada 5 en Windows):

- **Memoria RAM:** en uso, disponible, caché liberable (solo Linux) y swap o archivo de paginación, con un medidor que cambia de color al acercarse al límite.
- **Espacio en disco:** espacio libre y medidor por cada disco real.
- **RAM en uso, en tiempo real:** gráfico de los últimos 1, 5 o 15 minutos. Al pasar el cursor (o con las flechas del teclado, con el gráfico enfocado) muestra la hora y los valores de cada muestra; debajo están el mínimo, el promedio y el máximo, y una tabla con las últimas muestras.

El historial del gráfico se guarda en el navegador mientras el panel está abierto.

La interfaz está hecha con **Vue 3** y **Bootstrap 5.3**, y sigue el modo claro u oscuro del sistema.

## Requisitos

- PHP 8.3 o superior y Composer.
- Node.js 20 o superior y npm (para compilar la interfaz).
- **Linux:** systemd. El bloqueo de pantalla se revisa en escritorios GNOME.
- **Windows:** Windows PowerShell 5.1 (incluido en Windows 10 y 11).
- Opcionales en Linux, según lo que se quiera revisar: `ufw` o `firewalld`, `clamav`, `fwupd`, `snapd`, `mokutil`, `pacman-contrib` (Arch). Si alguno falta, su tarjeta lo indica e incluye el comando para instalarlo.

## Instalación

```bash
git clone https://github.com/cmonttf/monitor-sistema.git
cd monitor-sistema
composer install
npm install
npm run build
cp .env.example .env          # en Windows (PowerShell): Copy-Item .env.example .env
php artisan key:generate
php artisan migrate
```

Ajusta en `.env` la zona horaria (`APP_TIMEZONE`, por ejemplo `America/Santiago`) y el idioma (`APP_LOCALE=es`).

### Arranque automático

```bash
php artisan monitor:autostart
```

En **Linux** instala, para el usuario actual:

- Un servicio systemd de usuario (`~/.config/systemd/user/monitor-seguridad.service`) que levanta el servidor en `http://127.0.0.1:8787`.
- Una entrada de autoarranque del escritorio (`~/.config/autostart/monitor-seguridad.desktop`) que abre el panel en el navegador al iniciar sesión.
- Un lanzador en el menú de aplicaciones.

En **Windows** crea, sin necesidad de ser administrador:

- Un script de PowerShell (`storage/app/monitor-seguridad.ps1`) que levanta el servidor oculto, si no está corriendo, y abre el panel.
- Un acceso directo en la carpeta Inicio, que lo ejecuta al iniciar sesión, y otro en el menú Inicio.

Para abrir el panel a mano: `php artisan monitor:open`. Para desinstalar el arranque automático: `php artisan monitor:autostart --remove`.

### Permiso para leer las reglas de UFW (opcional, Linux)

UFW solo deja leer sus reglas a root. Para que la tarjeta de puertos cruce los puertos abiertos con las reglas del cortafuegos, permite a tu usuario ejecutar **solo** `ufw status verbose` sin contraseña:

```bash
echo "$USER ALL=(root) NOPASSWD: /usr/sbin/ufw status verbose" | sudo tee /etc/sudoers.d/monitor-seguridad
sudo chmod 440 /etc/sudoers.d/monitor-seguridad
sudo visudo -cf /etc/sudoers.d/monitor-seguridad
```

Es un comando de solo lectura: no permite cambiar reglas ni desactivar el cortafuegos. Sin este permiso, la tarjeta lista los puertos que escuchan en la red y muestra el comando para habilitarlo. Para revocarlo: `sudo rm /etc/sudoers.d/monitor-seguridad`.

Con **firewalld** no hace falta: sus reglas se consultan sin privilegios.

## Seguridad del panel

El panel solo atiende al propio equipo: el servidor escucha en `127.0.0.1` y, además, cada solicitud debe usar el nombre `127.0.0.1`, `localhost` o `[::1]` y venir de una dirección de loopback; si no, responde 403. Esto impide que una página web maliciosa lea el estado del equipo mediante *DNS rebinding* (un dominio externo que pasa a resolver a `127.0.0.1`).

## Configuración

Variables de `.env`:

| Variable | Por defecto | Descripción |
|---|---|---|
| `SECURITY_MONITOR_PORT` | `8787` | Puerto del panel (siempre en `127.0.0.1`) |
| `SECURITY_MONITOR_CACHE_SECONDS` | `300` | Cada cuánto se vuelven a ejecutar los chequeos |
| `SECURITY_MONITOR_REFRESH_SECONDS` | `60` | Cada cuánto el navegador consulta el estado |
| `SECURITY_MONITOR_RESOURCES_REFRESH_SECONDS` | `2` (Linux), `5` (Windows) | Cada cuánto se toma una muestra de memoria y discos |
| `SECURITY_MONITOR_RESOURCES_HISTORY_MINUTES` | `15` | Cuánto historial de RAM conserva el gráfico |

Si cambias el puerto, vuelve a ejecutar `php artisan monitor:autostart`.

Los chequeos activos y su orden se definen en [`config/security-monitor.php`](config/security-monitor.php).

## Agregar un chequeo

1. Crea una clase en `app/Services/Security/Checks/` que extienda `SystemCheck` (Linux) o `WindowsCheck` (Windows) e implemente `name()`, `category()` y `run()`. `run()` devuelve un `CheckResult` (`ok`, `warning`, `critical` o `unknown`) con un mensaje, detalles opcionales y, si hay un problema, los pasos para solucionarlo: `FixStep::command('Qué hace', 'comando')` o `FixStep::note('Indicación')`.
2. Si solo aplica a una familia de Linux, sobrescribe `supports()`, por ejemplo `return $platform->isLinux(LinuxFamily::RedHat);`. Para instalar paquetes, usa `$this->platform->installStep(...)`, que arma el comando con el gestor de la distribución.
3. Usa `$this->system` (`SystemInspector`) para ejecutar comandos, leer archivos o correr PowerShell (`powershell()`); así el chequeo se puede probar con dobles.
4. Regístralo en `config/security-monitor.php` y agrega sus pruebas en `tests/Feature/Security/`.

Un chequeo que lanza una excepción aparece como ⚪ sin detener a los demás.

## Estructura

| Ruta | Contenido |
|---|---|
| `app/Services/Security/Checks/` | Un archivo por chequeo (los de Windows empiezan con `Windows`) |
| `app/Services/Security/Platform.php`, `PlatformDetector.php` | Sistema operativo y familia Linux detectados (`/etc/os-release`) |
| `app/Services/Security/CheckResult.php`, `FixStep.php` | Resultado de un chequeo y pasos para solucionarlo |
| `app/Services/Security/SecurityMonitor.php` | Ejecuta los chequeos de la plataforma, calcula el estado global y guarda el reporte en caché |
| `app/Services/Security/SystemInspector.php` | Acceso a comandos, archivos y PowerShell |
| `app/Services/Security/UfwStatus.php`, `FirewalldStatus.php` | Evalúan los puertos contra las reglas de UFW o firewalld |
| `app/Services/Security/ResourceSampler.php` | Lee el uso de memoria y discos (`/proc/meminfo` y `df`, o CIM en Windows) |
| `app/Services/Security/WindowsAutostart.php` | Arranque automático en Windows (script y accesos directos) |
| `app/Http/Controllers/SecurityDashboardController.php` | Panel (`/`), estado en JSON (`/estado`, `?refresh=1` para forzar) y muestra en vivo (`/recursos`) |
| `resources/views/security/dashboard.blade.php` | Página que monta la interfaz con su configuración y el reporte inicial |
| `resources/js/dashboard/` | Componentes Vue del panel (tarjetas, recursos en tiempo real, gráfico) |
| `resources/css/dashboard.css` | Estilos propios sobre Bootstrap (franjas de estado, medidores y gráfico) |
| `app/Console/Commands/` | `monitor:autostart` y `monitor:open` |

## Desarrollo de la interfaz

Tras cambiar los componentes Vue o los estilos, recompila con `npm run build` (o usa `npm run dev` mientras desarrollas).

## Calidad de código

```bash
composer quality   # phpcs + PHPStan + pruebas
composer phpcs     # estilo PSR-12 y PHPDoc obligatorio (phpcs.xml)
composer phpcbf    # corrige automáticamente lo que phpcs puede arreglar
composer phpstan   # análisis estático nivel 5 con Larastan (phpstan.neon)
php artisan test   # pruebas
```

Las pruebas simulan los comandos, archivos y respuestas de PowerShell, y bloquean la ejecución de procesos reales, así que no dependen del sistema en que se ejecutan: los chequeos de Windows se prueban también desde Linux y viceversa.

### Pruebas de integración

`tests/Integration` contiene pruebas **sin simulaciones**, que ejecutan los chequeos contra el sistema real. En Windows además revisan la sintaxis de todos los scripts de PowerShell. No forman parte de `composer quality` (ejecutarían comandos reales y tardan más); se corren aparte:

```bash
php artisan test tests/Integration
```

Cada archivo solo corre en su sistema (`LinuxSystemTest` en Linux y `WindowsSystemTest` en Windows); el otro se omite.

### Integración continua

En cada push a `main` y en cada pull request, [GitHub Actions](.github/workflows/ci.yml) ejecuta en **Ubuntu y Windows**: instalación, compilación de la interfaz, `composer quality` y las pruebas de integración.

## Autor

Camilo Montt — cmonttf@gmail.com

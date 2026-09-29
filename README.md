# NEXUS 6.3 — Railway Backend

Backend Flask + Telegram Bot para NEXUS AI.

## Railway variables

- `TELEGRAM_BOT_TOKEN` = token del BotFather
- `WEBAPP_URL` = URL pública de Railway, por ejemplo `https://tu-app.up.railway.app`
- `ADMIN_KEY` = clave aleatoria para `/api/registrations`
- `DATABASE_PATH` = opcional; por defecto `data.db`
- `PORT` = proporcionado por Railway

## Endpoints

- `GET /health`
- `GET /api/system`
- `POST /api/register`
- `GET /api/registrations/<id>`
- `POST /api/registrations/<id>/event`
- `GET /api/registrations` con `X-Admin-Key`

## Validación

El servidor vuelve a validar todos los campos críticos:
- plataforma permitida
- nombres
- email
- teléfono
- país fijo United States
- estado válido de EE. UU.
- ciudad
- resultado del chequeo local de una sola cara

La foto/selfie no se sube al backend en este flujo. El servidor solo recibe el indicador `single_face_detected`.

La detección de una cara no equivale a verificar la identidad. La verificación oficial queda en el proceso autorizado de la plataforma.
### NEXUS 7.1 — Proceso inteligente de creación de documentos
After the client-side validation succeeds, the interface presents a futuristic creation sequence showing:
1. Data synthesis
2. Registration document creation
3. Platform handoff preparation

The final action opens the selected platform's official site. The interface does not claim that an external account was created or approved unless the external platform actually completes that process.


### NEXUS 7.4 — Face engine architecture fix
The face detector is initialized inside the main application scope instead of through `window.NEXUSFace`. The selfie handler waits for the MediaPipe initialization promise before attempting detection. This avoids the `Cannot read properties of undefined (reading 'detect')` failure in Telegram WebView.


### NEXUS 7.5 — Local server face engine
The face quality check no longer depends on MediaPipe/CDN resources. The selfie is sent over HTTPS to `/api/face-check`, analyzed in memory with OpenCV and a bundled frontal-face cascade, and is not stored. The endpoint reports face presence/count and basic framing quality only; it does not identify a person or perform biometric identity verification.


### NEXUS 7.6
Fixed upload rejection caused by the previous 1 MB global request limit. The server now permits requests up to 12 MB while the selfie endpoint still enforces an 8 MB image limit. HTTP 413 responses are handled explicitly.

### NEXUS 7.7 — Futuristic document creation workflow
After the registration information passes the existing form validation and is submitted, the interface replaces the generic completion message with a cinematic NEXUS AI document-creation sequence. It includes an animated holographic document, progress stages, platform destination, integrity pass and final handoff state. The final action opens the selected platform's official registration site; it does not claim an external account has been created or approved.

### NEXUS 7.8 — Submission flow fix
The document-creation animation is now triggered by the confirmed `/api/register` success event rather than a native form-submit listener. This fixes the issue where the legacy “Validación completada” screen appeared first because the main action is a `type="button"`.


### SSN
NEXUS 8.3 includes an SSN field with masked input, formatting and local 9-digit validation. It does not claim to verify an SSN against SSA records. SSA's official SSNVS is restricted to authorized employers/third-party submitters for permitted wage-reporting purposes, while CBSV is a consent-based service for enrolled organizations. An actual online SSA verification requires the appropriate authorized service/integration and credentials.


### NEXUS 8.4
Ajuste visual del campo SSN: alineación, ancho, espaciado, botón Mostrar/Ocultar y mensaje de ayuda integrados al formulario.


## Acceso restringido — NEXUS 8.6

Configura estas variables en Railway:

- `ACCESS_CODE`: código privado que el usuario debe introducir en el bot de Telegram. Usa una clave larga y aleatoria; no la pongas en el HTML ni en GitHub.
- `ACCESS_TOKEN_SECRET`: opcional; una clave aleatoria larga para firmar tokens de acceso. Si se omite, se deriva de `TELEGRAM_BOT_TOKEN` y `ACCESS_CODE`.

Comportamiento:
1. `/start` solicita el código de acceso por Telegram. Sin un código correcto, el bot no envía el botón de apertura.
2. El Mini App recibe un token temporal de 4 horas al abrirse desde el bot.
3. Si alguien abre la URL pública directamente, se muestra una pantalla de acceso antes de revelar la interfaz.
4. Los endpoints de análisis facial, validación y registro exigen el token firmado.
5. Los intentos de código están limitados por IP en la web y a cinco intentos por conversación del bot.

Después de añadir `ACCESS_CODE` en Railway, haz un nuevo deploy. Si la variable falta, el servicio se detiene de forma segura y lo indica en los logs.


## NEXUS 8.7 — Solicitar código en cada apertura

La Mini App ya no reutiliza tokens guardados ni acepta el token de lanzamiento como forma de saltarse la pantalla de acceso. Al abrir o volver a abrir la Mini App, solicita el código y emite un token nuevo para esa sesión. El token local también se elimina cuando la página se oculta o se descarga.

Nota: el código del bot de Telegram continúa funcionando como primer control de acceso; según el flujo actual, el usuario puede tener que introducir el código en Telegram y después en la Mini App.

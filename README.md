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
### NEXUS 7.1 — Document creation workflow
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

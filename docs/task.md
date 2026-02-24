# Plan de Trabajo: Maestro de Autenticación (Edición Definitiva)

Laboratorio de identidad y seguridad de grado producción. Cada fase se completa al 100% (código + tests + panel en dashboard) antes de continuar. El proyecto queda en estado funcional en la última fase completada.

---

## Convenciones del Proyecto

- **Lenguaje**: TypeScript estricto
- **Idioma de logs y mensajes del servidor**: Español
- **Frontend**: Alpine.js + Vanilla JS (sin build step)
- **Email**: Nodemailer + Gmail SMTP. Dev → log por consola. Prod → email real (credenciales pedidas al usuario en Fase 5.6)
- **OAuth**: GitHub y Google (ambos con Authorization Code + PKCE + Account Linking)
- **Estrategia**: completar fase → tests verdes → dashboard → siguiente fase

---

## Tareas

### Fase 0: Tooling y Tipos Base
- [ ] Inicializar proyecto Node.js con TypeScript (`tsconfig.json` modo estricto)
- [ ] Configurar `tsx` para ejecución directa y `nodemon` para hot-reload
- [ ] Configurar ESLint + Prettier con reglas TypeScript
- [ ] Crear `.gitignore`: `.env`, `dist/`, `*.sqlite`, `node_modules/`
- [ ] Crear `.env.example` con todas las variables documentadas:
    - `PORT`, `NODE_ENV`, `FRONTEND_URL`
    - `JWT_SECRET` (mínimo 32 chars), `JWT_EXPIRY_ACCESS=15m`, `JWT_EXPIRY_REFRESH=7d`
    - `IP_HASH_SALT` (salt aleatorio para hashing de IPs — GDPR)
    - `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_CALLBACK_URL`
    - `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_CALLBACK_URL`
    - `M2M_CLIENT_ID`, `M2M_CLIENT_SECRET` (Client Credentials Grant — máquina a máquina, Fase 5)
    - `GMAIL_USER`, `GMAIL_APP_PASSWORD` (solicitados al usuario en Fase 5.6)
    - `PASETO_PRIVATE_KEY`, `PASETO_PUBLIC_KEY` (generadas en Fase 5.10 si no existen; el servidor las imprime en logs y espera que el usuario las copie al `.env`)
- [ ] Definir tipos TypeScript base:
    - `JWTAccessPayload`: `{ sub, jti, kid, roles, iat, exp }`
    - `JWTRefreshPayload`: `{ sub, jti, kid, familyId, iat, exp }`
    - `UserRecord`, `SessionRecord`, `AuditEvent`, `ApiKeyRecord`
    - `OAuthProvider`: `"github" | "google"`
    - `UserRole`: `"admin" | "editor" | "user" | "viewer"`
    - `EmailTokenType`: `"VERIFY_EMAIL" | "PASSWORD_RESET" | "MAGIC_LINK"`
    - `DeviceCodeStatus`: `"pending" | "approved" | "denied" | "expired"`

---

### Fase 1: Infraestructura de Producción
- [ ] Inicializar servidor Express con TypeScript
- [ ] Aplicar middlewares globales: `helmet`, `cors` (con `FRONTEND_URL`), `pino-http`
- [ ] **Fail-Fast Config**: validar todas las variables de `.env` con Zod al arrancar
    - Si algo falta o es inválido → log de error en español + `process.exit(1)`
    - Mensaje: `"❌ Error de configuración: JWT_SECRET debe tener mínimo 32 caracteres"`
- [ ] **Correlation ID middleware**: genera `UUID v4` por request, lo adjunta a `req.correlationId`, lo propaga en headers de respuesta (`X-Correlation-ID`) y en todos los logs
- [ ] **Error Handler centralizado**: captura todos los errores no manejados, responde con formato consistente:
    ```json
    { "error": "Mensaje en español", "code": "TOKEN_INVALIDO", "correlationId": "uuid" }
    ```
- [ ] `GET /health`: responde `{ "estado": "activo", "timestamp": "..." }` — para Docker health check
- [ ] Registrar todas las rutas bajo prefijo `/api/v1/`
- [ ] Configurar **Docker + docker-compose**: servicio `app` + volumen persistente para `database.sqlite`
- [ ] Crear `README.md` con: descripción del proyecto, requisitos, comandos de inicio, variables de entorno requeridas, enlace a `/api-docs`

---

### Fase 2: Persistencia y Modelos de Datos
- [ ] Inicializar `better-sqlite3` con sistema de migraciones secuenciales (`migrations/001_initial.sql`, etc.)
- [ ] Crear el schema completo en migraciones:
    - [ ] `users` — con `email_verified`, `locked_until`, `mfa_secret`, `roles` (JSON), `deleted_at`
    - [ ] `linked_identities` — Account Linking GitHub + Google
    - [ ] `email_tokens` — un solo tipo para: verificación, reset, magic link (campo `type`)
    - [ ] `mfa_recovery_codes` — 8 códigos por usuario, un solo uso
    - [ ] `sessions` — Session Token clásico con `ip_hash`
    - [ ] `refresh_token_families` — JWT Family Tracking con `kid`, `current_jti`, `access_jti`
    - [ ] `jwt_signing_keys` — soporte a múltiples claves para rotación sin logout masivo
    - [ ] `api_keys` — con `key_prefix` visible y `key_hash` bcrypt
    - [ ] `oauth_states` — PKCE: `state` + `code_verifier` con TTL 10min
    - [ ] `device_codes` — Device Authorization Grant con `status` y `user_code`
    - [ ] `webauthn_challenges` — challenge temporal entre `/options` y `/verify` (TTL 5min, tipo registro o autenticación)
    - [ ] `webauthn_credentials` — con `counter` para detección de clonación
    - [ ] `audit_logs` — con `ip_hash`, `correlation_id`, `metadata` JSON
- [ ] Implementar **capa de repositorio** con funciones TypeScript tipadas para cada tabla (SQL directo, sin ORM)
- [ ] Marcar operaciones críticas con **transacciones SQLite** (`db.transaction()`):
    - Renovación de Refresh Token (actualizar `current_jti` + insertar en `audit_logs`)
    - Revocación de familia completa
    - Eliminación de cuenta GDPR (6 tablas)
    - Account Linking
    - Verificación de email (marcar token usado + actualizar `email_verified`)
- [ ] Implementar **job de purga automática** (cada hora con `setInterval`):
    - `webauthn_challenges` expirados (TTL 5min — se acumulan si el usuario abandona el flujo a mitad)
    - `email_tokens` expirados y usados
    - `oauth_states` expirados
    - `device_codes` expirados
    - `sessions` expiradas
    - `refresh_token_families` expiradas o revocadas hace > 7 días
    - `audit_logs` > 90 días → anonimizar (`user_id`, `ip_hash`, `user_agent` → NULL)
- [ ] Implementar **cache en memoria para DPoP replay protection** (`Map<jti, expiresAt>`):
    - Job interno cada 60 segundos elimina entradas expiradas del Map
    - No requiere tabla en BD — documentar limitación en multi-réplica (misma que rate limiter)

---

### Fase 3: Autenticación Clásica y API Keys
- [ ] **Basic Auth**:
    - Middleware que decodifica `Authorization: Basic <base64>`
    - Comparación con `crypto.timingSafeEqual` (no `===`)
    - Log de evento: `LOGIN_EXITOSO` / `LOGIN_FALLIDO`
    - Ruta protegida de demostración: `GET /api/v1/basic/protected`
- [ ] **Registro e inicio de sesión con contraseña**:
    - `POST /api/v1/auth/register`: hash de contraseña con bcrypt (cost 12), crear usuario con `email_verified=0`, enviar email de verificación (Fase 3 usa log por consola)
    - `GET /api/v1/auth/verify-email?token=...`: validar token, marcar `email_verified=1` (transacción)
    - `POST /api/v1/auth/login`: verificar contraseña, verificar `email_verified`, verificar `locked_until`, emitir AT + RT (Family Tracking)
    - **Account Lockout**: tras 5 `LOGIN_FALLIDO` consecutivos → `locked_until = now + 30min` → log `CUENTA_BLOQUEADA`
- [ ] **Session Tokens**:
    - `POST /api/v1/session/login`: genera `crypto.randomBytes(32)`, almacena hash en `sessions`
    - Middleware de validación con expiración y `ip_hash`
    - `GET /api/v1/session/protected`: ruta demo protegida
- [ ] **API Keys (Stripe-style)**:
    - `POST /api/v1/keys`: genera `sk_live_<random64>`, almacena `key_prefix` (primeros 8 chars en claro) + `key_hash` (bcrypt)
    - La key completa se muestra **una sola vez** al crearse — nunca recuperable después
    - Middleware que verifica `Authorization: Bearer sk_live_*` contra hashes en BD
    - `GET /api/v1/keys`: lista de keys con `key_prefix`, `name`, `scopes`, `last_used_at` (paginada)
    - `POST /api/v1/keys/:id/revoke`: revoca API Key → log `API_KEY_REVOCADA`
    - **Middleware de scopes**: `requireScope("read:data")` → 403 si la key no tiene el scope
- [ ] **Panel Fase 3 en dashboard**: demostración de Basic Auth, Session Token y API Keys con Alpine.js. Visualización de por qué API Key en header es mejor que en query param (los query params aparecen en logs del servidor).

---

### Fase 4: JWT con Defensas Completas
- [ ] **Configuración de claves de firma**:
    - Al arrancar, verificar que existe al menos una clave activa en `jwt_signing_keys`
    - Si no existe, crear la primera clave activa con el `JWT_SECRET` de `.env`
    - `kid` = UUID corto asignado a cada clave
- [ ] **Emisión de tokens**:
    - Access Token: 15 minutos, payload `{ sub, jti, kid, roles }` — sin PII (sin email)
    - Refresh Token: 7 días, cookie `HttpOnly; Secure; SameSite=Strict`
    - Ambos llevan `jti` único (UUID v4) y `kid` de la clave activa
    - Registrar nueva familia en `refresh_token_families`
- [ ] **Verificación segura**:
    - Leer `kid` del header JWT → buscar clave en `jwt_signing_keys` (activa o retirada)
    - Whitelist de algoritmos: solo `HS256` — lanzar error si `alg` es diferente (incluido `none`)
    - Verificar `jti` contra `refresh_token_families.current_jti` (no solo la firma)
- [ ] **Refresh Token Family Tracking** (`POST /api/v1/jwt/refresh`):
    - Extraer RT de cookie → decodificar → buscar familia por `familyId`
    - Si `jti` del RT !== `current_jti` de la familia → **robo detectado** → revocar familia con `revoked_reason="stolen"` → log `TOKEN_ROBO_DETECTADO` → responder 401
    - Si válido → emitir nuevo par AT/RT → actualizar `current_jti` y `access_jti` (transacción)
- [ ] **Logout** (`POST /api/v1/auth/logout`):
    - Revocar familia del RT actual (`revoked_reason="logout"`)
    - Limpiar cookie RT
    - Log `LOGOUT`
- [ ] **Logout global** (`POST /api/v1/jwt/logout-all`):
    - Revocar **todas** las familias activas del usuario (`revoked_reason="global_logout"`)
    - Log `SESION_GLOBAL_CERRADA`
- [ ] **Lista de sesiones activas** (`GET /api/v1/jwt/sessions`):
    - Devuelve familias activas con `ip_hash`, `user_agent`, `created_at`, `kid` — paginada
- [ ] **Rotación de clave de firma** (`POST /api/v1/admin/keys/rotate`) — solo admin, solo dev:
    - Crear nueva clave en `jwt_signing_keys` (active=1)
    - Marcar la anterior como retirada (active=0, `retired_at=now`)
    - Los tokens firmados con la clave retirada siguen siendo verificables hasta que expiren
    - Log `CLAVE_JWT_ROTADA`
- [ ] **Panel Fase 4 en dashboard**:
    - JWT Decoder en tiempo real (Alpine.js: pegar token → ver header/payload/firma/estado)
    - Timeline visual de AT (15min) vs RT (7 días) con barra de progreso en vivo
    - **Modo Inseguro**: demostración de `alg:none` y secreto débil con botón de ataque
    - Visualizador de familias: árbol de tokens de la sesión actual

---

### Fase 5: OAuth 2.0 — Los Cuatro Flujos
- [ ] **Authorization Code + PKCE — GitHub**:
    - Generar `code_verifier` aleatorio (43-128 chars URL-safe) y `code_challenge` (SHA-256)
    - Guardar `state` + `code_verifier` + `provider` en `oauth_states` (TTL 10min)
    - `GET /api/v1/oauth/github`: redirigir a GitHub con `state`, `code_challenge`, `scope=user:email`
    - `GET /api/v1/oauth/github/callback`: validar `state`, intercambiar `code` → tokens, obtener perfil, ejecutar Account Linking
    - Log `OAUTH_INICIO` y `OAUTH_CALLBACK`
- [ ] **Authorization Code + PKCE — Google**:
    - Mismo flujo que GitHub con `scope=openid email profile`
    - `GET /api/v1/oauth/google`: redirigir a Google OAuth
    - `GET /api/v1/oauth/google/callback`: validar, obtener perfil, Account Linking
- [ ] **Account Linking (transacción)**:
    - Recibir `provider`, `provider_id`, `provider_email`, `access_token` del provider
    - Buscar en `linked_identities` por `(provider, provider_id)`:
      - Existe → usuario conocido → emitir sesión → log `LOGIN_EXITOSO`
      - No existe → buscar `users` por `provider_email`:
        - Email no existe → crear usuario (`email_verified=1` porque el provider ya lo verificó) + `linked_identity` → log `REGISTRO_VERIFICADO` + `CUENTA_VINCULADA`
        - Email existe → si hay sesión activa: vincular directamente; si no: responder con código de vinculación temporal (flujo de confirmación en frontend)
    - `GET /api/v1/user/linked-accounts`: lista providers vinculados
    - `DELETE /api/v1/user/linked-accounts/:provider`: desvincular (solo si queda otro método de login)
- [ ] **Client Credentials Grant** (máquina a máquina):
    - `POST /api/v1/oauth/m2m/token`: `client_id` + `client_secret` en body o Basic Auth header
    - Validar contra `M2M_CLIENT_ID` y `M2M_CLIENT_SECRET` del `.env` (un único cliente para el demo)
    - Comparación con `crypto.timingSafeEqual` (mismo patrón que Basic Auth)
    - Devuelve AT sin `sub` de usuario, con scopes fijos del cliente (`read:data`, `write:data`)
    - Usar para demos de microservicios o scripts de automatización
- [ ] **Device Authorization Grant — RFC 8628**:
    - `POST /api/v1/oauth/device/code`: genera `device_code` (UUID largo), `user_code` (8 chars: `ABCD-1234`), almacena en `device_codes`, devuelve `verification_uri`, `expires_in=300`, `interval=5`
    - `GET /api/v1/oauth/device/verify`: página web donde el usuario ingresa el `user_code` y aprueba
    - `POST /api/v1/oauth/device/token`: polling — responde `authorization_pending`, `slow_down`, o AT cuando el usuario aprueba
    - Demo en dashboard: simula un CLI con countdown y campo para ingresar el `user_code`
- [ ] **Implicit Flow — Demostración Histórica**:
    - Implementación mínima que devuelve AT en el fragment de la URL de redirect
    - Dashboard muestra: el token en la barra del navegador, qué ve el historial del browser, qué ven los logs del servidor de analytics
    - Explica por qué OAuth 2.1 lo eliminó completamente
- [ ] **Panel Fase 5 en dashboard**:
    - Botones para iniciar cada flujo con visualización del estado
    - Device Grant: CLI simulado con código visible y estado de aprobación en tiempo real (polling visible)
    - Comparativa de flujos: tabla de cuándo usar cada uno

---

### Fase 5.5: WebAuthn / Passkeys (FIDO2)
- [ ] **Registro** (`POST /api/v1/webauthn/register/options` + `/verify`):
    - Generar opciones con `@simplewebauthn/server`
    - Verificar respuesta del authenticator → guardar `credential_id`, `public_key`, `counter`
    - Log `PASSKEY_REGISTRADA`
- [ ] **Login** (`POST /api/v1/webauthn/authenticate/options` + `/verify`):
    - Verificar firma biométrica → verificar que `counter` sea mayor al guardado (anti-clonación) → actualizar `counter`
    - Log `PASSKEY_LOGIN`
- [ ] Soporte a múltiples credenciales por usuario (varios dispositivos)
- [ ] Dashboard: QR code para registrar una Passkey desde el móvil
- [ ] Comparativa educativa: `password_hash` comprometida en una brecha = todos expuestos; `public_key` comprometida = solo esa credencial, la clave privada nunca salió del dispositivo

---

### Fase 5.6: MFA / TOTP con Step-up Authentication
- [ ] **Setup**:
    - `POST /api/v1/mfa/setup`: generar secret TOTP con `otplib`, devolver QR code (PNG base64) compatible con Google Authenticator
    - `POST /api/v1/mfa/enable`: verificar primer OTP para confirmar setup correcto → `mfa_enabled=1` → generar 8 códigos de recuperación → log `MFA_ACTIVADO`
    - Los 8 códigos de recuperación se muestran **una sola vez** → se almacenan hasheados en `mfa_recovery_codes`
- [ ] **Login con MFA**:
    - Login en dos pasos: password → responder con `mfa_required: true` + `mfa_session_token` temporal (5min) → frontend envía OTP
    - `POST /api/v1/mfa/verify`: validar OTP o código de recuperación → si código de recuperación, marcar como usado → emitir AT + RT definitivos
    - Log `MFA_VERIFICADO` / `MFA_FALLIDO` / `MFA_RECUPERACION_USADA`
- [ ] **Step-up Authentication**:
    - Para acciones sensibles: `PATCH /api/v1/user/password`, `GET /api/v1/mfa/recovery-codes`, `DELETE /api/v1/user/me`
    - El servidor exige un OTP fresco (< 5min de antigüedad) aunque ya haya sesión activa
    - `POST /api/v1/mfa/step-up`: valida OTP → devuelve `step_up_token` como **JWT firmado de 10min** (no se guarda en BD — la firma garantiza autenticidad)
    - Middleware `requireStepUp`: verifica `step_up_token` en el request (valida firma + expiración + `type: "step_up"`)
- [ ] **Login de dos pasos — `mfa_session_token`**:
    - Tras verificar contraseña con MFA activo: emitir `mfa_session_token` como **JWT firmado de 5min** (no se guarda en BD)
    - Payload: `{ sub, type: "mfa_session", iat, exp }` — solo válido para el endpoint `/mfa/verify`
    - El endpoint `/mfa/verify` lo verifica antes de emitir los tokens definitivos AT + RT

> [!IMPORTANT]
> **Credenciales Gmail**: Esta fase incluye Magic Links — pedir al usuario `GMAIL_USER` y `GMAIL_APP_PASSWORD` antes de implementar el envío real de emails. En desarrollo, todos los tokens siguen apareciendo en los logs.

---

### Fase 5.7: Magic Links / Passwordless
- [ ] `POST /api/v1/magic/send`:
    - Verificar que el email existe en `users`
    - Generar token aleatorio (`crypto.randomBytes(32)`), almacenar hash en `email_tokens` con `type="MAGIC_LINK"`, TTL 10min
    - **Dev**: imprimir link completo en log con `pino` (nivel `info`): `"[MAGIC LINK] URL: http://..."`
    - **Prod**: enviar email real con Nodemailer + Gmail SMTP
    - Responder siempre con el mismo mensaje (no revelar si el email existe): `"Si el email está registrado, recibirás un enlace"`
    - Log `MAGIC_LINK_ENVIADO`
- [ ] `GET /api/v1/magic/verify?token=...`:
    - Buscar token por hash, verificar que no esté usado ni expirado
    - Marcar como usado (`used_at=now`) + emitir AT + RT (transacción)
    - Log `MAGIC_LINK_VERIFICADO` / `MAGIC_LINK_EXPIRADO`
- [ ] Configurar Nodemailer con Gmail SMTP (`GMAIL_USER` + `GMAIL_APP_PASSWORD`)
- [ ] Plantillas de email en HTML (Magic Link, verificación de cuenta, reset de contraseña)

---

### Fase 5.8: Password Reset y Verificación de Email
- [ ] **Verificación de email** (flujo ya iniciado en Fase 3, completar aquí con email real):
    - Enviar email de verificación real tras el registro (Nodemailer + Gmail SMTP)
    - Reenvío si el token expiró: `POST /api/v1/auth/resend-verification` → log `VERIFICACION_REENVIADA`
    - Al completar la verificación → log `VERIFICACION_COMPLETADA`
- [ ] **Password Reset**:
    - `POST /api/v1/auth/forgot-password`: buscar usuario por email → generar token (`type="PASSWORD_RESET"`, TTL 1h) → enviar email con link
    - Responder siempre con el mismo mensaje (no revelar si el email existe)
    - `POST /api/v1/auth/reset-password`: validar token → actualizar `password_hash` → invalidar el token → revocar TODAS las familias de tokens activas (logout global por seguridad) → log `RESET_COMPLETADO`
- [ ] **Cambio de contraseña** (usuario autenticado):
    - `PATCH /api/v1/user/password`: requiere step-up MFA → verificar contraseña actual → actualizar hash → revocar todas las familias de tokens excepto la actual
- [ ] **Panel Fase 5.8 en dashboard**: flujo visual completo de forgot-password con estados

---

### Fase 5.9: Account Linking — Dashboard Completo
- [ ] Panel en dashboard:
    - Lista de providers vinculados del usuario actual (GitHub, Google)
    - Estado de cada uno: email del provider, fecha de vinculación
    - Botón "Vincular con GitHub/Google" (inicia flujo OAuth desde el dashboard)
    - Botón "Desvincular" (con confirmación — solo si queda otro método)
    - Flujo de confirmación cuando el email ya existe en otro provider
- [ ] Tests: vincular, desvincular, intento de desvincular único método (debe fallar)

---

### Fase 5.10: PASETO v4 — Comparativa con JWT
- [ ] Al arrancar: leer `PASETO_PRIVATE_KEY` y `PASETO_PUBLIC_KEY` del `.env`
    - Si no existen → generar par Ed25519 → imprimir ambas en logs en español → `process.exit(0)` con instrucción clara: `"Copia las claves al .env y reinicia el servidor"`
    - Si existen → cargar y continuar (nunca regenerar automáticamente — cambiarlas invalidaría tokens activos)
- [ ] `POST /api/v1/paseto/sign`: firmar payload con PASETO v4 `public`
- [ ] `POST /api/v1/paseto/verify`: verificar y devolver claims
- [ ] Dashboard side-by-side:
    - Mismo payload → JWT (HS256) vs PASETO v4 (EdDSA)
    - Intento de modificar el campo `alg` en JWT → puede funcionar en modo inseguro
    - Intento equivalente en PASETO → falla por diseño (no existe campo `alg`)
    - Explicación: versión `v4.public` es parte del token, no configurable
- [ ] Tests: verificar que `alg:none` en PASETO es imposible por diseño de protocolo

---

### Fase 5.11: DPoP — Tokens Sender-Constrained (RFC 9449) — Implementación Completa
- [ ] **Frontend** (Alpine.js + Web Crypto API):
    - Generar par de claves ECDSA P-256 efímeras en el browser
    - Para cada request DPoP: firmar un JWT proof con `{ htm, htu, iat, jti }` usando la clave privada
    - Adjuntar proof en header `DPoP: <proof_jwt>`
- [ ] **Backend**:
    - `POST /api/v1/dpop/token`: verificar proof DPoP → extraer JWK público → enlazar token emitido al JWK público del cliente
    - `GET /api/v1/dpop/protected`: verificar que el `DPoP` proof del request corresponde a la clave pública del token (binding)
    - **Prevención de replay**: verificar `iat` del proof dentro de ±30 segundos + verificar que el `jti` del proof NO está en `dpopReplayCache` → insertar `jti` con TTL 60s en el cache
    - El `dpopReplayCache` es un `Map<string, number>` (jti → expiresAt) en memoria, compartido con el Fase 2 (mismo módulo de cache)
- [ ] Dashboard:
    - Mostrar las claves efímeras generadas en el browser
    - Demostración: robar el token DPoP y enviarlo sin el proof → 401
    - Comparar con Bearer Token: robar el Bearer → 200 (en modo inseguro)
    - Marcar como "Estándar emergente — OAuth 2.1 adoptará DPoP como recomendado"
- [ ] Tests: token sin proof → 401; proof con clave incorrecta → 401; proof correcto → 200; replay del mismo proof → 401

---

### Fase 5.12: Autorización — RBAC, Scopes y Resource-level
- [ ] **Middleware de roles** (`requireRole(...roles: UserRole[])`):
    - Extrae `roles` del JWT/session
    - Si el rol del usuario no está en la lista → 403 con `{ code: "SIN_PERMISO", error: "No tienes permiso para esta acción" }`
- [ ] **Middleware de scopes** (`requireScope(...scopes: string[])`):
    - Para API Keys y OAuth tokens — verifica que el token tenga todos los scopes requeridos
    - 403 si falta alguno
- [ ] **Middleware de ownership** (`requireOwnership(getResourceOwnerId)`):
    - Función que extrae el `user_id` del recurso y lo compara con el `sub` del token
    - Admin puede acceder a cualquier recurso; otros usuarios solo a los propios
- [ ] **Rutas de demostración**:
    - `GET /api/v1/admin/users` — requiere `admin` → 200; cualquier otro rol → 403; sin sesión → 401
    - `GET /api/v1/editor/content` — requiere `admin` o `editor` → 200; `user`/`viewer` → 403
    - `GET /api/v1/user/me` — cualquier autenticado, solo sus propios datos
    - `DELETE /api/v1/admin/users/:id` — solo `admin`; log `CUENTA_ELIMINADA` con `{ initiatedBy: adminId }`
- [ ] **Admin: gestión de usuarios**:
    - `GET /api/v1/admin/users`: lista paginada con filtros por rol, estado, verificación
    - `POST /api/v1/admin/users/:id/unlock`: desbloquear cuenta bloqueada por lockout → log `CUENTA_DESBLOQUEADA`
- [ ] Dashboard: matriz visual roles × endpoints. Cambiar rol simulado → ver qué rutas quedan en 403 vs 200
- [ ] Documentar diferencia semántica: **401 Unauthorized** (no autenticado — falta o token inválido) vs **403 Forbidden** (autenticado — sin permiso)

---

### Fase 6: Frontend Lab — Dashboard Educativo Completo (Alpine.js)
- [ ] Estructura SPA con Alpine.js: tabs por cada sistema de auth, store global para estado de sesión y modo inseguro/seguro
- [ ] **Timeline Histórica Interactiva**: nodos `1994→2025`, cada uno con explicación de qué vulnerabilidad motivó el cambio. Clic → navega al tab del sistema
- [ ] **Modo Inseguro ↔ Seguro** (Alpine.js store + API del servidor):
    - Switch visible solo en `NODE_ENV=development`
    - Panel de ataques: botones pre-configurados para `alg:none`, secreto débil, token manipulado
- [ ] **Visualizador de Token Storage**: tres columnas interactivas (`localStorage` / `sessionStorage` / `HttpOnly Cookie`) con simulación de XSS que muestra qué puede robar
- [ ] **Comparativa PASETO vs JWT**: side-by-side con intento de ataque en vivo
- [ ] **Device Grant Demo**: panel que simula un terminal CLI con código de activación y estado de polling visible
- [ ] **Request Builder integrado**: construir y enviar requests a cualquier endpoint, ver headers completos de request y response
- [ ] **Security Score**: lee headers de cada respuesta y genera puntuación visual (`HSTS`, `CSP`, `X-Frame-Options`, `Referrer-Policy`)
- [ ] **Dashboard Admin** (solo rol `admin`):
    - Lista de usuarios con estado de cuenta
    - Panel de anomalías con filtros
    - Estado de claves JWT activas

---

### Fase 6.5: GDPR y Privacidad
- [ ] `DELETE /api/v1/user/me` (requiere step-up MFA si está activo):
    - Soft-delete del usuario (`deleted_at=now`)
    - Hard-delete: `sessions`, `refresh_token_families`, `email_tokens`, `linked_identities`, `webauthn_credentials`, `mfa_recovery_codes`, `api_keys`
    - `audit_logs`: anonimizar (`user_id→NULL`, `ip_hash→NULL`, `user_agent→NULL`) — no borrar (necesarios para estadísticas)
    - Log `CUENTA_ELIMINADA`
    - Todo en una sola transacción
- [ ] Hashing de IPs en todos los puntos de captura: `SHA-256(ip + IP_HASH_SALT)` — nunca guardar IP en claro en ninguna tabla
- [ ] Minimización de datos en JWT: Access Token solo lleva `sub` (user_id), `jti`, `kid`, `roles` — sin email, sin nombre, sin PII
- [ ] Dashboard GDPR: panel "Mis Datos" que muestra qué datos están almacenados con botón "Eliminar mi cuenta"

---

### Fase 7: Detección de Anomalías
- [ ] Función de análisis sobre `audit_logs` (ejecutada sincrónicamente en cada login fallido):
    - **Credential stuffing**: > 10 `LOGIN_FALLIDO` desde diferentes `ip_hash` en 5 minutos → insertar evento `ANOMALIA_CREDENTIAL_STUFFING` + notificar admin por log de nivel `warn`
    - **Brute force**: > 5 `LOGIN_FALLIDO` para el mismo `user_id` en 10 minutos → `ANOMALIA_FUERZA_BRUTA` + `CUENTA_BLOQUEADA`
    - **Sesión inusual**: mismo `family_id` usado desde más de 2 `ip_hash` distintas en 1 hora → `ANOMALIA_SESION_INUSUAL`
- [ ] `GET /api/v1/admin/anomalies` (solo `admin`): lista paginada de eventos de anomalía con filtros por `type` y rango de fechas
- [ ] Dashboard admin: panel de anomalías con indicador de severidad y metadata del evento

---

### Fase 8: Testing de Alta Fidelidad
- [ ] **Tests de cada sistema** (Supertest): flujo completo incluyendo casos de error
- [ ] **Tests de ataques JWT**: `alg:none` → 401; Algorithm Confusion → 401; Timing Attack (medir diferencia estadística entre `===` y `timingSafeEqual`)
- [ ] **Family Tracking**: RT reutilizado → 401 + familia revocada + log `TOKEN_ROBO_DETECTADO`
- [ ] **Race condition**: `Promise.all([refresh(), refresh()])` con el mismo RT → solo un 200, el otro 401
- [ ] **Account lockout**: 5 intentos fallidos → 423 Locked; intento 6 → mismo 423; admin unlock → login exitoso
- [ ] **Email verification**: login sin verificar → 403 con `code: "EMAIL_NO_VERIFICADO"`
- [ ] **JWT kid rotation**: token firmado con clave retirada → todavía válido (activo=0 = solo verifica)
- [ ] **RBAC**: admin → 200 en `/admin/*`; user → 403; anónimo → 401
- [ ] **DPoP**: sin proof → 401; proof clave incorrecta → 401; replay mismo proof → 401; correcto → 200
- [ ] **GDPR**: DELETE elimina todas las tablas asociadas en una transacción; audit_logs quedan anonimizados
- [ ] **Anomaly detection**: simular 10 logins fallidos → verificar evento de anomalía generado
- [ ] **Device Grant**: flujo completo con polling simulado y aprobación
- [ ] **Expiración exacta**: `jest.useFakeTimers()` — AT expira al segundo 901 exacto; RT al día 8 exacto
- [ ] **Fuzz testing**: tokens malformados, Base64 inválido, JSON truncado en payload, headers faltantes
- [ ] **Paginación**: verificar cursor correcto, hasMore correcto, límite respetado
- [ ] **Coverage**: threshold `≥ 80%` en líneas y branches — pipeline de CI falla si no se cumple

---

### Fase 9: CI/CD Pipeline (GitHub Actions)
- [ ] `.github/workflows/ci.yml` (ejecuta en cada push y PR):
    - `npm audit --audit-level=high` — falla si hay dependencias con CVE crítico
    - `npx semgrep --config=auto src/` — análisis estático de seguridad
    - `npx jest --coverage --coverageThreshold='{"global":{"lines":80,"branches":80}}'`
    - `docker build .` — verifica que el Dockerfile es válido
- [ ] `.github/workflows/load.yml` (ejecuta solo en push a `main`):
    - `npx artillery run tests/load.yml`
- [ ] Badge de CI en `README.md`

---

### Fase 10: Documentación Técnica Final
- [ ] **Diagramas de secuencia Mermaid** (en `docs/diagrams/`):
    - Basic Auth, Session Token, JWT con Family Tracking, OAuth PKCE (GitHub + Google)
    - Device Authorization Grant, WebAuthn, TOTP, Magic Link, Password Reset, DPoP
- [ ] **Matriz de trade-offs** (`docs/comparativa.md`): tabla de todos los sistemas — seguridad, complejidad, UX, stateful/stateless, caso de uso ideal
- [ ] **Árbol de decisión** (`docs/cuando-usar.md`): guía "¿Qué auth usar?" según tipo de cliente, sensibilidad de datos, requisito de MFA, tipo de usuario (humano/máquina)
- [ ] **Checklist de producción** (`docs/produccion.md`): qué cambiar al ir a prod — HTTPS, secretos en vault, Redis para rate limit, CSP restrictivo, monitoreo externo
- [ ] **Mapa OWASP A2:2021** (`docs/owasp.md`): qué parte del proyecto mitiga cada sub-punto de Broken Authentication
- [ ] **Glosario** (`docs/glosario.md`): AuthN vs AuthZ, AT vs RT, PKCE, jti, kid, Family Tracking, DPoP, PASETO, BFF, Account Linking, Step-up Auth, JIT Provisioning
- [ ] **Referencias a estándares**: RFC 6749, RFC 7519, RFC 7617, RFC 8628, RFC 9449, RFC 7662, WebAuthn Level 2, FIDO2

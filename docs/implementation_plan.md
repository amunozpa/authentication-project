# Plan de Implementación: Maestro de Autenticación (Edición Definitiva)

Laboratorio de identidad y seguridad de grado producción. Cubre autenticación, autorización, privacidad y los estándares modernos de 2025 (Passkeys, DPoP, PASETO).

---

## Decisiones de Diseño Confirmadas

| Decisión | Elección |
|---|---|
| Lenguaje de código | TypeScript (estricto) |
| Idioma de logs y mensajes | **Español** |
| Frontend | Vanilla JS + **Alpine.js** (reactividad ligera sin framework pesado) |
| Persistencia | SQLite (`better-sqlite3`) |
| Email real | Nodemailer + Gmail SMTP — credenciales solicitadas al usuario cuando se necesiten |
| OAuth providers | **GitHub** y **Google** |
| DPoP | Implementación funcional completa (RFC 9449) |
| Estrategia de avance | Completar cada fase al 100% antes de continuar. Detenerse en la última fase completa si se alcanza el límite. |

---

## Objetivos del Laboratorio

### Autenticación (AuthN) — Verificar identidad
- **Basic Auth**: Protección contra Timing Attacks con `crypto.timingSafeEqual`.
- **Session Tokens**: Con expiración, audit log y account lockout por cuenta.
- **JWT Hardened**: Whitelist de algoritmos (solo `HS256`), `jti` por token, Family Tracking para detección de robo, `kid` para rotación de claves sin logout masivo, purga automática de tokens expirados.
- **API Keys (Stripe-style)**: Prefijo legible `sk_live_*`, hashing con bcrypt, scopes granulares, rotación y revocación.
- **OAuth 2.0 — Cuatro flujos con dos proveedores (GitHub + Google)**:
  - Authorization Code + PKCE (usuarios con browser) — GitHub y Google
  - Client Credentials Grant (máquina a máquina, sin usuario)
  - Device Authorization Grant — RFC 8628 (CLIs, Smart TVs, dispositivos sin browser)
  - Implicit Flow — demostración de POR QUÉ fue deprecado (token en URL → historial → logs)
- **Account Linking**: GitHub y Google apuntan a la misma cuenta si el email coincide.
- **WebAuthn / Passkeys (FIDO2)**: Registro y login biométrico (`@simplewebauthn/server`).
- **MFA/TOTP**: Con Step-up Authentication y 8 códigos de recuperación de un solo uso.
- **Magic Links / Passwordless**: Nodemailer + Gmail SMTP. En dev: log por consola. En prod: email real.
- **Verificación de email**: Al registrarse con contraseña, el usuario recibe un email de verificación antes de poder iniciar sesión.
- **Password Reset**: Flujo independiente de Magic Links — "Olvidé mi contraseña" → email → nuevo password.
- **PASETO v4**: Comparativa educativa con JWT. Elimina `alg:none` por diseño de protocolo.
- **DPoP (RFC 9449)**: Implementación funcional completa. Tokens sender-constrained que atan el token a la clave privada del cliente.

### Autorización (AuthZ) — Verificar permisos
- **RBAC**: Roles `admin`, `editor`, `user`, `viewer` en JWT claims y validados por middleware.
- **OAuth Scopes**: `read:profile`, `write:posts`, `admin:users` — control granular por endpoint.
- **Resource-level**: Middleware que verifica que el usuario solo accede a sus propios recursos.
- **Account Lockout**: Distinto al rate limiting por IP. Bloquea una cuenta específica tras N intentos fallidos, independientemente de la IP.

### Privacidad y Cumplimiento
- **GDPR**: Derecho al olvido completo, hashing de IPs (`SHA-256 + SALT`) en todos los logs, minimización de datos en JWT.
- **Detección de Anomalías**: Reglas sobre audit logs (credential stuffing, brute force, sesión anormal).

---

## Stack Tecnológico Completo

| Capa | Herramienta | Motivo |
|---|---|---|
| Runtime | Node.js + TypeScript (`tsx`) | Tipos explícitos en payloads JWT y contratos de auth |
| Framework | Express | Estándar, ampliamente conocido |
| Frontend JS | Alpine.js | Reactividad declarativa ligera, sin build step |
| Validación | Zod | Env vars + request bodies + tipos inferidos |
| Persistencia | `better-sqlite3` | Sin setup, persistente, transacciones síncronas |
| JWT | `jsonwebtoken` | Implementación de referencia, soporte `kid` |
| PASETO | `paseto` | Alternativa moderna a JWT |
| WebAuthn | `@simplewebauthn/server` + `@simplewebauthn/browser` | Estándar FIDO2 |
| OTP/MFA | `otplib` + `qrcode` | TOTP compatible con Google Authenticator |
| Hashing | `bcryptjs` | Contraseñas y API Keys |
| Email | `nodemailer` | Gmail SMTP para verificación, reset y Magic Links |
| Hardening | `helmet`, `cors`, `express-rate-limit` | Headers seguros, CORS estricto, rate limiting por IP |
| Logs | `pino` + `pino-pretty` | JSON estructurado + legible en dev. **Mensajes en español.** |
| API Docs | `swagger-ui-express` + `zod-to-openapi` | Documentación auto-generada desde esquemas Zod |
| Contenedores | Docker + docker-compose | Un solo comando para levantar el lab |
| CI/CD | GitHub Actions | Pipeline automático en cada push |
| Testing | Jest + Supertest + Artillery | Integración + carga |
| SAST | Semgrep + `npm audit` | Análisis estático de seguridad |
| Linting | ESLint + Prettier | Consistencia de código TypeScript |

---

## Arquitectura de Datos (SQLite — Schema Completo)

```sql
-- ============================================================
-- USUARIOS E IDENTIDADES
-- ============================================================

users
  id            TEXT PRIMARY KEY,           -- UUID v4
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT,                        -- NULL si solo usa OAuth
  roles         TEXT NOT NULL DEFAULT '["user"]', -- JSON array
  email_verified INTEGER NOT NULL DEFAULT 0, -- 0 = pendiente, 1 = verificado
  mfa_enabled   INTEGER NOT NULL DEFAULT 0,
  mfa_secret    TEXT,                        -- secret TOTP (cifrado en reposo)
  locked_until  INTEGER,                     -- timestamp UNIX. Account lockout por intentos fallidos
  created_at    INTEGER NOT NULL,
  deleted_at    INTEGER                      -- Soft delete para GDPR (NULL = activo)

-- Account Linking: N providers → 1 usuario
linked_identities
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id),
  provider      TEXT NOT NULL,               -- "github" | "google"
  provider_id   TEXT NOT NULL,               -- ID del usuario en el provider
  provider_email TEXT,
  access_token  TEXT,                        -- Token del provider (cifrado, para llamadas futuras a su API)
  linked_at     INTEGER NOT NULL,
  UNIQUE(provider, provider_id)

-- ============================================================
-- EMAIL Y VERIFICACIÓN
-- ============================================================

email_tokens                                 -- Verificación de cuenta + Password Reset + Magic Links
  id            TEXT PRIMARY KEY,
  token_hash    TEXT UNIQUE NOT NULL,        -- Hash del token enviado por email
  user_id       TEXT NOT NULL REFERENCES users(id),
  type          TEXT NOT NULL,               -- "VERIFY_EMAIL" | "PASSWORD_RESET" | "MAGIC_LINK"
  expires_at    INTEGER NOT NULL,
  used_at       INTEGER,                     -- NULL = no usado, timestamp = ya consumido
  created_at    INTEGER NOT NULL

-- Códigos de recuperación MFA (8 por usuario, un solo uso cada uno)
mfa_recovery_codes
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id),
  code_hash     TEXT NOT NULL,
  used_at       INTEGER                      -- NULL = disponible

-- ============================================================
-- SESIONES Y TOKENS
-- ============================================================

sessions                                     -- Session Token Auth clásico
  token_hash    TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id),
  expires_at    INTEGER NOT NULL,
  ip_hash       TEXT,                        -- SHA-256(ip + SALT) — GDPR
  user_agent    TEXT,
  created_at    INTEGER NOT NULL

refresh_token_families                       -- JWT Family Tracking + blacklisting por jti
  family_id     TEXT PRIMARY KEY,            -- UUID de la familia (persiste entre rotaciones)
  user_id       TEXT NOT NULL REFERENCES users(id),
  current_jti   TEXT NOT NULL,              -- jti del Refresh Token activo
  access_jti    TEXT NOT NULL,              -- jti del Access Token emitido en la última rotación
  kid           TEXT NOT NULL,              -- ID de la clave de firma usada (para rotación de claves)
  expires_at    INTEGER NOT NULL,
  revoked       INTEGER NOT NULL DEFAULT 0,
  revoked_at    INTEGER,
  revoked_reason TEXT,                      -- "logout" | "stolen" | "expired" | "global_logout"
  ip_hash       TEXT,
  created_at    INTEGER NOT NULL

jwt_signing_keys                            -- Soporte a múltiples claves activas (rotación sin logout masivo)
  kid           TEXT PRIMARY KEY,           -- Key ID (referenciado en header JWT)
  secret        TEXT NOT NULL,              -- Secreto cifrado
  active        INTEGER NOT NULL DEFAULT 1, -- 1 = acepta firma + verifica, 0 = solo verifica (deprecada)
  created_at    INTEGER NOT NULL,
  retired_at    INTEGER                     -- NULL = activa

-- ============================================================
-- API KEYS
-- ============================================================

api_keys
  id            TEXT PRIMARY KEY,
  key_hash      TEXT UNIQUE NOT NULL,        -- bcrypt hash de la key completa
  key_prefix    TEXT NOT NULL,               -- Primeros 8 chars en claro (para identificación: "sk_live_ab12...")
  user_id       TEXT NOT NULL REFERENCES users(id),
  name          TEXT NOT NULL,
  scopes        TEXT NOT NULL DEFAULT '[]',  -- JSON array de scopes
  last_used_at  INTEGER,
  created_at    INTEGER NOT NULL,
  revoked_at    INTEGER

-- ============================================================
-- OAUTH 2.0
-- ============================================================

oauth_states                                 -- PKCE: state + code_verifier con TTL corto
  state         TEXT PRIMARY KEY,
  code_verifier TEXT NOT NULL,
  provider      TEXT NOT NULL,               -- "github" | "google"
  redirect_uri  TEXT NOT NULL,
  expires_at    INTEGER NOT NULL,            -- TTL: 10 minutos
  created_at    INTEGER NOT NULL

device_codes                                 -- Device Authorization Grant (RFC 8628)
  device_code   TEXT PRIMARY KEY,            -- Código del dispositivo (largo, secreto)
  user_code     TEXT UNIQUE NOT NULL,        -- Código corto para el usuario (ej: "ABCD-1234")
  user_id       TEXT REFERENCES users(id),   -- NULL hasta que el usuario apruebe
  verification_uri TEXT NOT NULL,
  expires_at    INTEGER NOT NULL,
  interval      INTEGER NOT NULL DEFAULT 5,  -- Segundos mínimos entre polls
  last_poll_at  INTEGER,
  status        TEXT NOT NULL DEFAULT 'pending', -- "pending" | "approved" | "denied" | "expired"
  created_at    INTEGER NOT NULL

-- ============================================================
-- WEBAUTHN / PASSKEYS
-- ============================================================

webauthn_challenges                          -- Challenge temporal entre /options y /verify (TTL: 5 min)
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL REFERENCES users(id),
  challenge       TEXT NOT NULL,               -- Challenge base64url generado por @simplewebauthn
  type            TEXT NOT NULL,               -- "registration" | "authentication"
  expires_at      INTEGER NOT NULL,
  created_at      INTEGER NOT NULL

webauthn_credentials
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL REFERENCES users(id),
  credential_id   TEXT UNIQUE NOT NULL,
  public_key      TEXT NOT NULL,
  counter         INTEGER NOT NULL DEFAULT 0,  -- Para detectar clonación de credencial
  device_name     TEXT,
  created_at      INTEGER NOT NULL,
  last_used_at    INTEGER

-- ============================================================
-- AUDIT LOG
-- ============================================================

audit_logs                                   -- GDPR: IPs hasheadas, retención 90 días, purga automática
  id              TEXT PRIMARY KEY,
  timestamp       INTEGER NOT NULL,
  event           TEXT NOT NULL,             -- Ver catálogo de eventos abajo
  user_id         TEXT,                      -- NULL si evento pre-login
  ip_hash         TEXT,                      -- SHA-256(ip + IP_SALT) — nunca IP en claro
  user_agent      TEXT,
  country_code    TEXT,
  correlation_id  TEXT NOT NULL,             -- UUID del request (propagado en header X-Correlation-ID)
  metadata        TEXT                       -- JSON con detalles específicos del evento
```

### Catálogo de Eventos de Audit Log

```
REGISTRO_INICIADO           REGISTRO_VERIFICADO         REGISTRO_FALLIDO
LOGIN_EXITOSO               LOGIN_FALLIDO               LOGOUT
CUENTA_BLOQUEADA            CUENTA_DESBLOQUEADA
TOKEN_EMITIDO               TOKEN_RENOVADO              TOKEN_REVOCADO              TOKEN_ROBO_DETECTADO
CLAVE_JWT_ROTADA
API_KEY_CREADA              API_KEY_USADA               API_KEY_REVOCADA
MFA_ACTIVADO                MFA_VERIFICADO              MFA_FALLIDO                 MFA_RECUPERACION_USADA
PASSKEY_REGISTRADA          PASSKEY_LOGIN               PASSKEY_ELIMINADA
MAGIC_LINK_ENVIADO          MAGIC_LINK_VERIFICADO       MAGIC_LINK_EXPIRADO
VERIFICACION_ENVIADA        VERIFICACION_REENVIADA      VERIFICACION_COMPLETADA
OAUTH_INICIO                OAUTH_CALLBACK              CUENTA_VINCULADA
RESET_SOLICITADO            RESET_COMPLETADO
CUENTA_ELIMINADA            SESION_GLOBAL_CERRADA
ANOMALIA_CREDENTIAL_STUFFING    ANOMALIA_FUERZA_BRUTA   ANOMALIA_SESION_INUSUAL
```

---

## Patrones Arquitecturales Clave

### BFF (Backend for Frontend)
El frontend **nunca** maneja Access Tokens en JavaScript. El servidor Express actúa como BFF: Access Token en memoria del servidor (no en cookie, no en localStorage), Refresh Token en cookie `HttpOnly; Secure; SameSite=Strict`. El JS del browser solo recibe un estado de sesión. XSS no puede robar lo que JS no puede leer.

### Fail-Fast en Configuración
Al arrancar, Zod valida **todas** las variables de entorno. Si falta cualquier secret requerido o tiene formato inválido, el proceso termina con un error descriptivo en español antes de aceptar conexiones.

```typescript
// Ejemplo del comportamiento:
// ❌ Error de configuración: JWT_SECRET debe tener al menos 32 caracteres
// ❌ Error de configuración: GITHUB_CLIENT_ID es requerido
// ✅ Configuración validada. Servidor iniciando en puerto 3000
```

### Account Lockout vs Rate Limiting
Son mecanismos complementarios e independientes:
- **Rate limit (por IP)**: `express-rate-limit` — max 10 intentos en 15 minutos desde la misma IP
- **Account lockout (por cuenta)**: campo `locked_until` en `users` — bloquea la cuenta específica independientemente de la IP. Se desbloquea automáticamente después de 30 minutos o manualmente por un admin.

### JWT Key Rotation con `kid`
Cada JWT lleva en su header el `kid` (Key ID) de la clave que lo firmó. El servidor mantiene múltiples claves activas en `jwt_signing_keys`:
- **Activa (active=1)**: firma nuevos tokens + verifica tokens existentes
- **Retirada (active=0)**: solo verifica tokens existentes hasta que expiren

Al rotar la clave: crear nueva clave activa → retirar la anterior → los tokens viejos siguen siendo válidos durante su vida útil normal → sin logout masivo.

### Transacciones SQLite para Operaciones Críticas
Las siguientes operaciones se ejecutan en transacciones atómicas. Si cualquier paso falla, se revierte todo:
- Renovación de Refresh Token (actualizar `current_jti` + escribir en audit_log)
- Revocación de familia completa (marcar familia + registrar razón `TOKEN_ROBO_DETECTADO`)
- Eliminación de cuenta GDPR (borrar de 6 tablas + anonimizar audit_logs)
- Account Linking (buscar usuario + insertar linked_identity)
- Verificación de email (marcar token como usado + actualizar `email_verified`)

### Tokens Temporales Internos (sin tabla en BD)
Dos tokens de corta duración se implementan como **JWTs firmados con el mismo `JWT_SECRET`**, sin persistencia en BD. Su validez se garantiza únicamente por la firma y el tiempo de expiración:

- **`mfa_session_token`** (TTL: 5 minutos): emitido tras verificar la contraseña cuando el usuario tiene MFA activo. El frontend lo adjunta en el segundo paso del login para enviar el OTP. Payload: `{ sub, type: "mfa_session", iat, exp }`. No se puede reutilizar porque expira en 5 min y el login completo emite un AT/RT que lo reemplaza.
- **`step_up_token`** (TTL: 10 minutos): emitido por `POST /api/v1/mfa/step-up` tras verificar un OTP fresco. Permite acceder a rutas sensibles (cambiar contraseña, ver recovery codes, eliminar cuenta). Payload: `{ sub, type: "step_up", iat, exp }`. El middleware `requireStepUp` lo verifica en cada request sensible.

Ventaja: cero escrituras en BD, cero purga necesaria, cero estado compartido. La firma del servidor garantiza autenticidad.

### Variables de Entorno — Referencia Completa

```bash
# === SERVIDOR ===
PORT=3000
NODE_ENV=development          # "development" | "production"
FRONTEND_URL=http://localhost:3000

# === JWT ===
JWT_SECRET=<mínimo 32 chars aleatorios>
JWT_EXPIRY_ACCESS=15m
JWT_EXPIRY_REFRESH=7d

# === GDPR ===
IP_HASH_SALT=<salt aleatorio para SHA-256 de IPs>

# === OAUTH — GITHUB ===
GITHUB_CLIENT_ID=<desde github.com/settings/developers>
GITHUB_CLIENT_SECRET=<desde github.com/settings/developers>
GITHUB_CALLBACK_URL=http://localhost:3000/api/v1/oauth/github/callback

# === OAUTH — GOOGLE ===
GOOGLE_CLIENT_ID=<desde console.cloud.google.com>
GOOGLE_CLIENT_SECRET=<desde console.cloud.google.com>
GOOGLE_CALLBACK_URL=http://localhost:3000/api/v1/oauth/google/callback

# === OAUTH — CLIENT CREDENTIALS (M2M) ===
M2M_CLIENT_ID=<ID del cliente máquina>
M2M_CLIENT_SECRET=<secreto del cliente máquina, mínimo 32 chars>

# === EMAIL (pedido al usuario en Fase 5.6) ===
GMAIL_USER=tucuenta@gmail.com
GMAIL_APP_PASSWORD=<contraseña de aplicación, NO la contraseña de Gmail>
                   # Generar en: myaccount.google.com → Seguridad → Contraseñas de aplicaciones

# === PASETO (generadas automáticamente en Fase 5.10 si no existen) ===
PASETO_PRIVATE_KEY=<clave privada Ed25519 en base64>
PASETO_PUBLIC_KEY=<clave pública Ed25519 en base64>
# Si están vacías al arrancar la Fase 5.10, el servidor genera el par y lo imprime en logs
# para que el usuario las copie al .env — nunca se regeneran automáticamente tras el primer arranque
```

### Estrategia de Email (Nodemailer + Gmail SMTP)
- **Desarrollo** (`NODE_ENV=development`): el contenido del email se imprime en los logs (pino, nivel `info`). No se envía email real.
- **Producción** (`NODE_ENV=production`): requiere `GMAIL_USER` y `GMAIL_APP_PASSWORD` en `.env`. Las credenciales se solicitan al usuario cuando se llegue a la Fase 5.6/5.7.
- Todos los tokens enviados por email tienen TTL corto: verificación = 24h, password reset = 1h, magic link = 10min.

### DPoP Replay Protection (Sin tabla en BD)
Los JWT proofs de DPoP tienen una ventana de validez de ±30 segundos. Para evitar que el mismo proof se use dos veces dentro de esa ventana, se mantiene un **`Set` en memoria** con los `jti` de los proofs ya procesados:

```
dpopReplayCache: Map<jti, expiresAt>   // Limpieza cada 60 segundos
```

Al recibir un proof: verificar que su `jti` no esté en el cache → procesarlo → insertar `jti` con `expiresAt = now + 60s`. Un job interno purga entradas expiradas cada 60 segundos. Ventaja: cero escrituras en BD, latencia mínima. Limitación: en múltiples réplicas Docker el cache no se comparte (igual que el rate limiter). Solución en producción: Redis con TTL de 60 segundos.

### Distributed Rate Limiting
El rate limiter en memoria falla en múltiples réplicas Docker. Código estructurado para conectar Redis como store externo con un cambio de una línea de configuración. En esta versión: un solo proceso, rate limit en memoria es suficiente y se documenta la limitación.

### Purga Automática de Datos (Cumplimiento GDPR)
Job cada hora (`setInterval`):
- Elimina `webauthn_challenges` expirados (TTL 5 min — se acumulan si el usuario abandona el flujo)
- Elimina `email_tokens` expirados y usados
- Elimina `oauth_states` expirados
- Elimina `device_codes` expirados
- Elimina `sessions` expiradas
- Elimina `refresh_token_families` expiradas y revocadas (> 7 días desde revocación)
- Anonimiza `audit_logs` con más de 90 días (`user_id → NULL`, `ip_hash → NULL`, `user_agent → NULL`)

---

## Features del Frontend Lab (Alpine.js)

### Timeline Histórica Interactiva
Línea de tiempo: `1994 Basic Auth → 1997 Session Cookies → 2007 OAuth 1.0 → 2012 JWT → 2018 PKCE+Rotation → 2022 Passkeys → 2025 DPoP`. Cada nodo explica qué vulnerabilidad motivó el salto. Clic en un nodo navega al tab correspondiente.

### Modo Inseguro ↔ Seguro (Alpine.js store global)
Switch global que alterna entre implementación vulnerable (permite `alg:none`, secreto `"secret"`, comparación `===`) y segura. El servidor responde de forma diferente según el modo. Solo disponible en `NODE_ENV=development`.

### Dashboard de Administración (solo rol `admin`)
- Usuarios activos con roles y estado de verificación
- Panel de anomalías detectadas con filtros por tipo
- Métricas: intentos de login, tasa de éxito/fallo, tokens emitidos

### Otros Paneles del Lab
- JWT Decoder en tiempo real (pegar token → ver header/payload/firma)
- Visualizador de Token Storage: `localStorage` vs `sessionStorage` vs `HttpOnly Cookie`
- Comparativa PASETO vs JWT side-by-side
- Matrix RBAC: roles × endpoints con simulación interactiva
- Device Grant Demo: CLI simulado con código y countdown
- Request Builder integrado tipo Postman
- Security Score basado en headers de respuesta
- Timeline de vida de AT (15min) vs RT (7 días) con barra en vivo

---

## Paginación en Endpoints de Lista

Todos los endpoints que devuelven colecciones usan paginación por cursor (más eficiente que offset en SQLite):

```
GET /api/v1/user/sessions?limit=20&cursor=<last_id>
GET /api/v1/user/api-keys?limit=20&cursor=<last_id>
GET /api/v1/admin/anomalies?limit=50&cursor=<last_id>&type=ANOMALIA_FUERZA_BRUTA
GET /api/v1/admin/users?limit=20&cursor=<last_id>
```

Respuesta estándar: `{ data: [...], nextCursor: "...", hasMore: true }`

---

## Endpoints API Completos (v1)

```
GET  /health                              — Health check para Docker
GET  /api-docs                            — Swagger UI

# Auth Clásica
GET  /api/v1/basic/protected              — Basic Auth (demo)
POST /api/v1/auth/register                — Registro con email + password (envía verificación)
GET  /api/v1/auth/verify-email            — Verificar email con token
POST /api/v1/auth/login                   — Login con email + password
POST /api/v1/auth/forgot-password         — Solicitar reset de contraseña
POST /api/v1/auth/reset-password          — Establecer nueva contraseña con token
POST /api/v1/auth/logout                  — Logout (revoca familia de tokens)
POST /api/v1/auth/resend-verification     — Reenviar email de verificación si el token expiró

# Sesiones Clásicas (Session Token)
POST /api/v1/session/login                — Login con generación de session token
GET  /api/v1/session/protected            — Ruta protegida por session token

# JWT
POST /api/v1/jwt/refresh                  — Renovar AT con RT (Family Tracking)
POST /api/v1/jwt/logout-all               — Cerrar sesión en todos los dispositivos
GET  /api/v1/jwt/sessions                 — Lista de sesiones activas (paginada)

# OAuth 2.0
GET  /api/v1/oauth/github                 — Iniciar Authorization Code + PKCE (GitHub)
GET  /api/v1/oauth/github/callback        — Callback GitHub
GET  /api/v1/oauth/google                 — Iniciar Authorization Code + PKCE (Google)
GET  /api/v1/oauth/google/callback        — Callback Google
POST /api/v1/oauth/m2m/token              — Client Credentials Grant
POST /api/v1/oauth/device/code            — Device Authorization Grant — solicitar códigos
POST /api/v1/oauth/device/token           — Device Authorization Grant — polling
GET  /api/v1/oauth/device/verify          — Página de verificación para usuario (user_code)

# WebAuthn / Passkeys
POST /api/v1/webauthn/register/options    — Generar opciones de registro
POST /api/v1/webauthn/register/verify     — Verificar y guardar credencial
POST /api/v1/webauthn/authenticate/options — Generar opciones de login
POST /api/v1/webauthn/authenticate/verify  — Verificar firma biométrica

# MFA / TOTP
POST /api/v1/mfa/setup                    — Generar QR y secret TOTP
POST /api/v1/mfa/enable                   — Confirmar setup con primer OTP
POST /api/v1/mfa/verify                   — Verificar OTP en login
POST /api/v1/mfa/step-up                  — Step-up auth para acciones sensibles
GET  /api/v1/mfa/recovery-codes           — Ver/regenerar códigos de recuperación (requiere step-up)

# Magic Links / Passwordless
POST /api/v1/magic/send                   — Enviar magic link (Gmail SMTP)
GET  /api/v1/magic/verify                 — Validar magic link y crear sesión

# API Keys
POST /api/v1/keys                         — Crear API Key con nombre y scopes
GET  /api/v1/keys                         — Listar API Keys (paginada)
POST /api/v1/keys/:id/revoke              — Revocar API Key

# PASETO (demo educativo)
POST /api/v1/paseto/sign                  — Firmar payload con PASETO v4
POST /api/v1/paseto/verify                — Verificar token PASETO

# DPoP (RFC 9449)
POST /api/v1/dpop/token                   — Emitir token con DPoP binding
GET  /api/v1/dpop/protected               — Recurso protegido que requiere proof DPoP

# Perfil y Cuenta
GET  /api/v1/user/me                      — Perfil del usuario autenticado
PATCH /api/v1/user/password               — Cambiar contraseña (requiere step-up)
GET  /api/v1/user/linked-accounts         — Listar cuentas OAuth vinculadas
DELETE /api/v1/user/linked-accounts/:provider — Desvincular provider OAuth
DELETE /api/v1/user/me                    — Eliminar cuenta completa (GDPR)

# Editor (requiere rol admin o editor)
GET  /api/v1/editor/content               — Recurso demo para rol editor

# Admin (requiere rol admin)
GET  /api/v1/admin/users                  — Lista de usuarios (paginada)
POST /api/v1/admin/users/:id/unlock       — Desbloquear cuenta
DELETE /api/v1/admin/users/:id            — Eliminar usuario (admin)
GET  /api/v1/admin/anomalies              — Eventos anómalos (paginada, con filtros)
POST /api/v1/admin/keys/rotate            — Rotar clave de firma JWT
```

---

## Plan de Verificación

### Tests de Integración y Seguridad (Jest + Supertest)
- Flujo completo de cada sistema de auth incluyendo casos de error
- `alg:none`, Algorithm Confusion, Timing Attack en comparación de tokens
- Family Tracking: RT reutilizado → familia revocada → usuario forzado a re-login
- Race condition: `Promise.all` con el mismo RT — solo una renovación debe triunfar
- Account lockout: N intentos fallidos → cuenta bloqueada → unlock por admin
- Email verification: usuario no puede hacer login sin verificar email
- GDPR: DELETE elimina todos los registros, audit_logs quedan anonimizados
- JWT kid rotation: tokens firmados con clave retirada siguen siendo válidos durante su vida útil
- RBAC: admin → 200, user → 403, anónimo → 401 en rutas protegidas
- DPoP: token válido sin proof → 401; proof con clave incorrecta → 401; proof correcto → 200
- Coverage threshold: **≥ 80%** en líneas y branches — bloquea CI si no se cumple

### Tests de Carga (Artillery)
- 100 usuarios concurrentes en `/api/v1/auth/login`
- Refresh masivo concurrente — verifica Family Tracking bajo presión
- Polling Device Grant — verifica comportamiento bajo múltiples dispositivos

### CI/CD (GitHub Actions)
```yaml
on: [push, pull_request]
jobs:
  calidad:
    - npm audit --audit-level=high
    - npx semgrep --config=auto src/
    - npx jest --coverage
  carga:                              # Solo en rama main
    - npx artillery run tests/load.yml
  docker:
    - docker build .                  # Verifica que el Dockerfile es válido
```

---

> [!CAUTION]
> El "Modo Inseguro" y el endpoint `POST /api/v1/admin/keys/rotate` están protegidos con `NODE_ENV=development`. El servidor rechaza estas operaciones en producción.

> [!IMPORTANT]
> **Credenciales de Gmail**: Se pedirán al usuario cuando se llegue a la Fase 5.6 (Magic Links). Requiere `GMAIL_USER` (cuenta Gmail) y `GMAIL_APP_PASSWORD` (contraseña de aplicación, no la contraseña de Gmail). El `.env.example` documenta dónde configurarlas.

> [!NOTE]
> **Estrategia de avance**: Cada fase se completa al 100% (código + tests + dashboard) antes de continuar con la siguiente. Si se alcanza el límite de uso, el proyecto queda en un estado funcional en la última fase completada.

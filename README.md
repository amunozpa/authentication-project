# Auth Lab — Maestro de Autenticación

[![CI](https://github.com/amunozpa/authentication-project/actions/workflows/ci.yml/badge.svg)](https://github.com/amunozpa/authentication-project/actions/workflows/ci.yml)
[![Load Tests](https://github.com/amunozpa/authentication-project/actions/workflows/load.yml/badge.svg)](https://github.com/amunozpa/authentication-project/actions/workflows/load.yml)
[![Coverage: Lines ≥80%](https://img.shields.io/badge/coverage-lines%20%E2%89%A580%25-brightgreen)](#)
[![Node.js 20](https://img.shields.io/badge/node-20-brightgreen)](https://nodejs.org)

Laboratorio de identidad y seguridad de grado producción. Implementa y compara **15+ sistemas de autenticación modernos** en un solo proyecto educativo.

---

## Stack

| Capa | Herramienta |
|---|---|
| Runtime | Node.js 20 + TypeScript (strict) |
| Framework | Express 4 |
| Frontend | Alpine.js (sin build step) |
| Persistencia | SQLite (`better-sqlite3`) |
| JWT | `jsonwebtoken` (HS256, kid rotation, Family Tracking) |
| PASETO | `paseto` v3 (tokens v4 — EdDSA/Ed25519) |
| WebAuthn | `@simplewebauthn/server` |
| MFA/TOTP | `otplib` |
| Email | `nodemailer` + Gmail SMTP |
| Logs | `pino` + `pino-pretty` (en español) |

---

## Requisitos

- **Node.js ≥ 18** (verificar con `node --version`)
- **Visual Studio Build Tools** con "Desktop development with C++" (Windows) — requerido por `better-sqlite3`
- **Docker Desktop** (opcional — para `docker-compose`)

---

## Inicio rápido

### 1. Instalar dependencias

```bash
npm install
```

### 2. Configurar variables de entorno

```bash
cp .env.example .env
```

Editar `.env` y completar como mínimo:

```bash
# Generar JWT_SECRET (mínimo 32 chars):
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Generar IP_HASH_SALT (mínimo 16 chars):
node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
```

### 3. Arrancar en desarrollo (hot-reload)

```bash
npm run dev
```

### 4. Con Docker

```bash
docker-compose up --build
```

---

## Scripts disponibles

| Comando | Descripción |
|---|---|
| `npm run dev` | Servidor con hot-reload (nodemon + tsx) |
| `npm start` | Servidor sin hot-reload |
| `npm run build` | Compilar TypeScript a `dist/` |
| `npm run lint` | ESLint sobre `src/` |
| `npm run lint:fix` | ESLint con corrección automática |
| `npm run format` | Prettier sobre `src/` |
| `npm test` | Jest — todos los tests |
| `npm run test:coverage` | Jest con reporte de cobertura (umbral: 80%) |

---

## Variables de entorno

| Variable | Requerida | Descripción |
|---|---|---|
| `PORT` | No (default: 3000) | Puerto del servidor |
| `NODE_ENV` | No (default: development) | Ambiente de ejecución |
| `FRONTEND_URL` | No (default: http://localhost:3000) | Origen permitido por CORS |
| `JWT_SECRET` | **Sí** | Secreto para firmar JWTs (mín. 32 chars) |
| `JWT_EXPIRY_ACCESS` | No (default: 15m) | Expiración del Access Token |
| `JWT_EXPIRY_REFRESH` | No (default: 7d) | Expiración del Refresh Token |
| `IP_HASH_SALT` | **Sí** | Salt para hashing de IPs (GDPR, mín. 16 chars) |
| `GITHUB_CLIENT_ID` | Fase 5 | OAuth App de GitHub |
| `GITHUB_CLIENT_SECRET` | Fase 5 | Secret de OAuth App de GitHub |
| `GOOGLE_CLIENT_ID` | Fase 5 | OAuth 2.0 Client de Google |
| `GOOGLE_CLIENT_SECRET` | Fase 5 | Secret de OAuth 2.0 de Google |
| `M2M_CLIENT_ID` | Fase 5 | Client Credentials Grant |
| `M2M_CLIENT_SECRET` | Fase 5 | Secret del client M2M |
| `GMAIL_USER` | Fase 5.7 | Correo Gmail para envío de emails |
| `GMAIL_APP_PASSWORD` | Fase 5.7 | App Password de Gmail (requiere 2FA) |
| `PASETO_PRIVATE_KEY` | Fase 5.10 | Clave Ed25519 privada (generada automáticamente) |
| `PASETO_PUBLIC_KEY` | Fase 5.10 | Clave Ed25519 pública (generada automáticamente) |

---

## Endpoints implementados

| Fase | Método | Ruta | Descripción |
|---|---|---|---|
| 1 | GET | `/api/v1/health` | Estado del servidor |
| 3 | POST | `/api/v1/auth/register` | Registro con verificación de email |
| 3 | POST | `/api/v1/auth/login` | Login JWT (Basic → AT + RT) |
| 3 | POST | `/api/v1/auth/logout` | Revocar refresh token |
| 3 | GET | `/api/v1/auth/verify-email` | Verificar email con token |
| 3 | POST | `/api/v1/session/login` | Login con Session Token clásico |
| 3 | POST | `/api/v1/session/logout` | Cerrar sesión (session token) |
| 3 | GET | `/api/v1/session/protected` | Ruta protegida con session token |
| 3 | POST | `/api/v1/keys` | Crear API Key con scopes |
| 3 | GET | `/api/v1/keys` | Listar API Keys del usuario |
| 3 | DELETE | `/api/v1/keys/:id` | Revocar API Key |
| 3 | GET | `/api/v1/keys/protected` | Ruta protegida con API Key + scope |
| 4 | POST | `/api/v1/auth/refresh` | Renovar AT con RT (Family Tracking) |
| 4 | POST | `/api/v1/auth/logout-all` | Revocar todas las sesiones |
| 4 | GET | `/api/v1/auth/sessions` | Listar sesiones activas |
| 4 | GET | `/api/v1/admin/keys` | Listar claves JWT activas |
| 4 | POST | `/api/v1/admin/keys/rotate` | Rotar clave JWT (solo admin/dev) |
| 5 | GET | `/api/v1/oauth/github` | Iniciar OAuth GitHub (PKCE) |
| 5 | GET | `/api/v1/oauth/google` | Iniciar OAuth Google (PKCE) |
| 5 | POST | `/api/v1/oauth/m2m/token` | Client Credentials Grant |
| 5 | POST | `/api/v1/oauth/device/code` | Device Authorization Grant |
| 5 | GET | `/api/v1/user/me` | Perfil del usuario autenticado |
| 5 | GET | `/api/v1/user/linked-accounts` | Cuentas OAuth vinculadas |
| 5 | GET | `/api/v1/user/link/:provider` | Iniciar vinculación de cuenta OAuth |
| 5.5 | POST | `/api/v1/webauthn/register/options` | WebAuthn registro — options |
| 5.5 | POST | `/api/v1/webauthn/register/verify` | WebAuthn registro — verificar |
| 5.5 | POST | `/api/v1/webauthn/login/options` | WebAuthn login — options |
| 5.5 | POST | `/api/v1/webauthn/login/verify` | WebAuthn login — verificar |
| 5.6 | GET | `/api/v1/mfa/status` | Estado de MFA del usuario |
| 5.6 | POST | `/api/v1/mfa/setup` | Generar secreto TOTP + QR |
| 5.6 | POST | `/api/v1/mfa/enable` | Activar TOTP + generar recovery codes |
| 5.6 | DELETE | `/api/v1/mfa/disable` | Desactivar TOTP |
| 5.6 | POST | `/api/v1/mfa/verify` | Verificar código TOTP (login step 2) |
| 5.6 | POST | `/api/v1/mfa/recovery` | Usar recovery code de un solo uso |
| 5.6 | POST | `/api/v1/mfa/step-up` | Elevar privilegios 10 min |
| 5.6 | GET | `/api/v1/mfa/protected` | Ruta con step-up requerido |
| 5.7 | POST | `/api/v1/magic/request` | Solicitar magic link por email |
| 5.7 | GET | `/api/v1/magic/verify` | Verificar magic link → AT + RT |
| 5.8 | POST | `/api/v1/auth/forgot-password` | Solicitar email de reset |
| 5.8 | POST | `/api/v1/auth/reset-password` | Restablecer password con token |
| 5.11 | GET | `/api/v1/dpop/info` | Info sobre DPoP |
| 5.11 | POST | `/api/v1/dpop/token` | Emitir token vinculado a clave pública (DPoP) |
| 5.11 | GET | `/api/v1/dpop/protected` | Ruta protegida con DPoP binding |
| 5.12 | GET | `/api/v1/admin/users` | Lista paginada de usuarios |
| 5.12 | POST | `/api/v1/admin/users/:id/unlock` | Desbloquear cuenta |
| 5.12 | DELETE | `/api/v1/admin/users/:id` | Eliminar cuenta (GDPR) |
| 6.5 | DELETE | `/api/v1/user/me` | Eliminar propia cuenta |
| 7 | GET | `/api/v1/admin/anomalies` | Lista de anomalías detectadas |

---

## Arquitectura

```
src/
├── config/
│   └── env.ts              # Fail-Fast: validación de .env con Zod
├── middleware/
│   ├── correlationId.ts    # UUID v4 por request → X-Correlation-ID
│   └── errorHandler.ts     # Error centralizado + clase AppError
├── routes/
│   └── health.ts           # GET /api/v1/health
├── types/
│   └── index.ts            # Todos los tipos TypeScript del sistema
├── logger.ts               # Instancia Pino (pino-pretty en dev)
└── index.ts                # Servidor Express
```

---

## CI/CD Pipeline

El pipeline de GitHub Actions ejecuta en cada push y PR:

1. **Auditoría de seguridad** — `npm audit --audit-level=high` (falla si hay CVE críticos)
2. **Análisis estático** — Semgrep con reglas OWASP + Node.js + JWT
3. **Tests + Cobertura** — Jest con umbrales ≥ 80% líneas / ≥ 60% branches
4. **Docker Build** — Verifica que el `Dockerfile` compila correctamente

Las **pruebas de carga** (Artillery — `tests/load.yml`) se ejecutan solo en push a `main`.

---

## Tests

**220 tests** en 9 suites con cobertura ≥ 80% líneas / ≥ 60% branches:

```bash
npm test                    # Todos los tests
npm run test:coverage       # Con informe de cobertura HTML (coverage/)
```

---

## Documentación adicional

- `docs/implementation_plan.md` — Arquitectura completa, schema SQLite, patrones de seguridad
- `docs/task.md` — Plan de trabajo por fases
- `docs/comparativa.md` — Matriz de trade-offs (seguridad, complejidad, UX)
- `docs/cuando-usar.md` — Árbol de decisión: ¿qué auth usar?
- `docs/produccion.md` — Checklist para despliegue en producción
- `docs/owasp.md` — Mapa OWASP A2:2021 Broken Authentication
- `docs/glosario.md` — Glosario de términos técnicos

---

## Referencias a Estándares

- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) — OAuth 2.0
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) — JSON Web Token (JWT)
- [RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617) — HTTP Basic Authentication
- [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) — OAuth 2.0 Device Authorization Grant
- [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) — OAuth 2.0 DPoP
- [WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/) — W3C Web Authentication
- [FIDO2](https://fidoalliance.org/fido2/) — FIDO Alliance

# Authentication POC — Claude Code

## Descripción
Laboratorio educativo de autenticación con 15+ sistemas implementados.
Node.js 20 + TypeScript strict + Express 4 + SQLite + Alpine.js frontend.
Proyecto completado — todas las fases del task.md implementadas.

## Comandos
- `npm run dev` — servidor con hot-reload (nodemon + tsx)
- `npm test` — 220 tests Jest
- `npm run test:coverage` — cobertura con umbral 80% líneas / 60% branches
- `npm run lint` — ESLint sobre src/
- `npx kill-port 3000` — matar servidor si queda en memoria

## Stack
- Runtime: Node.js 20 + TypeScript strict (ES2022)
- Framework: Express 4
- BD: better-sqlite3 (SQLite, sin ORM)
- Auth: jsonwebtoken (HS256), paseto@^3.1.4 (v4 EdDSA), @simplewebauthn/server
- MFA: otplib (TOTP)
- Logs: pino (en español)
- Validación: zod v4
- Frontend: Alpine.js + Tailwind CDN (sin build step)
- Email: consola en dev, nodemailer + Gmail SMTP en prod

## Arquitectura
- `src/app.ts` — Express app, middlewares, rutas, error handler
- `src/index.ts` — arranque del servidor HTTP (importa app, llama listen)
- `src/config/env.ts` — validación Zod fail-fast de variables de entorno
- `src/db/` — migrations, repositories, transactions, purgeJob
- `src/services/` — lógica de negocio (jwtService, oauthService, mfaService, etc.)
- `src/routes/` — un archivo por dominio
- `src/middleware/` — middlewares reutilizables

## Convenciones
- Logs y mensajes de error en español
- `asyncHandler` obligatorio en todos los async route handlers (Express 4)
- Parámetros no usados con `_prefix` (noUnusedParameters: true)
- `timingSafeEqual` para comparaciones de secrets
- bcrypt cost=12 para passwords, SHA-256 para tokens de sesión/email

## Variables de entorno requeridas
- `JWT_SECRET` (mín. 32 chars)
- `IP_HASH_SALT` (mín. 16 chars)
- `NODE_ENV=test` desactiva rate limiting y logging HTTP (útil para tests y carga)

## Tests
- 220 tests en 9 suites, cobertura Lines 85.93% / Branches 60.12%
- CI en `.github/workflows/ci.yml` (Semgrep, npm audit, Jest, Docker)
- Pruebas de carga en `.github/workflows/load.yml` (Artillery, solo push a main)

## Dependencias críticas
- `paseto@^3.1.4` — NO usar ^4.0.0 (no existe en npm)
- `@asteasolutions/zod-to-openapi@8.4.1` — requerida por zod v4
- `better-sqlite3` requiere C++ build tools (Windows: Visual Studio Build Tools)

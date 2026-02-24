# Checklist de Producción

Qué cambiar y configurar antes de desplegar en producción.

## 1. Secretos y Claves

- [ ] **JWT_SECRET**: mínimo 64 bytes aleatorios — `openssl rand -hex 64`
  - Nunca reutilizar el secreto de desarrollo
  - Usar un gestor de secretos (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)
- [ ] **IP_HASH_SALT**: mínimo 32 bytes — `openssl rand -hex 32`
- [ ] **Variables de entorno**: nunca en el código fuente, nunca en logs
- [ ] **Rotación de claves JWT**: activar la rotación periódica con `POST /admin/keys/rotate`
  - Recomendado: cada 30-90 días
  - Las claves antiguas siguen verificando (active=0) hasta que expiren todos los AT emitidos con ellas

## 2. HTTPS / TLS

- [ ] **TLS 1.2+ obligatorio** — deshabilitar TLS 1.0 y 1.1
- [ ] **Certificado válido** — Let's Encrypt o CA corporativa
- [ ] **HSTS** (`Strict-Transport-Security: max-age=31536000; includeSubDomains`)
  - Helmet ya lo añade — verificar que `hstsOptions` está configurado correctamente
- [ ] **Redirigir HTTP → HTTPS** a nivel de proxy inverso (nginx/Caddy)
- [ ] **HSTS preload** para dominios de producción de larga vida

## 3. Base de Datos

- [ ] **No usar `./database.sqlite` en producción**
  - Montar en volumen persistente con backup automático
  - O migrar a PostgreSQL para alta disponibilidad (requiere reemplazar `better-sqlite3`)
- [ ] **WAL mode**: `PRAGMA journal_mode=WAL` — ya configurado en las migraciones
- [ ] **Backup automático**: snapshot diario del archivo SQLite o export con `.dump`
- [ ] **Permisos de archivo**: `chmod 600 database.sqlite` — solo el proceso del servidor puede acceder

## 4. Rate Limiting

- [ ] **Express Rate Limit**: el proyecto usa `express-rate-limit` con límites en memoria
  - **Problema en producción**: no se comparte entre instancias (múltiples pods)
  - **Solución**: usar Redis Store (`rate-limit-redis`)
  ```typescript
  import { RedisStore } from 'rate-limit-redis';
  // Reemplazar MemoryStore por RedisStore en config del rate limiter
  ```
- [ ] **Ajustar límites según carga real**:
  - Login: 10 intentos / 15 min / IP
  - Register: 5 / hora / IP
  - Forgot password: 3 / hora / email
  - API en general: 100 req / min / usuario

## 5. CORS

- [ ] **FRONTEND_URL** apunta al dominio de producción exacto (no `*`)
- [ ] Verificar que el origen del dashboard/SPA está en la allowlist de CORS
- [ ] No permitir `origin: '*'` en ningún endpoint con cookies

## 6. Headers de Seguridad (Helmet)

El proyecto usa Helmet. Verificar en producción:

```bash
curl -I https://tu-dominio.com/api/v1/health
```

Cabeceras requeridas:
- [ ] `Strict-Transport-Security` — HSTS
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options: DENY`
- [ ] `Referrer-Policy: strict-origin-when-cross-origin`
- [ ] `Content-Security-Policy` — configurar según el frontend
- [ ] `Permissions-Policy` — restringir APIs del navegador no usadas

## 7. Logs y Monitoreo

- [ ] **Pino en producción**: usar `pino` sin `pino-pretty` (JSON puro para sistemas de log)
  ```typescript
  // config/logger.ts — NODE_ENV=production no usa pino-pretty
  ```
- [ ] **Centralizar logs**: enviar a ELK Stack, Datadog, Grafana Loki, o CloudWatch
- [ ] **Alertas sobre anomalías**: configurar alertas cuando se logueen eventos:
  - `ANOMALIA_CREDENTIAL_STUFFING`
  - `ANOMALIA_FUERZA_BRUTA`
  - `TOKEN_ROBO_DETECTADO`
- [ ] **Métricas**: latencia p99, tasa de error 4xx/5xx, CPU/RAM del proceso
- [ ] **Health check externo**: usar `GET /api/v1/health` con un monitor (UptimeRobot, Pingdom)

## 8. Docker / Contenedores

- [ ] **Usuario no-root en el contenedor**:
  ```dockerfile
  RUN addgroup -S appgroup && adduser -S appuser -G appgroup
  USER appuser
  ```
- [ ] **Imagen base mínima**: `node:20-alpine` (ya configurado)
- [ ] **Multi-stage build** para producción (separar builder de imagen final):
  ```dockerfile
  FROM node:20-alpine AS builder
  RUN npm ci && npm run build
  FROM node:20-alpine AS production
  COPY --from=builder /app/dist ./dist
  ```
- [ ] **No copiar `node_modules` de dev** — solo dependencias de producción
- [ ] **Read-only filesystem**: montar solo `/data` como escritura
- [ ] **Límites de recursos**: CPU y memoria en `docker-compose.yml` o Kubernetes

## 9. WebAuthn en Producción

- [ ] **RP_ID** debe ser el dominio exacto (sin subdominio o con el subdominio correcto)
  - Desarrollo: `localhost`
  - Producción: `mi-app.com` o `auth.mi-app.com`
- [ ] **RP_ORIGIN** debe ser `https://mi-app.com` (con HTTPS obligatorio)
- [ ] WebAuthn NO funciona sobre HTTP excepto en `localhost`

## 10. Email (Nodemailer)

- [ ] **GMAIL_USER + GMAIL_APP_PASSWORD** en variables de entorno (nunca en código)
- [ ] Para producción de alto volumen: usar un servicio transaccional (SendGrid, AWS SES, Postmark)
- [ ] **SPF, DKIM, DMARC**: configurar en el DNS para evitar que los emails vayan a spam
- [ ] **Rate de envío**: implementar colas de email para picos de tráfico

## 11. Variables de Entorno de Producción

```bash
NODE_ENV=production
PORT=3000
FRONTEND_URL=https://mi-app.com

# Secretos — generados con openssl rand -hex 64
JWT_SECRET=<64-bytes-hex>
IP_HASH_SALT=<32-bytes-hex>

# TTL conservadores en producción
JWT_EXPIRY_ACCESS=15m
JWT_EXPIRY_REFRESH=7d

# OAuth — credenciales del proveedor de producción
GITHUB_CLIENT_ID=<prod-github-id>
GITHUB_CLIENT_SECRET=<prod-github-secret>
GITHUB_CALLBACK_URL=https://mi-app.com/api/v1/oauth/github/callback

# Email
GMAIL_USER=noreply@mi-app.com
GMAIL_APP_PASSWORD=<app-password>
```

## 12. Checklist Final Pre-Deploy

- [ ] `npm audit --audit-level=high` — sin vulnerabilidades críticas
- [ ] `npm run test:coverage` — todos los tests verdes
- [ ] `npm run build` — sin errores de TypeScript
- [ ] Variables de entorno revisadas en el entorno de producción
- [ ] Backup de BD antes del deploy
- [ ] Health check responde correctamente tras el deploy
- [ ] Logs de arranque sin errores ni warnings críticos

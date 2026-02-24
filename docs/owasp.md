# OWASP A07:2021 — Identification and Authentication Failures

Anteriormente "A2:2021 — Broken Authentication". Mapa de cómo este proyecto mitiga cada sub-punto.

## Sub-puntos OWASP y Mitigaciones Implementadas

### 1. Credenciales débiles o por defecto

**Riesgo**: contraseñas triviales como `123456`, `password`, o credenciales de desarrollo en producción.

**Mitigación en este proyecto**:
- Zod valida en el registro: `password.min(8)` y patrón de complejidad
- `JWT_SECRET` validado en startup con Zod: mínimo 32 caracteres o el proceso no arranca
- `.env.example` documenta que los secretos deben generarse con `openssl rand`
- Tests verifican que un password corto devuelve 400 VALIDACION_FALLIDA

**Archivo**: `src/config.ts` — `configSchema` con validaciones Zod en arranque

---

### 2. Ataques de brute force

**Riesgo**: probar contraseñas automáticamente hasta encontrar la correcta.

**Mitigación en este proyecto**:
- **Account lockout**: tras 5 intentos fallidos → `locked_until = Date.now() + 30min`
- **Rate limiting**: `express-rate-limit` limita requests por IP
- **Detección de anomalías**: `ANOMALIA_FUERZA_BRUTA` detectada y logueada como `warn`
- **bcrypt cost=12**: hace que cada intento tome ~100-300ms en hardware moderno

**Archivos**:
- `src/routes/auth.ts` — lógica de lockout
- `src/services/anomalyService.ts` — detección brute force
- `src/app.ts` — rate limiter global

**Tests**: `tests/routes.test.ts` — "5 intentos fallidos → 423 Locked"

---

### 3. Credential stuffing

**Riesgo**: usar listas de credenciales filtradas de otras brechas.

**Mitigación en este proyecto**:
- **Detección de anomalías**: > 10 logins fallidos desde IPs distintas en 5 minutos → `ANOMALIA_CREDENTIAL_STUFFING`
- **IP hashing**: `SHA-256(ip + IP_HASH_SALT)` — se detecta el patrón sin guardar IPs reales
- **Lockout individual**: bloquea la cuenta atacada

**Archivo**: `src/services/anomalyService.ts` — `detectCredentialStuffing()`

---

### 4. Sesiones no invalidadas al cerrar sesión

**Riesgo**: tokens que siguen válidos después de que el usuario hace logout.

**Mitigación en este proyecto**:
- **Session Tokens**: `DELETE FROM sessions` al hacer logout → revocación inmediata
- **JWT + Family Tracking**: `DELETE FROM refresh_token_families` → AT queda "huérfano" (familia ya no existe)
- **Logout-all**: elimina **todas** las familias del usuario
- **Password reset**: revoca todas las sesiones y familias activas al cambiar la contraseña

**Archivos**:
- `src/routes/auth.ts` — logout, logout-all
- `src/routes/session.ts` — session logout
- `src/db/transactions.ts` — transacciones atómicas de logout

---

### 5. Tokens con TTL demasiado largo

**Riesgo**: un token robado puede usarse durante días o semanas.

**Mitigación en este proyecto**:
- **Access Token**: TTL de 15 minutos (`JWT_EXPIRY_ACCESS=15m`)
- **Refresh Token**: TTL de 7 días con rotación — si se roba, el Family Tracking lo detecta
- **Session Token**: TTL configurable, extendible solo en uso activo
- **Magic Link**: TTL de 15 minutos
- **Password Reset**: TTL de 1 hora
- **Step-Up Token**: TTL de 10 minutos
- **Device Code**: TTL de 15 minutos

---

### 6. Token almacenado de forma insegura

**Riesgo**: tokens en `localStorage` (robo por XSS), en logs, en URLs.

**Mitigación en este proyecto**:
- **RT en HttpOnly Cookie**: protegido de acceso por JavaScript (anti-XSS)
- **AT en memoria**: nunca en localStorage en el dashboard
- **Tokens en BD**: solo el hash (SHA-256) se almacena — nunca el token en claro
- **Minimización en JWT**: AT solo contiene `sub`, `jti`, `kid`, `roles` — sin PII (email, nombre)
- **Logs**: pino no loguea el cuerpo de requests — no se filtran tokens en logs

**Archivo**: `src/routes/auth.ts` — `res.cookie('refreshToken', rt, { httpOnly: true, secure: true, sameSite: 'strict' })`

---

### 7. Ausencia de MFA

**Riesgo**: una contraseña comprometida da acceso completo.

**Mitigación en este proyecto**:
- **TOTP opcional**: usuario puede activar MFA con `POST /mfa/setup` + `/mfa/enable`
- **WebAuthn**: passkeys como segundo factor o factor único
- **Recovery codes**: 8 códigos de un solo uso para recuperación de acceso
- **Step-Up Auth**: reautenticación para operaciones sensibles, aunque ya esté logueado

**Archivos**: `src/routes/mfa.ts`, `src/middleware/requireStepUp.ts`

---

### 8. Vulnerabilidades en JWT (Algorithm Confusion, alg:none)

**Riesgo**: modificar el header del JWT para cambiar el algoritmo o eliminar la firma.

**Mitigación en este proyecto**:
- **Algorithm pinning**: `jwt.verify(token, secret, { algorithms: ['HS256'] })` — no se acepta ningún otro algoritmo
- **alg:none**: rechazado explícitamente por `algorithms` array
- **Algorithm confusion RS256→HS256**: imposible porque el servidor siempre usa el secreto HMAC, no la clave pública como secreto
- **kid validation**: se verifica que el `kid` del token corresponde a una clave activa en BD
- **API Key como Bearer JWT**: detectada y rechazada antes de la verificación JWT (`sk_live_` prefix check)

**Archivos**:
- `src/middleware/authenticate.ts` — verificación con algoritmo fijo
- `src/services/jwtService.ts` — emisión y verificación

**Tests**: `tests/routes.test.ts` — "alg:none", "Algorithm Confusion", "API Key como Bearer"

---

### 9. Enumeración de usuarios

**Riesgo**: el servidor revela si un email existe o no, facilitando ataques dirigidos.

**Mitigación en este proyecto**:
- **Login**: mismo mensaje de error para "email no encontrado" y "password incorrecto" (`CREDENCIALES_INVALIDAS`)
- **Forgot password**: "Si el email existe, recibirás instrucciones" — sin confirmar si existe
- **Magic link request**: misma respuesta para email existente e inexistente
- **Registro**: único caso donde se informa de email duplicado (necesario para UX)

---

### 10. CSRF en flujos con cookies

**Riesgo**: sitio malicioso hace requests en nombre del usuario autenticado.

**Mitigación en este proyecto**:
- **SameSite=Strict** en cookies de RT: el navegador no envía la cookie en requests cross-site
- **PKCE state parameter**: previene CSRF en OAuth flows
- **Authorization header**: para AT (no cookie) — no susceptible a CSRF
- **CORS**: solo permite el origen configurado en `FRONTEND_URL`

---

### 11. Gestión de sesiones paralelas no auditada

**Riesgo**: el usuario no sabe cuántas sesiones tiene activas ni puede cerrarlas.

**Mitigación en este proyecto**:
- `GET /api/v1/auth/sessions` — lista todas las sesiones con `ip_hash`, `user_agent`, `created_at`
- `POST /api/v1/auth/logout-all` — cierra todas las sesiones excepto la actual
- Audit log completo: cada login, logout, rotación de token queda registrado en `audit_logs`

---

## Resumen de Cumplimiento

| Sub-punto OWASP | Estado | Mecanismo |
|---|:---:|---|
| Credenciales débiles | ✅ | Validación Zod, Fail-Fast config |
| Brute force | ✅ | Lockout + Rate Limiting + bcrypt |
| Credential stuffing | ✅ | Anomaly detection + IP hashing |
| Sesiones no invalidadas | ✅ | Family Tracking + Logout-all |
| TTL demasiado largo | ✅ | AT=15min, RT=7d con rotación |
| Token inseguro | ✅ | HttpOnly cookie, solo hashes en BD |
| Sin MFA | ✅ | TOTP + WebAuthn + Step-Up |
| JWT algorithm confusion | ✅ | Algorithm pinning `['HS256']` |
| Enumeración de usuarios | ✅ | Mensajes genéricos anti-enumeración |
| CSRF | ✅ | SameSite=Strict + PKCE state |
| Sesiones sin auditoría | ✅ | Audit logs + /sessions endpoint |

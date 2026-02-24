# Matriz de Trade-offs — Sistemas de Autenticación

Comparativa de todos los sistemas implementados en este laboratorio.

## Tabla Comparativa

| Sistema | Stateful | Revocación | Complejidad | UX | Seguridad | Caso de Uso Ideal |
|---|:---:|---|:---:|:---:|:---:|---|
| **HTTP Basic Auth** | No | Inmediata (cambiando password) | Baja | Mala | Baja | APIs internas, herramientas CLI legacy |
| **Session Token** | Sí (BD) | Inmediata (borrar fila) | Baja | Media | Media-Alta | Apps web tradicionales, backends con BD |
| **JWT sin rotación** | No | Imposible hasta expiración | Media | Buena | Media | APIs stateless simples |
| **JWT + Family Tracking** | Semi (familia en BD) | Inmediata (borrar familia) | Alta | Buena | Alta | APIs modernas con seguridad robusta |
| **API Key** | Sí (BD) | Inmediata (revocar en BD) | Baja | Buena (para M2M) | Media | Integraciones, webhooks, acceso programático |
| **OAuth 2.0 PKCE** | Semi | Depende del proveedor | Alta | Excelente | Alta | Login social, delegar auth a proveedor |
| **OAuth Device Grant** | Semi | Inmediata | Alta | Excelente para CLI | Alta | CLI tools, Smart TVs, IoT |
| **OAuth M2M (Client Credentials)** | No | Por rotación de secret | Media | N/A (máquinas) | Alta | Microservicios, backends a backends |
| **WebAuthn / Passkeys** | Semi (credential en BD) | Inmediata (revocar credential) | Muy Alta | Excelente | Muy Alta | Consumer apps, alta seguridad |
| **TOTP / MFA** | Sí (secret en BD) | Desactivar MFA | Media | Media | Alta | 2do factor para cualquier sistema |
| **Magic Link** | Semi (token en BD) | Inmediata (token se usa) | Baja | Excelente | Media-Alta | Passwordless para usuarios técnicos |
| **Password Reset** | Semi (token en BD) | Inmediata (token se usa) | Baja | Buena | Media | Recuperación de acceso |
| **DPoP** | No (proof stateless) | Por expiración del AT | Alta | Transparente | Muy Alta | APIs de alta seguridad, OAuth 2.1 |
| **PASETO v4** | No | Por expiración | Media | Igual que JWT | Alta | Alternativa a JWT con algoritmo único |
| **Step-Up Auth** | Semi (step-up token) | Por expiración (10min) | Media | Buena | Alta | Operaciones sensibles: cambio de email, pagos |

## Dimensiones de Evaluación

### Stateful vs Stateless

- **Stateful**: requiere BD para verificar cada request. Permite revocación inmediata.
  - Session Tokens, API Keys, Device Grant
- **Semi-stateful**: tiene estado mínimo (familia, token hash) pero verifica criptográficamente.
  - JWT + Family Tracking, Magic Links, WebAuthn
- **Stateless**: la validez está completamente en el token. Sin BD en el path crítico.
  - JWT básico, PASETO, DPoP (el proof es stateless; el AT puede ser stateless)

### Revocación

| Tipo | Revocación |
|---|---|
| Inmediata | Session tokens, API Keys, Magic Links (token de un uso) |
| Semi-inmediata | JWT + Family (revocar familia en BD) |
| Imposible | JWT sin rotación (hasta expiración del AT) |
| Por rotación | OAuth tokens (revocar en el IDP) |

### Resistencia a Ataques

| Ataque | Mitigación |
|---|---|
| Phishing | WebAuthn (vinculado al dominio), TOTP (segundo factor) |
| Robo de token en tránsito | DPoP (inútil sin clave privada), HTTPS |
| Robo de RT | Family Tracking (detecta y revoca) |
| Brute force | Lockout, rate limiting, bcrypt |
| Credential stuffing | Anomaly detection, lockout por IP |
| Token replay | DPoP jti cache, session invalidation |
| CSRF | PKCE state parameter, SameSite cookies |
| XSS → robo de token | HttpOnly cookies para RT, PKCE |

## Recomendación por Tipo de Aplicación

| Aplicación | Sistema Recomendado |
|---|---|
| SPA + API REST | JWT (AT corto) + RT HttpOnly Cookie + Family Tracking |
| App móvil | OAuth 2.0 PKCE + JWT |
| CLI / herramienta de línea de comandos | Device Grant o API Key |
| Backend a backend (microservicios) | API Key o M2M Client Credentials |
| Portal corporativo con MFA obligatorio | OAuth + TOTP o WebAuthn |
| Alta seguridad (banca, gobierno) | WebAuthn + MFA + DPoP |
| Usuarios sin contraseña | Magic Link o WebAuthn |

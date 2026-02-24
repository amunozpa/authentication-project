# Glosario de Términos Técnicos

Definiciones de los conceptos clave usados en este laboratorio de autenticación.

---

## A

### Access Token (AT)
Token de corta vida (15 minutos por defecto) que el cliente presenta en cada request para acceder a recursos protegidos. En este proyecto es un **JWT** firmado con HMAC-SHA256. Contiene: `sub`, `jti`, `kid`, `roles`, `iat`, `exp`. **No contiene PII** (sin email, sin nombre).

### Account Linking
Proceso de vincular múltiples identidades de proveedores OAuth (GitHub, Google) a una sola cuenta local. Cuando un usuario hace login con Google usando el mismo email que ya registró manualmente, las identidades se vinculan automáticamente. Ver: `src/services/oauthService.ts` — `processOAuthLogin()`.

### Algorithm Confusion Attack
Ataque a JWT donde el atacante modifica el header `alg` del token (por ejemplo, de `RS256` a `HS256`) para hacer que el servidor use la clave pública RSA como secreto HMAC. Mitigado en este proyecto con `algorithms: ['HS256']` en `jwt.verify()`.

### AuthN (Authentication)
Verificación de identidad — ¿Quién eres? Ejemplos: contraseña, biometría, token.

### AuthZ (Authorization)
Verificación de permisos — ¿Qué puedes hacer? Ejemplos: RBAC, scopes, ownership checks.

---

## B

### Basic Auth (HTTP Basic Authentication)
Esquema de autenticación definido en RFC 7617. El cliente envía `Authorization: Basic base64(usuario:contraseña)` en cada request. **Solo es seguro sobre HTTPS** ya que Base64 es trivialmente reversible.

### bcrypt
Función de hash de contraseñas diseñada para ser lenta por diseño (cost factor). En este proyecto se usa `cost=12` (~100-300ms por hash). Incluye sal aleatoria automáticamente. **Nunca usar SHA-256 o MD5 para contraseñas**.

### BFF (Backend For Frontend)
Patrón donde el servidor web tradicional actúa como proxy entre el frontend y las APIs, gestionando cookies y tokens de forma segura. El frontend nunca ve el AT directamente.

### Brute Force Attack
Intento sistemático de todas las combinaciones posibles de contraseña. Mitigado con lockout (5 intentos → 30 min bloqueado) y bcrypt (hace cada intento costoso en tiempo).

---

## C

### CSRF (Cross-Site Request Forgery)
Ataque donde un sitio malicioso hace requests en nombre de un usuario autenticado aprovechando que el navegador envía automáticamente las cookies. Mitigado con `SameSite=Strict` en cookies y el parámetro `state` en OAuth.

### cnf (Confirmation Claim)
Claim JWT que vincula el token a una clave criptográfica del cliente. En DPoP, `cnf.jkt` contiene el thumbprint de la clave pública del cliente. Solo quien tiene la clave privada puede usar el token.

### Credential Stuffing
Ataque que usa listas de credenciales robadas de otras brechas para intentar acceder a cuentas. Funciona porque los usuarios reutilizan contraseñas. Detectado en este proyecto cuando > 10 IPs distintas intentan login en 5 minutos.

---

## D

### Device Authorization Grant (RFC 8628)
Flujo OAuth 2.0 para dispositivos sin navegador (Smart TVs, CLIs). El dispositivo obtiene un `user_code` que el usuario introduce manualmente en otro dispositivo con navegador para autorizar.

### DPoP (Demonstrating Proof-of-Possession, RFC 9449)
Mecanismo que vincula un token OAuth a la clave pública del cliente. El cliente debe presentar una prueba criptográfica (`DPoP: <proof_jwt>`) firmada con su clave privada en cada request. Un token robado es inútil sin la clave privada.

---

## E

### Email Verification Token
Token de un solo uso enviado por email para verificar que el usuario controla la dirección de email. En este proyecto: `rawToken` aleatorio → `SHA-256(rawToken)` en BD, TTL 24h, tipo `VERIFY_EMAIL`.

### exp (Expiration Time)
Claim estándar de JWT (RFC 7519) con la fecha de expiración en segundos Unix. El verificador rechaza tokens donde `exp < now()`.

---

## F

### FIDO2
Conjunto de estándares del FIDO Alliance que incluye WebAuthn (autenticación en el browser) y CTAP (protocolo con authenticators externos como YubiKey).

### Family Tracking
Técnica de seguridad para JWT que agrupa un AT y su RT bajo un `familyId`. Si se detecta reutilización de un RT antiguo (indicio de robo), toda la familia se revoca. Implementado en `src/db/repositories/refreshTokenFamilies.ts`.

---

## I

### iat (Issued At)
Claim JWT con el timestamp de emisión. Usado en DPoP para verificar que el proof fue generado recientemente (±30 segundos).

### IP Hashing
En lugar de guardar IPs en claro (que son datos personales bajo GDPR), se almacena `SHA-256(ip + IP_HASH_SALT)`. Permite detectar patrones (mismo hash = misma IP) sin poder reconstruir la IP original.

---

## J

### JIT Provisioning (Just-in-Time)
Creación automática de cuenta al primer login OAuth. Si el email del proveedor no existe en la BD, se crea el usuario automáticamente. Implementado en `processOAuthLogin()`.

### jti (JWT ID)
Identificador único de un JWT (UUID v4). Permite invalidar tokens individuales y detectar reutilización. En Family Tracking, `current_jti` es el único RT válido de una familia.

### JWT (JSON Web Token, RFC 7519)
Formato de token en tres partes codificadas en Base64URL separadas por `.`: `header.payload.signature`. La firma permite verificar integridad sin consultar una BD.

---

## K

### kid (Key ID)
Identificador de la clave JWT usada para firmar el token. Permite al servidor buscar la clave correcta cuando hay múltiples claves activas (rotación sin logout masivo). Presente en el header del JWT.

---

## M

### Magic Link
Enlace de autenticación de un solo uso enviado por email. El usuario hace clic en el link para autenticarse sin contraseña. El token tiene TTL de 15 minutos y se invalida al usarse.

### MFA (Multi-Factor Authentication)
Autenticación con dos o más factores independientes: algo que sabes (contraseña), algo que tienes (teléfono + TOTP), algo que eres (biometría). Ver: `docs/diagrams/07-totp-mfa.md`.

---

## O

### OAuth 2.0 (RFC 6749)
Marco de autorización que permite a aplicaciones de terceros acceder a recursos del usuario en su nombre sin necesidad de compartir credenciales. Define cuatro flujos: Authorization Code, Implicit (deprecado), Client Credentials, Device.

---

## P

### PASETO (Platform-Agnostic Security Tokens)
Alternativa a JWT que usa un único algoritmo por versión (sin `alg` seleccionable → sin algorithm confusion). v4 usa EdDSA (Ed25519). Más seguro por diseño pero menos soportado que JWT.

### PKCE (Proof Key for Code Exchange, RFC 7636)
Extensión de OAuth 2.0 que previene el robo del código de autorización. El cliente genera un `code_verifier` aleatorio y envía `code_challenge = SHA256(code_verifier)` al iniciar el flujo. Al canjear el código, debe presentar el `code_verifier` original.

---

## R

### RBAC (Role-Based Access Control)
Modelo de autorización donde los permisos se asignan a roles, y los usuarios se asignan a roles. En este proyecto: `admin`, `user`. El middleware `requireRole('admin')` protege endpoints de administración.

### Refresh Token (RT)
Token de larga vida (7 días) usado exclusivamente para obtener nuevos Access Tokens. Se envía en HttpOnly Cookie (nunca en el body de responses de API) y se rota en cada uso (Refresh Token Rotation).

### Refresh Token Rotation
Práctica de invalidar el RT actual y emitir uno nuevo en cada renovación. Combinado con Family Tracking, permite detectar robo de RT.

---

## S

### Scope
Permiso específico que define qué acciones puede realizar un token. En API Keys: `read:data`, `write:data`. El middleware `requireScope('read:data')` verifica que el token tenga el scope necesario.

### Session Token
Token opaco (sin payload legible) que referencia una sesión almacenada en el servidor. Al contrario que JWT, no contiene información — el servidor la busca en BD. Permite revocación inmediata.

### Step-Up Authentication
Reautenticación temporal para operaciones sensibles, aunque el usuario ya tenga sesión activa. Genera un `step_up_token` válido 10 minutos. Útil para: cambio de contraseña, eliminación de cuenta, pagos.

---

## T

### timingSafeEqual
Comparación de strings que tarda exactamente el mismo tiempo independientemente de cuántos caracteres coincidan. Previene timing attacks donde el atacante mide el tiempo de respuesta para adivinar el secreto carácter a carácter.

### TOTP (Time-based One-Time Password, RFC 6238)
Algoritmo que genera códigos de 6 dígitos que cambian cada 30 segundos basándose en `HMAC-SHA1(secret, floor(now/30))`. Compatible con Google Authenticator, Authy, etc.

---

## W

### WebAuthn (Web Authentication API, W3C)
Estándar del W3C para autenticación sin contraseña usando criptografía de clave pública. El authenticator (Touch ID, Windows Hello, YubiKey) guarda la clave privada y nunca la expone. Phishing-resistant: la clave está vinculada al `rpId` (dominio).

---

## Referencias

- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) — OAuth 2.0
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) — JWT
- [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638) — JWK Thumbprint
- [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) — Device Authorization Grant
- [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) — DPoP
- [WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/) — W3C WebAuthn
- [OWASP A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) — Identification and Authentication Failures

# TOTP / MFA — Autenticación en Dos Factores (RFC 6238)

```mermaid
sequenceDiagram
    participant U as Usuario
    participant App as App Autenticadora (Google Auth, Authy)
    participant S as Servidor

    Note over U,S: Activación de MFA

    U->>S: POST /api/v1/mfa/setup<br/>Authorization: Bearer AT
    Note over S: Generar secret = authenticator.generateSecret()<br/>Generar otpauthUri con issuer y email<br/>Generar QR code PNG (base64)
    S-->>U: { secret, otpauthUri, qrCode }

    U->>App: Escanear QR code
    Note over App: Registrar cuenta con secret<br/>Genera códigos TOTP cada 30s

    U->>S: POST /api/v1/mfa/enable<br/>{ secret, totp_code: "123456" }
    Note over S: Verificar totp_code con secret (ventana ±1 período)<br/>Generar 8 recovery codes aleatorios<br/>Hash de recovery codes (bcrypt) → BD<br/>UPDATE users SET mfa_enabled=1, mfa_secret=secret
    S-->>U: { recoveryCodes: ["abcd-1234", ...] }

    Note over U,S: Login con MFA activo (paso 2)

    U->>S: POST /api/v1/auth/login<br/>{ email, password }
    S-->>U: 200 { mfa_required: true, mfa_session_token }

    Note over U: Abrir app autenticadora → copiar código

    U->>S: POST /api/v1/mfa/verify<br/>{ mfa_session_token, totp_code: "789012" }
    Note over S: Verificar mfa_session_token (JWT temporal 5min)<br/>Verificar totp_code con mfa_secret del usuario
    S-->>U: 200 { accessToken, refreshToken }

    Note over U,S: Step-Up Authentication (privilegios elevados)

    U->>S: POST /api/v1/mfa/step-up<br/>Authorization: Bearer AT<br/>{ totp_code: "345678" }
    Note over S: Verificar totp_code<br/>Emitir step_up_token (JWT, TTL 10min)
    S-->>U: { step_up_token }

    U->>S: GET /api/v1/mfa/protected<br/>Authorization: Bearer AT<br/>X-Step-Up-Token: step_up_token
    Note over S: Verificar AT + step_up_token<br/>Verificar TTL del step-up (máx 10min)
    S-->>U: 200 — recurso de alta sensibilidad
```

## Recovery Codes

- Se generan **8 códigos** al activar MFA.
- Cada código es de **un solo uso**: tras usarlo se marca como `used_at`.
- Se almacenan con **bcrypt** (nunca en claro).
- Si el usuario pierde el dispositivo, puede recuperar acceso con un recovery code.

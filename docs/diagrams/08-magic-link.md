# Magic Link — Passwordless Authentication

```mermaid
sequenceDiagram
    participant U as Usuario
    participant S as Servidor
    participant E as Email (Gmail SMTP / Consola en dev)
    participant DB as SQLite

    Note over U,DB: Solicitar magic link

    U->>S: POST /api/v1/magic/request<br/>{ email: "usuario@example.com" }
    S->>DB: Buscar usuario por email
    alt Usuario existe
        Note over S: Generar rawToken = crypto.randomBytes(32)<br/>tokenHash = SHA-256(rawToken)<br/>Insertar en email_tokens<br/>{ type: MAGIC_LINK, expires_at: +15min }
        S->>E: Enviar email con link:<br/>https://app.com/magic/verify?token=rawToken
    else Usuario no existe
        Note over S: No hacer nada (anti-enumeración)
    end
    S-->>U: 200 { mensaje: "Si el email existe, recibirás un enlace" }

    Note over U,DB: Verificar magic link (usuario hace clic en el email)

    U->>S: GET /api/v1/magic/verify?token=rawToken
    Note over S: tokenHash = SHA-256(rawToken)<br/>Buscar en email_tokens WHERE token_hash=... AND type=MAGIC_LINK
    alt Token válido
        S->>DB: Verificar token no expirado y no usado<br/>UPDATE email_tokens SET used_at=now()<br/>UPDATE users SET email_verified=1
        alt Usuario sin MFA
            S-->>U: 200 { accessToken, refreshToken, usuario }
        else Usuario con MFA activo
            S-->>U: 200 { mfa_required: true, mfa_session_token }
        end
    else Token expirado (>15min)
        S-->>U: 400 { code: "TOKEN_EXPIRADO" }
    else Token ya usado
        S-->>U: 400 { code: "TOKEN_YA_USADO" }
    else Token no encontrado
        S-->>U: 400 { code: "TOKEN_INVALIDO" }
    end
```

## Ventajas del Magic Link

- **Sin contraseña**: elimina el riesgo de contraseñas débiles o reutilizadas.
- **Email como segundo factor implícito**: quien controla el email, controla la cuenta.
- **Anti-enumeración**: la respuesta es idéntica exista o no el email.
- **Un solo uso**: el token se marca como `used_at` al verificarse.
- **TTL corto (15 min)**: ventana de ataque mínima.
- **SHA-256 en BD**: el token en claro nunca se almacena.

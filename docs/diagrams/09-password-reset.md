# Password Reset por Email

```mermaid
sequenceDiagram
    participant U as Usuario
    participant S as Servidor
    participant E as Email
    participant DB as SQLite

    Note over U,DB: Solicitar reset

    U->>S: POST /api/v1/auth/forgot-password<br/>{ email: "usuario@example.com" }
    S->>DB: Buscar usuario por email
    alt Usuario existe
        Note over S: Generar rawToken = crypto.randomBytes(32)<br/>tokenHash = SHA-256(rawToken)<br/>Insertar en email_tokens<br/>{ type: PASSWORD_RESET, expires_at: +1h }
        S->>E: Enviar email con link:<br/>https://app.com/reset-password?token=rawToken
    else Usuario no existe
        Note over S: No hacer nada (anti-enumeración)
    end
    S-->>U: 200 { mensaje: "Si el email existe, recibirás instrucciones" }

    Note over U,DB: Restablecer contraseña

    U->>S: POST /api/v1/auth/reset-password<br/>{ token: rawToken, new_password: "NuevaPass123" }
    Note over S: Validar Zod: new_password mín 8 chars<br/>tokenHash = SHA-256(rawToken)<br/>Buscar en email_tokens WHERE token_hash=... AND type=PASSWORD_RESET
    alt Token válido
        Note over S: Verificar no expirado y no usado<br/>bcrypt.hash(new_password, 12)<br/>UPDATE users SET password_hash=nuevo_hash<br/>UPDATE email_tokens SET used_at=now()
        S->>DB: Revocar todas las sesiones activas del usuario:<br/>DELETE FROM refresh_token_families WHERE user_id=...<br/>DELETE FROM sessions WHERE user_id=...
        S-->>U: 200 { mensaje: "Contraseña restablecida" }
    else Token expirado
        S-->>U: 400 { code: "TOKEN_EXPIRADO" }
    else Token ya usado
        S-->>U: 400 { code: "TOKEN_YA_USADO" }
    else Token inválido
        S-->>U: 400 { code: "TOKEN_INVALIDO" }
    end
```

## Seguridad del Flujo

- **Anti-enumeración**: misma respuesta 200 exista o no el email.
- **TTL de 1 hora**: ventana limitada para el atacante.
- **Un solo uso**: no se puede reutilizar el mismo link.
- **SHA-256 en BD**: token en claro nunca almacenado.
- **Revocación de sesiones**: al cambiar la contraseña, todas las sesiones previas quedan invalidadas — el atacante que tenía un RT queda expulsado.
- **bcrypt cost=12**: hash robusto de la nueva contraseña.

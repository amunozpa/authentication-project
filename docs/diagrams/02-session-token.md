# Session Token (Stateful)

```mermaid
sequenceDiagram
    participant C as Cliente
    participant S as Servidor
    participant DB as SQLite

    C->>S: POST /api/v1/session/login<br/>{ email, password }
    S->>DB: Buscar usuario, verificar password
    DB-->>S: Usuario encontrado
    Note over S: Generar token = SHA-256(random bytes)<br/>Almacenar en tabla sessions<br/>{ token_hash, user_id, ip_hash, user_agent, expires_at }
    S-->>C: 200 OK<br/>{ sessionToken: "abc123...", expiresAt }

    Note over C,S: Request posterior protegido

    C->>S: GET /api/v1/session/protected<br/>Authorization: Bearer abc123...
    S->>DB: Buscar sessions WHERE token_hash = SHA256(abc123)
    alt Token válido y no expirado
        DB-->>S: { user_id, ... }
        S-->>C: 200 OK — recurso protegido
    else Token inválido o expirado
        S-->>C: 401 Unauthorized<br/>{ code: "TOKEN_INVALIDO" }
    end

    Note over C,S: Cierre de sesión

    C->>S: POST /api/v1/session/logout<br/>Authorization: Bearer abc123...
    S->>DB: DELETE FROM sessions WHERE token_hash = SHA256(token)
    S-->>C: 200 OK — sesión cerrada
```

## Características

- **Stateful**: el servidor guarda cada sesión en BD
- **Revocación instantánea**: borrar de BD invalida inmediatamente
- **ip_hash**: nunca se guarda la IP en claro (GDPR)
- **SHA-256** del token — nunca el token en claro en BD
- Expira tras inactividad (TTL configurable)

# JWT con Family Tracking y Refresh Token Rotation

```mermaid
sequenceDiagram
    participant C as Cliente
    participant S as Servidor
    participant DB as SQLite

    Note over C,DB: Login inicial — emisión del par AT+RT

    C->>S: POST /api/v1/auth/login
    Note over S: Generar familyId = UUID<br/>Generar AT (15min) + RT (7d)<br/>Ambos comparten familyId
    S->>DB: INSERT refresh_token_families<br/>{ id: familyId, current_jti: RT.jti,<br/>  access_jti: AT.jti, user_id, kid }
    S-->>C: 200 { accessToken, refreshToken }<br/>Set-Cookie: refreshToken (HttpOnly)

    Note over C,S: AT expirado — renovar con RT

    C->>S: POST /api/v1/auth/refresh<br/>Cookie: refreshToken=...
    S->>DB: Buscar familia por familyId (del RT)
    alt RT válido (current_jti coincide)
        Note over S: Generar nuevo AT + nuevo RT<br/>Reutilizar familyId
        S->>DB: UPDATE refresh_token_families<br/>SET current_jti=nuevoRT.jti,<br/>    access_jti=nuevoAT.jti,<br/>    expires_at=nueva_fecha
        S-->>C: 200 { accessToken, refreshToken }
    else RT reutilizado (jti no coincide → robo detectado)
        Note over S: ⚠️ TOKEN_ROBO_DETECTADO<br/>Revocar toda la familia
        S->>DB: DELETE FROM refresh_token_families<br/>WHERE id = familyId
        S->>DB: INSERT audit_logs { type: TOKEN_ROBO_DETECTADO }
        S-->>C: 401 { code: "TOKEN_INVALIDO" }
    else RT expirado
        S-->>C: 401 { code: "TOKEN_EXPIRADO" }
    end

    Note over C,S: Logout

    C->>S: POST /api/v1/auth/logout<br/>Authorization: Bearer AT<br/>Cookie: refreshToken=...
    S->>DB: DELETE FROM refresh_token_families WHERE id=familyId
    S-->>C: 200 — sesión cerrada

    Note over C,S: Logout-all (todas las sesiones)

    C->>S: POST /api/v1/auth/logout-all<br/>Authorization: Bearer AT
    S->>DB: DELETE FROM refresh_token_families WHERE user_id=sub
    S-->>C: 200 — todas las sesiones cerradas
```

## Por Qué Family Tracking

El **Refresh Token Rotation** estándar no detecta el robo si el atacante usa el RT
antes que el usuario legítimo. El Family Tracking agrega:

1. El RT tiene un `familyId` que agrupa AT + RT emitidos juntos.
2. Al renovar, solo se acepta el RT con `jti == current_jti` de la familia.
3. Si alguien presenta un RT con `jti` diferente (el RT antiguo robado), la familia **entera** se revoca.
4. El usuario legítimo queda sin sesión — molestia mínima vs seguridad máxima.

## Protección contra Race Conditions

La actualización de `current_jti` se hace en una **transacción SQLite** (`db.transaction()`).
Una segunda llamada concurrente con el mismo RT ve el `jti` ya actualizado y recibe 401.

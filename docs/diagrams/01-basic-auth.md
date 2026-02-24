# HTTP Basic Authentication (RFC 7617)

```mermaid
sequenceDiagram
    participant C as Cliente
    participant S as Servidor

    C->>S: POST /api/v1/auth/login<br/>Authorization: Basic base64(email:password)
    Note over S: 1. Decodificar Base64<br/>2. Buscar usuario por email<br/>3. bcrypt.compare(password, hash)<br/>4. Verificar email_verified=1<br/>5. Verificar locked_until
    alt Credenciales válidas
        S-->>C: 200 OK<br/>{ accessToken, refreshToken, ... }
    else Email no verificado
        S-->>C: 403 Forbidden<br/>{ code: "EMAIL_NO_VERIFICADO" }
    else Cuenta bloqueada
        S-->>C: 423 Locked<br/>{ code: "CUENTA_BLOQUEADA", desbloqueaEn }
    else Credenciales inválidas
        Note over S: Incrementar failed_attempts<br/>Si ≥5: bloquear 30 min (lockout)<br/>Log ANOMALIA_FUERZA_BRUTA
        S-->>C: 401 Unauthorized<br/>{ code: "CREDENCIALES_INVALIDAS" }
    end
```

## Vulnerabilidades y Mitigaciones

| Vulnerabilidad | Mitigación implementada |
|---|---|
| Credenciales en Base64 (reversible) | Solo válido sobre HTTPS |
| Timing attack en comparación | `bcrypt.compare` es inherentemente constant-time |
| Brute force | Lockout tras 5 intentos, 30 min |
| Credential stuffing | Detección de anomalías: >10 IPs distintas en 5 min |
| Enumeración de usuarios | Mismo mensaje de error para usuario no encontrado y password incorrecto |

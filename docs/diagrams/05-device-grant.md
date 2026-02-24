# OAuth 2.0 Device Authorization Grant (RFC 8628)

Diseñado para dispositivos sin navegador o teclado (Smart TVs, CLIs, IoT).

```mermaid
sequenceDiagram
    participant D as Dispositivo (CLI)
    participant U as Usuario (Browser)
    participant S as Servidor

    Note over D,S: Fase 1 — Solicitud de códigos

    D->>S: POST /api/v1/oauth/device/code<br/>{ client_id }
    Note over S: Generar device_code = UUID<br/>Generar user_code = "ABCD-1234" (legible)<br/>Guardar en device_codes (status=pending, TTL=15min)
    S-->>D: { device_code, user_code: "ABCD-1234",<br/>  verification_uri: "https://app.com/device",<br/>  expires_in: 900, interval: 5 }

    Note over D: Mostrar al usuario:<br/>"Ve a https://app.com/device<br/>e ingresa: ABCD-1234"

    Note over D,U: Fase 2 — Polling + Autorización del usuario (en paralelo)

    loop Polling cada 5 segundos
        D->>S: POST /api/v1/oauth/device/token<br/>{ device_code }
        alt Estado: pending
            S-->>D: 400 { error: "authorization_pending" }
        else Estado: approved
            S-->>D: 200 { access_token, token_type }
        else Estado: denied o expired
            S-->>D: 400 { error: "access_denied" / "expired_token" }
        end
    end

    U->>S: POST /api/v1/oauth/device/verify<br/>Authorization: Bearer AT<br/>{ user_code: "ABCD-1234", action: "approve" }
    Note over S: Buscar device_codes WHERE user_code=...<br/>Verificar status=pending y no expirado<br/>Actualizar status=approved, user_id=sub
    S-->>U: 200 { mensaje: "Dispositivo autorizado" }

    Note over D: Próxima iteración de polling → 200 con AT
    D->>S: POST /api/v1/oauth/device/token
    S-->>D: 200 { access_token, token_type: "Bearer" }
```

## Caso de Uso

- CLI tools que necesitan autenticar al usuario sin abrir un navegador automáticamente
- Smart TVs / consolas de videojuegos
- Dispositivos IoT con pantalla limitada

# WebAuthn / Passkeys (FIDO2)

```mermaid
sequenceDiagram
    participant U as Usuario (Browser)
    participant A as Authenticator (TPM/Touch ID/YubiKey)
    participant S as Servidor

    Note over U,S: Registro de credencial

    U->>S: POST /api/v1/webauthn/register/options
    Note over S: Generar challenge aleatorio (32 bytes)<br/>Guardar en webauthn_challenges (TTL 5min)<br/>Configurar RP: { id, name, origin }
    S-->>U: { challenge, rp, user, pubKeyCredParams, ... }

    U->>A: Crear credencial<br/>navigator.credentials.create(options)
    Note over A: Verificar presencia del usuario (biometría/PIN)<br/>Generar par de claves (privada + pública)<br/>Firmar clientDataJSON + authenticatorData<br/>con clave privada del dispositivo
    A-->>U: PublicKeyCredential { attestationObject, clientDataJSON }

    U->>S: POST /api/v1/webauthn/register/verify<br/>{ credential }
    Note over S: Verificar challenge coincide<br/>Verificar origen y rpId<br/>Extraer clave pública<br/>Guardar en webauthn_credentials { credentialId, publicKey, counter }
    S-->>U: 200 { mensaje: "Passkey registrada" }

    Note over U,S: Login con passkey

    U->>S: POST /api/v1/webauthn/login/options
    Note over S: Generar nuevo challenge<br/>Incluir allowCredentials del usuario
    S-->>U: { challenge, allowCredentials, ... }

    U->>A: Autenticar<br/>navigator.credentials.get(options)
    Note over A: Verificar presencia del usuario<br/>Firmar challenge con clave privada almacenada<br/>Incrementar counter interno
    A-->>U: PublicKeyCredential { signature, authenticatorData }

    U->>S: POST /api/v1/webauthn/login/verify<br/>{ credential }
    Note over S: Verificar firma con clave pública guardada<br/>Verificar counter > counter anterior (anti-clonación)<br/>Actualizar counter en BD
    S-->>U: 200 { accessToken, refreshToken }
```

## Seguridad

- **Phishing-resistant**: la clave está vinculada a `rpId` (dominio). Un sitio de phishing obtendría una aserción para su dominio, no el legítimo.
- **No hay secreto compartido**: el servidor nunca ve la clave privada.
- **Counter anti-clonación**: si el counter retrocede o no avanza, hay una clave clonada.
- **Presencia del usuario**: el authenticator requiere acción física (biometría, PIN, toque).

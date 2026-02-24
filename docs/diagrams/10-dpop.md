# DPoP — Sender-Constrained Tokens (RFC 9449)

```mermaid
sequenceDiagram
    participant C as Cliente
    participant S as Servidor

    Note over C: Generar par de claves ECDSA P-256 efímeras<br/>(Web Crypto API en browser / crypto en Node.js)<br/>Retener privateKey — nunca sale del cliente

    Note over C,S: Obtener token DPoP-bound

    Note over C: Construir DPoP Proof JWT:<br/>header: { alg: "ES256", typ: "dpop+jwt", jwk: publicKey }<br/>payload: { jti: UUID, htm: "POST", htu: "http://server/dpop/token", iat: now }
    Note over C: Firmar con privateKey → dpopProof

    C->>S: POST /api/v1/dpop/token<br/>Authorization: Basic base64(clientId:secret)<br/>DPoP: dpopProof
    Note over S: 1. Verificar credenciales Basic<br/>2. Verificar dpopProof:<br/>   - typ == "dpop+jwt"<br/>   - htm == "POST"<br/>   - htu == request URL<br/>   - iat dentro de ±30s<br/>   - jti no visto antes (replay cache)<br/>3. Extraer JWK pública del proof<br/>4. Calcular JWK Thumbprint (RFC 7638)<br/>5. Emitir AT con claim { cnf: { jkt: thumbprint } }
    S-->>C: 200 { access_token, token_type: "DPoP" }

    Note over C,S: Usar token DPoP-bound en recurso protegido

    Note over C: Calcular ath = BASE64URL(SHA256(access_token))<br/>Construir nuevo DPoP Proof:<br/>{ jti: UUID, htm: "GET", htu: ".../dpop/protected", iat: now, ath: ath }<br/>Firmar con misma privateKey

    C->>S: GET /api/v1/dpop/protected<br/>Authorization: DPoP access_token<br/>DPoP: dpopProof
    Note over S: 1. Verificar AT (firma JWT estándar)<br/>2. Verificar dpopProof (htm, htu, iat, jti)<br/>3. Verificar ath == SHA256(token del header)<br/>4. Extraer JWK del proof<br/>5. Calcular thumbprint del JWK<br/>6. Verificar thumbprint == cnf.jkt del AT<br/>   (la clave que presenta == la clave del token)
    S-->>C: 200 — recurso protegido

    Note over C,S: Ataque: robo del token sin la clave privada

    Note over X as Atacante: Intercepta access_token<br/>No tiene privateKey → no puede construir proof válido
    X->>S: GET /api/v1/dpop/protected<br/>Authorization: Bearer access_token (sin DPoP)
    S-->>X: 401 { code: "TOKEN_NO_DPOP" }
```

## Por Qué DPoP es Superior a Bearer

| | Bearer Token | DPoP Token |
|---|---|---|
| Token robado | Atacante puede usarlo directamente | Inútil sin la clave privada |
| Replay de proof | N/A | Bloqueado por jti cache (TTL 60s) |
| Vinculación a cliente | Ninguna | `cnf.jkt` en AT = thumbprint de la clave |
| Complejidad | Baja | Media (requiere firma por request) |
| Adopción | Universal | OAuth 2.1 lo recomienda |

## Prevención de Replay

Cada DPoP Proof tiene un `jti` único. El servidor mantiene un cache en memoria
(`Map<jti, expiresAt>`) con TTL de 60 segundos. El mismo proof no puede usarse
dos veces dentro de esa ventana.

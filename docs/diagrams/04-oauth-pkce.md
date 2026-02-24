# OAuth 2.0 Authorization Code + PKCE (GitHub / Google)

```mermaid
sequenceDiagram
    participant U as Usuario (Browser)
    participant App as Servidor App
    participant IDP as GitHub / Google

    Note over U,IDP: Fase 1 — Generación de PKCE

    U->>App: GET /api/v1/oauth/github
    Note over App: Generar code_verifier = random(32 bytes)<br/>code_challenge = BASE64URL(SHA256(code_verifier))<br/>state = random UUID<br/>Guardar en oauth_states (TTL 10min)
    App-->>U: 302 → GitHub /oauth/authorize<br/>?client_id=...&code_challenge=...&state=...

    Note over U,IDP: Fase 2 — Autorización del usuario

    U->>IDP: Login y consentimiento
    IDP-->>U: 302 → /oauth/github/callback<br/>?code=AUTH_CODE&state=...

    Note over U,IDP: Fase 3 — Intercambio de código

    U->>App: GET /oauth/github/callback?code=...&state=...
    App->>App: Verificar state (anti-CSRF)<br/>Recuperar code_verifier de oauth_states
    App->>IDP: POST /oauth/token<br/>{ code, code_verifier, client_secret }
    IDP-->>App: { access_token: GITHUB_TOKEN }
    App->>IDP: GET /user (con GITHUB_TOKEN)
    IDP-->>App: { id, email, login, ... }

    Note over App: Account Linking — 3 caminos:
    Note over App: 1. Email ya existe + linked → Login directo<br/>2. Email existe, no linked → Vincular identidad<br/>3. Email nuevo → Crear usuario + vincular

    App->>App: Emitir AT + RT propios (JWT)
    App-->>U: 302 → /dashboard?token=AT
```

## PKCE — Por Qué Es Necesario

Sin PKCE, un atacante que intercepte el `AUTH_CODE` puede canjearlo por tokens
(especialmente en apps móviles/SPA donde el `client_secret` no se puede guardar de forma segura).

Con PKCE:
1. Solo quien generó el `code_verifier` puede completar el intercambio.
2. El `code_challenge` (derivado públicamente) no permite reconstruir el `code_verifier`.
3. El `state` previene ataques CSRF.

# Árbol de Decisión — ¿Qué Sistema de Auth Usar?

## Guía Rápida

Sigue el árbol según las características de tu aplicación.

```
¿Quién accede?
│
├─► Máquina / Servicio (sin usuario humano)
│   │
│   ├─► ¿Misma organización / red interna?
│   │   └─► API Key con scopes + IP allowlist
│   │
│   └─► ¿Tercero / proveedor externo?
│       └─► OAuth M2M Client Credentials (RFC 6749 §4.4)
│
└─► Humano
    │
    ├─► ¿Dispositivo sin navegador? (CLI, Smart TV, IoT)
    │   └─► OAuth Device Authorization Grant (RFC 8628)
    │
    └─► ¿Tiene navegador?
        │
        ├─► ¿Login social requerido? (Google, GitHub, etc.)
        │   └─► OAuth 2.0 PKCE + Account Linking
        │
        └─► ¿Login propio (email/password)?
            │
            ├─► ¿Es una API REST stateless con múltiples clientes?
            │   └─► JWT + Family Tracking (AT 15min + RT 7d)
            │       + MFA si alta sensibilidad
            │       + DPoP si muy alta seguridad (OAuth 2.1)
            │
            ├─► ¿Es una app web tradicional (server-side rendering)?
            │   └─► Session Token (stateful, revocación inmediata)
            │
            ├─► ¿Quieres eliminar contraseñas?
            │   ├─► ¿Usuarios técnicos o con dispositivos modernos?
            │   │   └─► WebAuthn / Passkeys (FIDO2)
            │   └─► ¿Usuarios no técnicos?
            │       └─► Magic Link (email como factor)
            │
            └─► ¿Necesitas MFA adicional?
                ├─► ¿Usuarios con smartphone?
                │   └─► TOTP (Google Authenticator, Authy)
                └─► ¿Máxima seguridad, hardware dedicado?
                    └─► WebAuthn con YubiKey / hardware token
```

## Por Sensibilidad de Datos

| Nivel | Ejemplos | Auth Recomendada |
|---|---|---|
| **Bajo** | Blog, foro público | Session Token o JWT básico |
| **Medio** | E-commerce, SaaS | JWT + Family Tracking + Email verification |
| **Alto** | Banca, salud, legal | JWT + MFA obligatorio + Step-Up para operaciones críticas |
| **Muy alto** | Gobierno, infraestructura crítica | WebAuthn + DPoP + auditoría completa |

## Por Tipo de Requisito de MFA

| Requisito | Solución |
|---|---|
| Sin MFA | JWT básico o Session Token |
| MFA opcional (usuario elige) | TOTP con setup voluntario |
| MFA obligatorio | TOTP o WebAuthn forzado en login |
| MFA solo para operaciones sensibles | Step-Up Auth (token temporal 10min) |
| Sin contraseña en absoluto | WebAuthn como único factor |

## Por Tipo de Cliente

| Cliente | Consideraciones | Solución |
|---|---|---|
| **SPA (React, Vue, Angular)** | No puede guardar secretos de forma segura, XSS risk | AT en memoria + RT en HttpOnly cookie + PKCE |
| **App móvil nativa** | Sin servidor proxy, OAuth PKCE nativo | OAuth PKCE + KeyChain/Keystore para RT |
| **Backend tradicional (BFF)** | Puede guardar client_secret, gestiona cookies | OAuth Authorization Code + session server-side |
| **CLI** | Sin navegador garantizado, interactivo | Device Grant o API Key para acceso permanente |
| **Microservicio / worker** | Sin usuario, comunicación M2M | Client Credentials o API Key interna |
| **IoT / embedded** | CPU limitada, sin pantalla | Device Grant o API Key preconfigurada |

## Decisiones Frecuentes

### ¿JWT o Session Token?

| | JWT | Session Token |
|---|---|---|
| Escalabilidad horizontal | ✅ Stateless (sin BD en path crítico) | ❌ Requiere BD compartida o sticky sessions |
| Revocación inmediata | ❌ Solo con Family Tracking (semi-stateful) | ✅ Borrar fila en BD |
| Tamaño del token | Mayor (payload codificado) | Pequeño (UUID opaco) |
| Auditoría | Payload visible para el servidor | Solo con log explícito |
| Mejor para | APIs REST con múltiples clientes | Apps web monolíticas |

### ¿Magic Link o WebAuthn?

| | Magic Link | WebAuthn |
|---|---|---|
| Requiere hardware especial | No | No (Touch ID / Windows Hello) |
| Funciona offline | No (necesita email) | Sí |
| Phishing-resistant | Parcialmente | ✅ Completamente (vinculado al dominio) |
| Setup para el usuario | Muy fácil | Fácil en dispositivos modernos |
| Mejor para | B2C apps, usuarios no técnicos | Apps de seguridad alta |

### ¿Cuándo usar DPoP?

- APIs que manejan datos muy sensibles (médicos, financieros)
- Cuando el robo de AT en tránsito es una amenaza real
- Implementando OAuth 2.1 (lo recomienda como obligatorio)
- Cuando los tokens tienen TTL largo (> 1 hora)

**No uses DPoP si**: la complejidad de implementación en el cliente es prohibitiva o el AT tiene TTL muy corto (< 5min).

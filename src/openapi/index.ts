/**
 * OpenAPI / Swagger — generación del documento completo.
 * Importa todos los módulos de paths (side-effects: registran sus rutas)
 * y genera el documento final con OpenApiGeneratorV31.
 */
import { OpenApiGeneratorV31 } from '@asteasolutions/zod-to-openapi';
import { registry } from './registry';

// Importar todos los paths — cada uno registra sus rutas en el registry
import './paths/health';
import './paths/auth';
import './paths/jwt';
import './paths/session';
import './paths/keys';
import './paths/oauth';
import './paths/user';
import './paths/webauthn';
import './paths/mfa';
import './paths/magic';
import './paths/paseto';
import './paths/dpop';
import './paths/rbac';
import './paths/admin';
import './paths/ratelimit';

const generator = new OpenApiGeneratorV31(registry.definitions);

export const openApiDocument = generator.generateDocument({
  openapi: '3.1.0',
  info: {
    title: 'Auth Lab — Maestro de Autenticación',
    version: '1.0.0',
    description: `Laboratorio educativo de identidad y seguridad de grado producción.
Implementa y compara **15+ sistemas de autenticación modernos** en un solo proyecto.

## Sistemas implementados

| Sistema | Descripción |
|---|---|
| Basic Auth | RFC 7617 — timingSafeEqual contra timing attacks |
| Session Tokens | Stateful — 32 bytes aleatorios, hash SHA-256 en BD |
| API Keys | Stripe-style \`sk_live_*\`, bcrypt hash, scopes |
| JWT | HS256, Family Tracking, kid rotation, alg whitelist |
| OAuth 2.0 | PKCE (GitHub + Google), Client Credentials, Device Grant (RFC 8628) |
| WebAuthn | Passkeys / FIDO2 — biométrico, counter anti-clonación |
| MFA / TOTP | otplib, 8 recovery codes, step-up authentication |
| Magic Links | Passwordless, SHA-256 del token raw, TTL 15min |
| PASETO v4 | EdDSA/Ed25519 — algoritmo no configurable por diseño |
| DPoP | RFC 9449 — tokens sender-constrained, replay protection |
| RBAC | Capa de permisos sobre roles (admin ⊃ editor ⊃ user ⊃ viewer) |

## Autenticación en esta UI

Usa el botón **Authorize** (arriba a la derecha) para configurar el Access Token:
1. Obtén un token con \`POST /api/v1/auth/login\`
2. Copia el \`accessToken\` de la respuesta
3. Pégalo en **BearerAuth** → **Authorize**`,
  },
  servers: [
    { url: 'http://localhost:3000', description: 'Desarrollo local' },
  ],
  tags: [
    { name: 'Health', description: 'Estado del servidor y health check' },
    { name: 'Auth', description: 'Registro, login, logout, verificación de email y password reset' },
    { name: 'JWT', description: 'Refresh tokens con Family Tracking y rotación de claves JWT' },
    { name: 'Session', description: 'Session tokens clásicos (stateful, cookie o header)' },
    { name: 'API Keys', description: 'Claves de API estilo Stripe con scopes granulares' },
    { name: 'OAuth', description: 'OAuth 2.0: PKCE (GitHub/Google), Client Credentials, Device Grant' },
    { name: 'User', description: 'Perfil de usuario, cuentas OAuth vinculadas y gestión de seguridad' },
    { name: 'WebAuthn', description: 'Passkeys / FIDO2 — autenticación biométrica sin contraseña' },
    { name: 'MFA', description: 'TOTP, recovery codes y step-up authentication' },
    { name: 'Magic Links', description: 'Autenticación passwordless por email' },
    { name: 'PASETO', description: 'Platform-Agnostic Security Tokens v4 — EdDSA/Ed25519' },
    { name: 'DPoP', description: 'Demonstration of Proof of Possession — RFC 9449' },
    { name: 'RBAC', description: 'Role-Based Access Control con capa de permisos granulares' },
    { name: 'Admin', description: 'Gestión de usuarios, rotación de claves JWT y panel de anomalías' },
    { name: 'Rate Limits', description: 'Información y demostración de rate limiting' },
  ],
});

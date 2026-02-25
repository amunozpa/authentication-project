import { z } from 'zod';
import { registry, ErrorSchema, TokenResponseSchema } from '../registry';

// ── GitHub OAuth ──────────────────────────────────────────────────────────────

registry.registerPath({
  method: 'get',
  path: '/api/v1/oauth/github',
  tags: ['OAuth'],
  summary: 'Iniciar OAuth GitHub (PKCE)',
  description: 'Redirige a GitHub con `state`, `code_challenge` y `scope=user:email`. El estado y el code_verifier se guardan en BD (TTL 10min). Al completar, GitHub redirige al callback.',
  responses: {
    302: { description: 'Redirección a GitHub OAuth' },
  },
});

registry.registerPath({
  method: 'get',
  path: '/api/v1/oauth/github/callback',
  tags: ['OAuth'],
  summary: 'Callback OAuth GitHub',
  description: 'GitHub redirige aquí tras la autorización. Valida `state`, intercambia el `code` por tokens, obtiene el perfil y ejecuta Account Linking (3 caminos: login, registro o vinculación).',
  request: {
    query: z.object({
      code: z.string().openapi({ example: 'github_auth_code_abc123' }),
      state: z.string().openapi({ example: 'uuid-state-random' }),
    }),
  },
  responses: {
    302: { description: 'Redirección a FRONTEND_URL?at=<accessToken>' },
    400: { description: 'State inválido o código expirado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

// ── Google OAuth ──────────────────────────────────────────────────────────────

registry.registerPath({
  method: 'get',
  path: '/api/v1/oauth/google',
  tags: ['OAuth'],
  summary: 'Iniciar OAuth Google (PKCE)',
  description: 'Redirige a Google con `scope=openid email profile`. Mismo flujo PKCE que GitHub.',
  responses: {
    302: { description: 'Redirección a Google OAuth' },
  },
});

registry.registerPath({
  method: 'get',
  path: '/api/v1/oauth/google/callback',
  tags: ['OAuth'],
  summary: 'Callback OAuth Google',
  description: 'Callback del flujo OAuth de Google. Valida state, obtiene perfil y ejecuta Account Linking.',
  request: {
    query: z.object({
      code: z.string().openapi({ example: 'google_auth_code_abc123' }),
      state: z.string().openapi({ example: 'uuid-state-random' }),
    }),
  },
  responses: {
    302: { description: 'Redirección a FRONTEND_URL?at=<accessToken>' },
    400: { description: 'State inválido o código expirado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

// ── M2M Client Credentials ────────────────────────────────────────────────────

registry.registerPath({
  method: 'post',
  path: '/api/v1/oauth/m2m/token',
  tags: ['OAuth'],
  summary: 'Client Credentials Grant (M2M)',
  description: `Emite un Access Token para comunicación máquina-a-máquina. No hay usuario involucrado.

Credenciales via Basic Auth (\`Authorization: Basic base64(clientId:clientSecret)\`) o en el body.`,
  security: [{ BasicAuth: [] }],
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({
            grant_type: z.literal('client_credentials').openapi({ example: 'client_credentials' }),
            client_id: z.string().optional().openapi({ example: 'mi-cliente-m2m' }),
            client_secret: z.string().optional().openapi({ example: 'secreto-largo-aquí' }),
            scope: z.string().optional().openapi({ example: 'read:data write:data' }),
          }),
        },
      },
    },
  },
  responses: {
    200: {
      description: 'Token M2M emitido',
      content: {
        'application/json': {
          schema: z.object({
            access_token: z.string().openapi({ example: 'eyJhbGciOiJIUzI1NiJ9...' }),
            token_type: z.literal('Bearer').openapi({ example: 'Bearer' }),
            expires_in: z.number().openapi({ example: 900 }),
            scope: z.string().openapi({ example: 'read:data write:data' }),
          }),
        },
      },
    },
    401: { description: 'Credenciales M2M inválidas', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

// ── Device Authorization Grant ────────────────────────────────────────────────

registry.registerPath({
  method: 'post',
  path: '/api/v1/oauth/device/code',
  tags: ['OAuth'],
  summary: 'Device Authorization Grant — solicitar código',
  description: `Inicia el flujo RFC 8628 para dispositivos sin browser (CLI, TV, IoT).

El dispositivo muestra el \`user_code\` al usuario. El usuario visita \`verification_uri\` en otro dispositivo y aprueba.`,
  responses: {
    200: {
      description: 'Códigos generados',
      content: {
        'application/json': {
          schema: z.object({
            device_code: z.string().openapi({ example: 'uuid-largo-del-device' }),
            user_code: z.string().openapi({ example: 'ABCD-1234' }),
            verification_uri: z.string().openapi({ example: 'http://localhost:3000/api/v1/oauth/device/verify' }),
            expires_in: z.number().openapi({ example: 300 }),
            interval: z.number().openapi({ example: 5 }),
          }),
        },
      },
    },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/oauth/device/token',
  tags: ['OAuth'],
  summary: 'Device Authorization Grant — polling por token',
  description: 'El dispositivo hace polling con el `device_code`. Responde `authorization_pending` mientras el usuario no aprueba, `slow_down` si hace polling muy rápido, o el AT cuando aprueba.',
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({
            grant_type: z.literal('urn:ietf:params:oauth:grant-type:device_code').openapi({ example: 'urn:ietf:params:oauth:grant-type:device_code' }),
            device_code: z.string().openapi({ example: 'uuid-largo-del-device' }),
          }),
        },
      },
      required: true,
    },
  },
  responses: {
    200: {
      description: 'Token emitido — usuario aprobó',
      content: { 'application/json': { schema: TokenResponseSchema } },
    },
    400: {
      description: '`authorization_pending` | `slow_down` | `expired_token` | `access_denied`',
      content: { 'application/json': { schema: z.object({ error: z.string(), error_description: z.string() }) } },
    },
  },
});

void TokenResponseSchema;

import { z } from 'zod';
import { registry, ErrorSchema, TokenResponseSchema, MessageSchema } from '../registry';

registry.registerPath({
  method: 'post',
  path: '/api/v1/webauthn/register/options',
  tags: ['WebAuthn'],
  summary: 'Generar opciones de registro de Passkey',
  description: 'Genera un challenge y las opciones necesarias para registrar una Passkey (biométrico, hardware key, etc.) usando la WebAuthn API del browser.',
  security: [{ BearerAuth: [] }],
  responses: {
    200: {
      description: 'Opciones de registro — pasar a `navigator.credentials.create()`',
      content: {
        'application/json': {
          schema: z.object({
            challenge: z.string().openapi({ example: 'base64url-challenge' }),
            rp: z.object({ name: z.string(), id: z.string() }),
            user: z.object({ id: z.string(), name: z.string(), displayName: z.string() }),
            pubKeyCredParams: z.array(z.object({ type: z.string(), alg: z.number() })),
          }),
        },
      },
    },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/webauthn/register/verify',
  tags: ['WebAuthn'],
  summary: 'Verificar y guardar Passkey registrada',
  description: 'Verifica la respuesta del authenticator y guarda la credencial (`credential_id`, `public_key`, `counter`) en BD.',
  security: [{ BearerAuth: [] }],
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({
            id: z.string().openapi({ example: 'credential-id-base64url' }),
            rawId: z.string(),
            response: z.object({
              clientDataJSON: z.string(),
              attestationObject: z.string(),
            }),
            type: z.literal('public-key'),
          }),
        },
      },
      required: true,
    },
  },
  responses: {
    201: { description: 'Passkey registrada', content: { 'application/json': { schema: MessageSchema } } },
    400: { description: 'Verificación fallida', content: { 'application/json': { schema: ErrorSchema } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/webauthn/login/options',
  tags: ['WebAuthn'],
  summary: 'Generar opciones de autenticación con Passkey',
  description: 'Genera un challenge para autenticar con una Passkey registrada previamente.',
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({
            email: z.string().email().optional().openapi({ example: 'usuario@ejemplo.com' }),
          }),
        },
      },
    },
  },
  responses: {
    200: {
      description: 'Opciones de autenticación — pasar a `navigator.credentials.get()`',
      content: {
        'application/json': {
          schema: z.object({
            challenge: z.string(),
            allowCredentials: z.array(z.object({ type: z.string(), id: z.string() })),
            userVerification: z.string(),
          }),
        },
      },
    },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/webauthn/login/verify',
  tags: ['WebAuthn'],
  summary: 'Verificar autenticación con Passkey',
  description: 'Verifica la firma biométrica, comprueba que el `counter` es mayor al guardado (anti-clonación) y emite AT + RT.',
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({
            id: z.string(),
            rawId: z.string(),
            response: z.object({
              authenticatorData: z.string(),
              clientDataJSON: z.string(),
              signature: z.string(),
            }),
            type: z.literal('public-key'),
          }),
        },
      },
      required: true,
    },
  },
  responses: {
    200: { description: 'Autenticado — AT + RT emitidos', content: { 'application/json': { schema: TokenResponseSchema } } },
    400: { description: 'Verificación fallida', content: { 'application/json': { schema: ErrorSchema } } },
    401: { description: 'Credencial no reconocida', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

void MessageSchema;
void TokenResponseSchema;

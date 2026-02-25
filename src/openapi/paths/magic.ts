import { z } from 'zod';
import { registry, ErrorSchema, MessageSchema, TokenResponseSchema } from '../registry';

registry.registerPath({
  method: 'post',
  path: '/api/v1/magic/request',
  tags: ['Magic Links'],
  summary: 'Solicitar magic link por email',
  description: `Envía un enlace de inicio de sesión único al email indicado (TTL 15 minutos).

Siempre responde 200 independientemente de si el email existe (anti-enumeración). En desarrollo, el enlace aparece en los logs del servidor.

Si el usuario ya tiene un magic link activo, se invalida y se genera uno nuevo.`,
  request: {
    body: {
      content: { 'application/json': { schema: z.object({ email: z.string().email().openapi({ example: 'usuario@ejemplo.com' }) }) } },
      required: true,
    },
  },
  responses: {
    200: {
      description: 'Email enviado (si el email existe)',
      content: { 'application/json': { schema: MessageSchema } },
    },
    429: { description: 'Límite excedido (10 req/hora)', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'get',
  path: '/api/v1/magic/verify',
  tags: ['Magic Links'],
  summary: 'Verificar magic link',
  description: 'Valida el token del enlace (one-time, TTL 15min) y emite AT + RT. Si el usuario tiene MFA activo, devuelve un `mfa_session_token` en lugar del AT definitivo.',
  request: {
    query: z.object({
      token: z.string().openapi({ example: 'a1b2c3d4e5f6...' }),
    }),
  },
  responses: {
    200: { description: 'Autenticado — AT + RT emitidos (o mfa_session_token si MFA activo)', content: { 'application/json': { schema: TokenResponseSchema } } },
    400: { description: 'Token inválido, ya usado o expirado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

void MessageSchema;
void TokenResponseSchema;

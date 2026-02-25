import { z } from 'zod';
import { registry, ErrorSchema, MessageSchema } from '../registry';

const sessionLoginBody = z.object({
  email: z.string().email().openapi({ example: 'usuario@ejemplo.com' }),
  password: z.string().openapi({ example: 'MiPassword123!' }),
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/session/login',
  tags: ['Session'],
  summary: 'Login con Session Token',
  description: 'Autentica y devuelve un Session Token opaco (32 bytes aleatorios). El token se almacena hasheado en BD. A diferencia de JWT, es stateful: cada request requiere una consulta a BD.',
  request: {
    body: { content: { 'application/json': { schema: sessionLoginBody } }, required: true },
  },
  responses: {
    200: {
      description: 'Login exitoso',
      content: {
        'application/json': {
          schema: z.object({
            sessionToken: z.string().openapi({ example: 'a1b2c3d4e5f6...' }),
            expiresAt: z.string().openapi({ example: '2025-01-22T10:00:00.000Z' }),
          }),
        },
      },
    },
    401: { description: 'Credenciales incorrectas', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/session/logout',
  tags: ['Session'],
  summary: 'Cerrar sesión (session token)',
  description: 'Invalida el session token. Requiere `Authorization: Bearer <sessionToken>`.',
  security: [{ BearerAuth: [] }],
  responses: {
    200: { description: 'Sesión cerrada', content: { 'application/json': { schema: MessageSchema } } },
    401: { description: 'Token inválido', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'get',
  path: '/api/v1/session/protected',
  tags: ['Session'],
  summary: 'Ruta protegida con session token',
  description: 'Demo de ruta que requiere session token válido.',
  security: [{ BearerAuth: [] }],
  responses: {
    200: {
      description: 'Acceso concedido',
      content: {
        'application/json': {
          schema: z.object({
            mensaje: z.string().openapi({ example: 'Acceso concedido con session token' }),
            userId: z.string().openapi({ example: 'uuid-del-usuario' }),
          }),
        },
      },
    },
    401: { description: 'Token inválido o expirado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

import { z } from 'zod';
import { registry, ErrorSchema, MessageSchema } from '../registry';

const ApiKeyRecord = z.object({
  id: z.string().uuid().openapi({ example: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' }),
  name: z.string().openapi({ example: 'Mi App de Producción' }),
  keyPrefix: z.string().openapi({ example: 'sk_live_' }),
  scopes: z.array(z.string()).openapi({ example: ['read:data', 'write:data'] }),
  createdAt: z.string().openapi({ example: '2025-01-15T10:00:00.000Z' }),
  lastUsedAt: z.string().nullable().openapi({ example: '2025-01-20T15:30:00.000Z' }),
  expiresAt: z.string().nullable().openapi({ example: null }),
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/keys',
  tags: ['API Keys'],
  summary: 'Crear API Key',
  description: `Genera una nueva API Key estilo Stripe (\`sk_live_<64chars>\`).

**⚠️ La key completa se muestra UNA SOLA VEZ** — solo en la respuesta de creación. Después solo se guarda el hash bcrypt. Si se pierde, hay que revocarla y crear una nueva.`,
  security: [{ BearerAuth: [] }],
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({
            name: z.string().openapi({ example: 'Mi App de Producción' }),
            scopes: z.array(z.string()).openapi({ example: ['read:data', 'write:data'] }),
            expiresAt: z.string().nullable().optional().openapi({ example: null }),
          }),
        },
      },
      required: true,
    },
  },
  responses: {
    201: {
      description: 'API Key creada — guardar la key completa ahora, no se mostrará de nuevo',
      content: {
        'application/json': {
          schema: z.object({
            key: z.string().openapi({ example: 'sk_live_a1b2c3d4e5f6g7h8i9j0...' }),
            id: z.string().uuid().openapi({ example: 'f47ac10b-...' }),
            name: z.string().openapi({ example: 'Mi App de Producción' }),
          }),
        },
      },
    },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'get',
  path: '/api/v1/keys',
  tags: ['API Keys'],
  summary: 'Listar API Keys',
  description: 'Lista las API Keys del usuario autenticado. La key completa nunca se devuelve, solo el prefijo visible.',
  security: [{ BearerAuth: [] }],
  responses: {
    200: {
      description: 'Lista de API Keys',
      content: { 'application/json': { schema: z.object({ keys: z.array(ApiKeyRecord) }) } },
    },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'delete',
  path: '/api/v1/keys/{id}',
  tags: ['API Keys'],
  summary: 'Revocar API Key',
  security: [{ BearerAuth: [] }],
  request: {
    params: z.object({ id: z.string().uuid().openapi({ example: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' }) }),
  },
  responses: {
    200: { description: 'API Key revocada', content: { 'application/json': { schema: MessageSchema } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
    404: { description: 'API Key no encontrada', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'get',
  path: '/api/v1/keys/protected',
  tags: ['API Keys'],
  summary: 'Ruta protegida con API Key + scope',
  description: 'Demo de endpoint que requiere API Key con scope `read:data`.',
  security: [{ ApiKeyAuth: [] }],
  responses: {
    200: {
      description: 'Acceso concedido',
      content: { 'application/json': { schema: z.object({ mensaje: z.string(), scopes: z.array(z.string()) }) } },
    },
    401: { description: 'API Key inválida', content: { 'application/json': { schema: ErrorSchema } } },
    403: { description: 'Scope insuficiente', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

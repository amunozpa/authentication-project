import { z } from 'zod';
import { registry, ErrorSchema, TokenResponseSchema, MessageSchema } from '../registry';

const SessionSchema = z.object({
  familyId: z.string().uuid().openapi({ example: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' }),
  createdAt: z.string().openapi({ example: '2025-01-15T10:00:00.000Z' }),
  lastUsedAt: z.string().openapi({ example: '2025-01-15T12:30:00.000Z' }),
  expiresAt: z.string().openapi({ example: '2025-01-22T10:00:00.000Z' }),
  ipHash: z.string().openapi({ example: 'sha256:abc123...' }),
  userAgent: z.string().openapi({ example: 'Mozilla/5.0 ...' }),
  kid: z.string().openapi({ example: 'key-uuid-abc' }),
  isCurrent: z.boolean().openapi({ example: true }),
});

// ── Refresh ───────────────────────────────────────────────────────────────────

registry.registerPath({
  method: 'post',
  path: '/api/v1/jwt/refresh',
  tags: ['JWT'],
  summary: 'Renovar Access Token',
  description: `Usa el Refresh Token de la cookie HttpOnly para emitir un nuevo Access Token y un nuevo Refresh Token.

**Family Tracking:** Si se detecta que el Refresh Token ya fue utilizado previamente (posible robo), se revocan **todas** las sesiones de la familia y se registra el evento \`TOKEN_ROBO_DETECTADO\`.`,
  responses: {
    200: {
      description: 'Nuevo par AT/RT emitido — nuevo RT en cookie HttpOnly',
      content: { 'application/json': { schema: TokenResponseSchema } },
    },
    401: { description: 'RT inválido, expirado o revocado', content: { 'application/json': { schema: ErrorSchema } } },
    429: { description: 'Demasiadas peticiones', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

// ── Logout all ────────────────────────────────────────────────────────────────

registry.registerPath({
  method: 'post',
  path: '/api/v1/jwt/logout-all',
  tags: ['JWT'],
  summary: 'Cerrar todas las sesiones',
  description: 'Revoca todas las familias de Refresh Tokens activas del usuario. Útil al detectar actividad sospechosa.',
  security: [{ BearerAuth: [] }],
  responses: {
    200: { description: 'Todas las sesiones revocadas', content: { 'application/json': { schema: MessageSchema } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

// ── Sessions ──────────────────────────────────────────────────────────────────

registry.registerPath({
  method: 'get',
  path: '/api/v1/jwt/sessions',
  tags: ['JWT'],
  summary: 'Listar sesiones activas',
  description: 'Devuelve todas las familias de Refresh Tokens activas. Las IPs se muestran hasheadas (GDPR). La sesión actual se indica con `isCurrent: true`.',
  security: [{ BearerAuth: [] }],
  request: {
    query: z.object({
      page: z.string().optional().openapi({ example: '1' }),
      limit: z.string().optional().openapi({ example: '20' }),
    }),
  },
  responses: {
    200: {
      description: 'Lista de sesiones activas',
      content: {
        'application/json': {
          schema: z.object({
            sesiones: z.array(SessionSchema),
            total: z.number().openapi({ example: 3 }),
          }),
        },
      },
    },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

void MessageSchema;

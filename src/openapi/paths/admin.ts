import { z } from 'zod';
import { registry, ErrorSchema, MessageSchema } from '../registry';

const UserAdminRecord = z.object({
  id: z.string().uuid().openapi({ example: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' }),
  email: z.string().email().openapi({ example: 'usuario@ejemplo.com' }),
  roles: z.array(z.string()).openapi({ example: ['user'] }),
  emailVerified: z.boolean(),
  lockedUntil: z.string().nullable().openapi({ example: null }),
  createdAt: z.string(),
  deletedAt: z.string().nullable(),
});

const JwtKeyRecord = z.object({
  id: z.string().uuid(),
  active: z.boolean().openapi({ example: true }),
  createdAt: z.string(),
  retiredAt: z.string().nullable(),
});

const AnomalyRecord = z.object({
  id: z.string().uuid(),
  type: z.string().openapi({ example: 'ANOMALIA_FUERZA_BRUTA' }),
  userId: z.string().nullable(),
  ipHash: z.string().nullable(),
  metadata: z.record(z.string(), z.unknown()),
  createdAt: z.string(),
});

// ── Users ─────────────────────────────────────────────────────────────────────

registry.registerPath({
  method: 'get',
  path: '/api/v1/admin/users',
  tags: ['Admin'],
  summary: 'Listar usuarios (paginado)',
  description: 'Lista todos los usuarios del sistema con filtros opcionales. Solo accesible para admins.',
  security: [{ BearerAuth: [] }],
  request: {
    query: z.object({
      page: z.string().optional().openapi({ example: '1' }),
      limit: z.string().optional().openapi({ example: '20' }),
      role: z.string().optional().openapi({ example: 'admin' }),
      verified: z.string().optional().openapi({ example: 'true' }),
    }),
  },
  responses: {
    200: {
      description: 'Lista paginada de usuarios',
      content: {
        'application/json': {
          schema: z.object({
            users: z.array(UserAdminRecord),
            total: z.number(),
            page: z.number(),
            hasMore: z.boolean(),
          }),
        },
      },
    },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
    403: { description: 'No es admin', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/admin/users/{id}/unlock',
  tags: ['Admin'],
  summary: 'Desbloquear cuenta',
  description: 'Desbloquea una cuenta bloqueada por account lockout (5 intentos fallidos).',
  security: [{ BearerAuth: [] }],
  request: {
    params: z.object({ id: z.string().uuid().openapi({ example: 'f47ac10b-...' }) }),
  },
  responses: {
    200: { description: 'Cuenta desbloqueada', content: { 'application/json': { schema: MessageSchema } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
    403: { description: 'No es admin', content: { 'application/json': { schema: ErrorSchema } } },
    404: { description: 'Usuario no encontrado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'delete',
  path: '/api/v1/admin/users/{id}',
  tags: ['Admin'],
  summary: 'Eliminar cuenta (GDPR — iniciado por admin)',
  security: [{ BearerAuth: [] }],
  request: {
    params: z.object({ id: z.string().uuid().openapi({ example: 'f47ac10b-...' }) }),
  },
  responses: {
    200: { description: 'Cuenta eliminada', content: { 'application/json': { schema: MessageSchema } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
    403: { description: 'No es admin', content: { 'application/json': { schema: ErrorSchema } } },
    404: { description: 'Usuario no encontrado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

// ── JWT Keys ──────────────────────────────────────────────────────────────────

registry.registerPath({
  method: 'get',
  path: '/api/v1/admin/keys',
  tags: ['Admin'],
  summary: 'Listar claves JWT activas',
  security: [{ BearerAuth: [] }],
  responses: {
    200: {
      description: 'Claves de firma JWT',
      content: { 'application/json': { schema: z.object({ keys: z.array(JwtKeyRecord) }) } },
    },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
    403: { description: 'No es admin', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/admin/keys/rotate',
  tags: ['Admin'],
  summary: 'Rotar clave JWT',
  description: 'Crea una nueva clave activa y retira la anterior. Los tokens firmados con la clave retirada siguen siendo verificables hasta que expiren naturalmente.',
  security: [{ BearerAuth: [] }],
  responses: {
    200: {
      description: 'Clave rotada — nueva clave activa',
      content: { 'application/json': { schema: z.object({ mensaje: z.string(), newKeyId: z.string() }) } },
    },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
    403: { description: 'No es admin o no está en entorno dev', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

// ── Anomalies ─────────────────────────────────────────────────────────────────

registry.registerPath({
  method: 'get',
  path: '/api/v1/admin/anomalies',
  tags: ['Admin'],
  summary: 'Listar anomalías detectadas',
  description: `Lista eventos de seguridad anómalos detectados por el sistema:
- \`ANOMALIA_CREDENTIAL_STUFFING\` — >10 logins fallidos desde IPs distintas en 5 min
- \`ANOMALIA_FUERZA_BRUTA\` — >5 logins fallidos del mismo usuario en 10 min
- \`ANOMALIA_SESION_INUSUAL\` — misma familia desde >2 IPs distintas en 1 hora`,
  security: [{ BearerAuth: [] }],
  request: {
    query: z.object({
      type: z.string().optional().openapi({ example: 'ANOMALIA_FUERZA_BRUTA' }),
      from: z.string().optional().openapi({ example: '2025-01-01T00:00:00.000Z' }),
      to: z.string().optional().openapi({ example: '2025-12-31T23:59:59.000Z' }),
      page: z.string().optional().openapi({ example: '1' }),
    }),
  },
  responses: {
    200: {
      description: 'Lista de anomalías',
      content: {
        'application/json': {
          schema: z.object({
            anomalies: z.array(AnomalyRecord),
            total: z.number(),
            hasMore: z.boolean(),
          }),
        },
      },
    },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
    403: { description: 'No es admin', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

import { z } from 'zod';
import { registry, ErrorSchema, MessageSchema } from '../registry';

const UserProfileSchema = z.object({
  id: z.string().uuid().openapi({ example: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' }),
  email: z.string().email().openapi({ example: 'usuario@ejemplo.com' }),
  roles: z.array(z.string()).openapi({ example: ['user'] }),
  emailVerified: z.boolean().openapi({ example: true }),
  mfaEnabled: z.boolean().openapi({ example: false }),
  createdAt: z.string().openapi({ example: '2025-01-15T10:00:00.000Z' }),
});

const LinkedAccountSchema = z.object({
  provider: z.enum(['github', 'google']).openapi({ example: 'github' }),
  providerEmail: z.string().email().openapi({ example: 'usuario@gmail.com' }),
  linkedAt: z.string().openapi({ example: '2025-01-15T10:00:00.000Z' }),
});

registry.registerPath({
  method: 'get',
  path: '/api/v1/user/me',
  tags: ['User'],
  summary: 'Perfil del usuario autenticado',
  security: [{ BearerAuth: [] }],
  responses: {
    200: {
      description: 'Perfil del usuario',
      content: { 'application/json': { schema: UserProfileSchema } },
    },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'get',
  path: '/api/v1/user/linked-accounts',
  tags: ['User'],
  summary: 'Listar cuentas OAuth vinculadas',
  security: [{ BearerAuth: [] }],
  responses: {
    200: {
      description: 'Cuentas vinculadas',
      content: { 'application/json': { schema: z.object({ accounts: z.array(LinkedAccountSchema) }) } },
    },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'get',
  path: '/api/v1/user/link/{provider}',
  tags: ['User'],
  summary: 'Vincular cuenta OAuth',
  description: 'Inicia el flujo OAuth para vincular una cuenta adicional (GitHub o Google) al usuario autenticado.',
  security: [{ BearerAuth: [] }],
  request: {
    params: z.object({
      provider: z.enum(['github', 'google']).openapi({ example: 'github' }),
    }),
  },
  responses: {
    302: { description: 'Redirección al proveedor OAuth' },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'get',
  path: '/api/v1/user/security',
  tags: ['User'],
  summary: 'Panel de seguridad del usuario',
  description: 'Información de seguridad: sesiones activas, MFA, cuentas vinculadas, API Keys activas.',
  security: [{ BearerAuth: [] }],
  responses: {
    200: {
      description: 'Información de seguridad',
      content: {
        'application/json': {
          schema: z.object({
            mfaEnabled: z.boolean(),
            activeSessions: z.number().openapi({ example: 2 }),
            linkedProviders: z.array(z.string()).openapi({ example: ['github'] }),
            activeApiKeys: z.number().openapi({ example: 1 }),
          }),
        },
      },
    },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/user/change-password',
  tags: ['User'],
  summary: 'Cambiar contraseña',
  description: 'Cambia la contraseña del usuario autenticado. Requiere la contraseña actual. Revoca todas las sesiones excepto la actual.',
  security: [{ BearerAuth: [] }],
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({
            currentPassword: z.string().openapi({ example: 'PasswordActual123!' }),
            newPassword: z.string().min(8).openapi({ example: 'NuevaPassword456!' }),
          }),
        },
      },
      required: true,
    },
  },
  responses: {
    200: { description: 'Contraseña actualizada', content: { 'application/json': { schema: MessageSchema } } },
    400: { description: 'Contraseña actual incorrecta o nueva contraseña débil', content: { 'application/json': { schema: ErrorSchema } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'delete',
  path: '/api/v1/user/me',
  tags: ['User'],
  summary: 'Eliminar cuenta (GDPR)',
  description: 'Elimina permanentemente la cuenta del usuario. Soft-delete en `users`, hard-delete en sesiones, tokens, credenciales WebAuthn, MFA y API Keys. Los audit logs se anonimizan. Requiere step-up si MFA está activo.',
  security: [{ BearerAuth: [] }],
  responses: {
    200: { description: 'Cuenta eliminada', content: { 'application/json': { schema: MessageSchema } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
    403: { description: 'Step-up requerido', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

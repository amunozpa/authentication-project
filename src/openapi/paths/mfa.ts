import { z } from 'zod';
import { registry, ErrorSchema, MessageSchema, TokenResponseSchema } from '../registry';

registry.registerPath({
  method: 'get',
  path: '/api/v1/mfa/status',
  tags: ['MFA'],
  summary: 'Estado de MFA del usuario',
  security: [{ BearerAuth: [] }],
  responses: {
    200: {
      description: 'Estado MFA',
      content: {
        'application/json': {
          schema: z.object({
            mfaEnabled: z.boolean().openapi({ example: false }),
            recoveryCodesRemaining: z.number().openapi({ example: 8 }),
          }),
        },
      },
    },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/mfa/setup',
  tags: ['MFA'],
  summary: 'Generar secreto TOTP y QR',
  description: 'Genera un secreto TOTP y devuelve un QR code en base64 compatible con Google Authenticator, Authy, etc. El MFA no queda activo hasta confirmar con `POST /api/v1/mfa/enable`.',
  security: [{ BearerAuth: [] }],
  responses: {
    200: {
      description: 'QR y secreto generados',
      content: {
        'application/json': {
          schema: z.object({
            secret: z.string().openapi({ example: 'JBSWY3DPEHPK3PXP' }),
            qrCodeDataUrl: z.string().openapi({ example: 'data:image/png;base64,...' }),
            otpAuthUri: z.string().openapi({ example: 'otpauth://totp/AuthLab:usuario@ejemplo.com?secret=...' }),
          }),
        },
      },
    },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/mfa/enable',
  tags: ['MFA'],
  summary: 'Activar TOTP y generar recovery codes',
  description: `Verifica el primer OTP para confirmar que el setup fue correcto, activa MFA y genera **8 recovery codes de un solo uso**.

**⚠️ Los recovery codes se muestran UNA SOLA VEZ** — guardarlos en un lugar seguro.`,
  security: [{ BearerAuth: [] }],
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({
            secret: z.string().openapi({ example: 'JBSWY3DPEHPK3PXP' }),
            totp_code: z.string().length(6).openapi({ example: '123456' }),
          }),
        },
      },
      required: true,
    },
  },
  responses: {
    200: {
      description: 'MFA activado — recovery codes de un solo uso',
      content: {
        'application/json': {
          schema: z.object({
            mensaje: z.string(),
            recoveryCodes: z.array(z.string()).openapi({ example: ['XXXX-YYYY', 'AAAA-BBBB'] }),
          }),
        },
      },
    },
    400: { description: 'Código TOTP inválido', content: { 'application/json': { schema: ErrorSchema } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'delete',
  path: '/api/v1/mfa/disable',
  tags: ['MFA'],
  summary: 'Desactivar MFA',
  security: [{ BearerAuth: [] }],
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({
            totp_code: z.string().length(6).openapi({ example: '123456' }),
          }),
        },
      },
      required: true,
    },
  },
  responses: {
    200: { description: 'MFA desactivado', content: { 'application/json': { schema: MessageSchema } } },
    400: { description: 'Código TOTP inválido', content: { 'application/json': { schema: ErrorSchema } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/mfa/verify',
  tags: ['MFA'],
  summary: 'Verificar TOTP (segundo paso del login)',
  description: 'Segundo paso del login cuando MFA está activo. Recibe el `mfa_session_token` del primer paso y el código TOTP. Emite AT + RT definitivos.',
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({
            mfa_session_token: z.string().openapi({ example: 'eyJhbGciOiJIUzI1NiJ9...' }),
            totp_code: z.string().length(6).openapi({ example: '123456' }),
          }),
        },
      },
      required: true,
    },
  },
  responses: {
    200: { description: 'Autenticado — AT + RT emitidos', content: { 'application/json': { schema: TokenResponseSchema } } },
    400: { description: 'Código TOTP inválido o token MFA expirado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/mfa/recovery',
  tags: ['MFA'],
  summary: 'Usar recovery code',
  description: 'Autentica usando uno de los 8 recovery codes de un solo uso. El código se marca como usado tras emplearlo.',
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({
            mfa_session_token: z.string().openapi({ example: 'eyJhbGciOiJIUzI1NiJ9...' }),
            recovery_code: z.string().openapi({ example: 'XXXX-YYYY' }),
          }),
        },
      },
      required: true,
    },
  },
  responses: {
    200: { description: 'Autenticado con recovery code', content: { 'application/json': { schema: TokenResponseSchema } } },
    400: { description: 'Recovery code inválido o ya usado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/mfa/step-up',
  tags: ['MFA'],
  summary: 'Step-up authentication (elevar privilegios)',
  description: `Verifica un OTP fresco y devuelve un **step-up token** válido por 10 minutos.

Necesario para acciones sensibles como cambio de contraseña o eliminación de cuenta, incluso si ya hay sesión activa.`,
  security: [{ BearerAuth: [] }],
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({
            totp_code: z.string().length(6).openapi({ example: '123456' }),
          }),
        },
      },
      required: true,
    },
  },
  responses: {
    200: {
      description: 'Step-up token emitido (válido 10 minutos)',
      content: {
        'application/json': {
          schema: z.object({
            stepUpToken: z.string().openapi({ example: 'eyJhbGciOiJIUzI1NiJ9...' }),
            expiresIn: z.number().openapi({ example: 600 }),
          }),
        },
      },
    },
    400: { description: 'Código TOTP inválido', content: { 'application/json': { schema: ErrorSchema } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'get',
  path: '/api/v1/mfa/protected',
  tags: ['MFA'],
  summary: 'Ruta protegida con step-up',
  description: 'Demo de endpoint que requiere un step-up token válido además del Access Token normal.',
  security: [{ BearerAuth: [] }],
  responses: {
    200: { description: 'Acceso concedido con step-up', content: { 'application/json': { schema: z.object({ mensaje: z.string() }) } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
    403: { description: 'Step-up requerido o expirado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

void MessageSchema;
void TokenResponseSchema;

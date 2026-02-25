import { z } from 'zod';
import { registry, ErrorSchema, MessageSchema, TokenResponseSchema } from '../registry';

const registerBody = z.object({
  email: z.string().email().openapi({ example: 'usuario@ejemplo.com' }),
  password: z.string().min(8).max(128).openapi({ example: 'MiPassword123!' }),
});

const loginBody = z.object({
  email: z.string().email().openapi({ example: 'usuario@ejemplo.com' }),
  password: z.string().openapi({ example: 'MiPassword123!' }),
});

const LoginResponseSchema = z.union([
  z.object({
    accessToken: z.string().openapi({ example: 'eyJhbGciOiJIUzI1NiJ9...' }),
    expiresIn: z.number().openapi({ example: 900 }),
  }).openapi({ description: 'Login exitoso — RT en cookie HttpOnly' }),
  z.object({
    mfa_required: z.literal(true),
    mfa_session_token: z.string().openapi({ example: 'eyJhbGciOiJIUzI1NiJ9...' }),
  }).openapi({ description: 'Usuario tiene MFA activo — continuar en POST /api/v1/mfa/verify' }),
]);

// ── Register ──────────────────────────────────────────────────────────────────

registry.registerPath({
  method: 'post',
  path: '/api/v1/auth/register',
  tags: ['Auth'],
  summary: 'Registrar nuevo usuario',
  description: 'Crea una cuenta nueva. Envía un email de verificación (en dev aparece en los logs del servidor). La cuenta queda inactiva hasta verificar el email.',
  request: {
    body: { content: { 'application/json': { schema: registerBody } }, required: true },
  },
  responses: {
    201: {
      description: 'Usuario creado — email de verificación enviado',
      content: { 'application/json': { schema: MessageSchema } },
    },
    400: { description: 'Datos inválidos', content: { 'application/json': { schema: ErrorSchema } } },
    409: { description: 'El email ya está registrado', content: { 'application/json': { schema: ErrorSchema } } },
    429: { description: 'Demasiadas peticiones', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

// ── Verify email ──────────────────────────────────────────────────────────────

registry.registerPath({
  method: 'get',
  path: '/api/v1/auth/verify-email',
  tags: ['Auth'],
  summary: 'Verificar email con token',
  description: 'Activa la cuenta usando el token recibido por email. El token es de un solo uso y expira en 24 horas.',
  request: {
    query: z.object({
      token: z.string().openapi({ example: 'a1b2c3d4e5f6...' }),
    }),
  },
  responses: {
    200: {
      description: 'Email verificado — cuenta activada',
      content: { 'application/json': { schema: MessageSchema } },
    },
    400: { description: 'Token inválido o expirado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

// ── Login ─────────────────────────────────────────────────────────────────────

registry.registerPath({
  method: 'post',
  path: '/api/v1/auth/login',
  tags: ['Auth'],
  summary: 'Iniciar sesión',
  description: `Autentica con email y contraseña. Emite un Access Token (JWT, 15min) en el body y un Refresh Token en cookie HttpOnly.

Si el usuario tiene MFA activo, devuelve \`mfa_required: true\` y un \`mfa_session_token\` temporal (5min). Continuar con \`POST /api/v1/mfa/verify\`.

**Account lockout:** 5 intentos fallidos bloquean la cuenta por 30 minutos.`,
  request: {
    body: { content: { 'application/json': { schema: loginBody } }, required: true },
  },
  responses: {
    200: {
      description: 'Login exitoso o MFA requerido',
      content: { 'application/json': { schema: LoginResponseSchema } },
    },
    400: { description: 'Datos inválidos', content: { 'application/json': { schema: ErrorSchema } } },
    401: { description: 'Credenciales incorrectas', content: { 'application/json': { schema: ErrorSchema } } },
    403: { description: 'Email no verificado', content: { 'application/json': { schema: ErrorSchema } } },
    423: { description: 'Cuenta bloqueada por demasiados intentos', content: { 'application/json': { schema: ErrorSchema } } },
    429: { description: 'Demasiadas peticiones', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

// ── Logout ────────────────────────────────────────────────────────────────────

registry.registerPath({
  method: 'post',
  path: '/api/v1/auth/logout',
  tags: ['Auth'],
  summary: 'Cerrar sesión',
  description: 'Revoca el Refresh Token actual y limpia la cookie. El Access Token sigue siendo válido hasta su expiración natural (15min).',
  security: [{ BearerAuth: [] }],
  responses: {
    200: { description: 'Sesión cerrada', content: { 'application/json': { schema: MessageSchema } } },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

// ── Forgot password ───────────────────────────────────────────────────────────

registry.registerPath({
  method: 'post',
  path: '/api/v1/auth/forgot-password',
  tags: ['Auth'],
  summary: 'Solicitar reset de contraseña',
  description: 'Envía un email con enlace de reset (TTL 1 hora). Responde siempre con 200 para no revelar si el email existe (anti-enumeración). Solo funciona para cuentas con email verificado.',
  request: {
    body: {
      content: { 'application/json': { schema: z.object({ email: z.string().email().openapi({ example: 'usuario@ejemplo.com' }) }) } },
      required: true,
    },
  },
  responses: {
    200: { description: 'Email enviado (si el email existe y está verificado)', content: { 'application/json': { schema: MessageSchema } } },
    429: { description: 'Límite excedido (10 req/hora)', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

// ── Reset password ────────────────────────────────────────────────────────────

registry.registerPath({
  method: 'post',
  path: '/api/v1/auth/reset-password',
  tags: ['Auth'],
  summary: 'Restablecer contraseña',
  description: 'Cambia la contraseña usando el token del email. El token es de un solo uso. Revoca **todas** las sesiones activas del usuario como medida de seguridad.',
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({
            token: z.string().openapi({ example: 'a1b2c3d4...' }),
            password: z.string().min(8).openapi({ example: 'NuevaPassword123!' }),
          }),
        },
      },
      required: true,
    },
  },
  responses: {
    200: { description: 'Contraseña restablecida — todas las sesiones revocadas', content: { 'application/json': { schema: MessageSchema } } },
    400: { description: 'Token inválido, expirado o contraseña débil', content: { 'application/json': { schema: ErrorSchema } } },
    429: { description: 'Límite excedido', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

// Suppress unused import warning
void TokenResponseSchema;

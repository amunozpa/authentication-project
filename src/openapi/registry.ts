/**
 * OpenAPI Registry — base compartida para todos los módulos de paths.
 * extendZodWithOpenApi se llama UNA SOLA VEZ aquí.
 */
import { extendZodWithOpenApi, OpenAPIRegistry } from '@asteasolutions/zod-to-openapi';
import { z } from 'zod';

extendZodWithOpenApi(z);

export const registry = new OpenAPIRegistry();

// ── Schemas comunes ───────────────────────────────────────────────────────────

export const ErrorSchema = registry.register(
  'Error',
  z.object({
    error: z.string().openapi({ example: 'Token inválido' }),
    code: z.string().openapi({ example: 'TOKEN_INVALIDO' }),
    correlationId: z.string().uuid().optional().openapi({ example: 'f47ac10b-58cc-4372-a567-0e02b2c3d479' }),
  }).openapi('Error'),
);

export const MessageSchema = registry.register(
  'Message',
  z.object({
    mensaje: z.string().openapi({ example: 'Operación completada correctamente' }),
  }).openapi('Message'),
);

export const TokenResponseSchema = registry.register(
  'TokenResponse',
  z.object({
    accessToken: z.string().openapi({ example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' }),
    expiresIn: z.number().openapi({ example: 900, description: 'Segundos hasta expiración' }),
  }).openapi('TokenResponse'),
);

export const PaginatedMetaSchema = z.object({
  total: z.number().openapi({ example: 42 }),
  page: z.number().openapi({ example: 1 }),
  limit: z.number().openapi({ example: 20 }),
  hasMore: z.boolean().openapi({ example: true }),
});

// ── Security schemes ──────────────────────────────────────────────────────────

registry.registerComponent('securitySchemes', 'BearerAuth', {
  type: 'http',
  scheme: 'bearer',
  bearerFormat: 'JWT',
  description: 'Access Token JWT — obtener con `POST /api/v1/auth/login`',
});

registry.registerComponent('securitySchemes', 'BasicAuth', {
  type: 'http',
  scheme: 'basic',
  description: 'HTTP Basic Auth — `Authorization: Basic base64(email:password)`',
});

registry.registerComponent('securitySchemes', 'ApiKeyAuth', {
  type: 'apiKey',
  in: 'header',
  name: 'Authorization',
  description: 'API Key — `Authorization: Bearer sk_live_...`',
});

registry.registerComponent('securitySchemes', 'DPoP', {
  type: 'http',
  scheme: 'DPoP',
  description: 'Token DPoP bound a clave pública ECDSA P-256. Requiere también header `DPoP: <proof_jwt>`',
});

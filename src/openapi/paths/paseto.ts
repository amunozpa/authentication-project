import { z } from 'zod';
import { registry, ErrorSchema } from '../registry';

registry.registerPath({
  method: 'get',
  path: '/api/v1/paseto/info',
  tags: ['PASETO'],
  summary: 'Información sobre PASETO v4',
  description: 'Devuelve la clave pública Ed25519 del servidor y una explicación de las ventajas de PASETO v4 sobre JWT.',
  responses: {
    200: {
      description: 'Info PASETO',
      content: {
        'application/json': {
          schema: z.object({
            publicKey: z.string().openapi({ example: 'base64url-encoded-public-key' }),
            algorithm: z.literal('Ed25519').openapi({ example: 'Ed25519' }),
            version: z.literal('v4.public').openapi({ example: 'v4.public' }),
            advantages: z.array(z.string()),
          }),
        },
      },
    },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/paseto/sign',
  tags: ['PASETO'],
  summary: 'Firmar payload con PASETO v4',
  description: 'Firma un payload arbitrario con la clave privada Ed25519 del servidor y devuelve un token PASETO v4.public.',
  security: [{ BearerAuth: [] }],
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({
            payload: z.record(z.string(), z.unknown()).openapi({ example: { sub: 'usuario-id', rol: 'admin' } }),
            ttl_seconds: z.number().int().min(1).max(86400).openapi({ example: 3600 }),
          }),
        },
      },
      required: true,
    },
  },
  responses: {
    200: {
      description: 'Token PASETO v4.public firmado',
      content: {
        'application/json': {
          schema: z.object({
            token: z.string().openapi({ example: 'v4.public.eyJzdWIiOiJ1c3VhcmlvLWlkIn0...' }),
            expiresAt: z.string().openapi({ example: '2025-01-15T11:00:00.000Z' }),
          }),
        },
      },
    },
    401: { description: 'No autenticado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/paseto/verify',
  tags: ['PASETO'],
  summary: 'Verificar token PASETO v4',
  description: 'Verifica la firma del token con la clave pública Ed25519. Endpoint público — cualquiera puede verificar tokens.',
  request: {
    body: {
      content: {
        'application/json': {
          schema: z.object({
            token: z.string().openapi({ example: 'v4.public.eyJzdWIiOiJ1c3VhcmlvLWlkIn0...' }),
          }),
        },
      },
      required: true,
    },
  },
  responses: {
    200: {
      description: 'Token válido — payload decodificado',
      content: {
        'application/json': {
          schema: z.object({
            valid: z.literal(true),
            payload: z.record(z.string(), z.unknown()).openapi({ example: { sub: 'usuario-id', exp: 1705312800 } }),
          }),
        },
      },
    },
    400: { description: 'Token inválido o expirado', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

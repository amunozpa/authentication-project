import { z } from 'zod';
import { registry, ErrorSchema } from '../registry';

registry.registerPath({
  method: 'get',
  path: '/api/v1/dpop/info',
  tags: ['DPoP'],
  summary: 'Información sobre DPoP (RFC 9449)',
  description: 'Documentación sobre el flujo DPoP y cómo construir el proof JWT.',
  responses: {
    200: {
      description: 'Info DPoP',
      content: {
        'application/json': {
          schema: z.object({
            description: z.string(),
            proofStructure: z.object({
              header: z.object({ alg: z.string(), typ: z.string(), jwk: z.object({}) }),
              payload: z.object({ htm: z.string(), htu: z.string(), iat: z.number(), jti: z.string() }),
            }),
            steps: z.array(z.string()),
          }),
        },
      },
    },
  },
});

registry.registerPath({
  method: 'post',
  path: '/api/v1/dpop/token',
  tags: ['DPoP'],
  summary: 'Emitir token DPoP',
  description: `Autentica con email/contraseña y emite un Access Token **vinculado a la clave pública ECDSA P-256** del cliente (cnf.jkt = JWK thumbprint).

Requiere header \`DPoP: <proof_jwt>\` donde el proof contiene la clave pública JWK del cliente.

**Prevención de replay:** el \`jti\` del proof debe ser único (TTL 60s en cache).`,
  request: {
    headers: z.object({
      DPoP: z.string().openapi({ example: 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand...' }),
    }),
    body: {
      content: {
        'application/json': {
          schema: z.object({
            email: z.string().email().openapi({ example: 'usuario@ejemplo.com' }),
            password: z.string().openapi({ example: 'MiPassword123!' }),
          }),
        },
      },
      required: true,
    },
  },
  responses: {
    200: {
      description: 'Token DPoP emitido — bound a la clave pública del cliente',
      content: {
        'application/json': {
          schema: z.object({
            accessToken: z.string().openapi({ example: 'eyJhbGciOiJIUzI1NiJ9...' }),
            tokenType: z.literal('DPoP').openapi({ example: 'DPoP' }),
            expiresIn: z.number().openapi({ example: 900 }),
          }),
        },
      },
    },
    400: { description: 'DPoP proof inválido (alg, typ, iat, jti, htm, htu)', content: { 'application/json': { schema: ErrorSchema } } },
    401: { description: 'Credenciales incorrectas', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

registry.registerPath({
  method: 'get',
  path: '/api/v1/dpop/protected',
  tags: ['DPoP'],
  summary: 'Ruta protegida con DPoP binding',
  description: `Verifica que el token DPoP pertenece al cliente que lo presenta.

Requiere:
- \`Authorization: DPoP <accessToken>\`
- Header \`DPoP: <proof_jwt>\` firmado con la misma clave privada usada para obtener el token

Si se roba el token y se usa sin el proof (o con una clave diferente) → 401.`,
  security: [{ DPoP: [] }],
  request: {
    headers: z.object({
      DPoP: z.string().openapi({ example: 'eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand...' }),
    }),
  },
  responses: {
    200: {
      description: 'Acceso concedido — token y clave pública coinciden',
      content: { 'application/json': { schema: z.object({ mensaje: z.string(), jkt: z.string() }) } },
    },
    401: { description: 'DPoP proof inválido, expirado, replay detectado o clave no coincide', content: { 'application/json': { schema: ErrorSchema } } },
  },
});

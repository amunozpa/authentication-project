import { z } from 'zod';
import { registry, ErrorSchema } from '../registry';

registry.registerPath({
  method: 'get',
  path: '/api/v1/ratelimit/info',
  tags: ['Rate Limits'],
  summary: 'Información sobre rate limiting',
  description: 'Documenta todos los limitadores activos y sus configuraciones.',
  responses: {
    200: {
      description: 'Configuración de rate limiters',
      content: {
        'application/json': {
          schema: z.object({
            limiters: z.array(z.object({
              name: z.string().openapi({ example: 'authLimiter' }),
              limit: z.number().openapi({ example: 20 }),
              windowMs: z.number().openapi({ example: 900000 }),
              appliedTo: z.array(z.string()).openapi({ example: ['/api/v1/auth/login', '/api/v1/auth/register'] }),
            })),
            note: z.string().openapi({ example: 'Todos los limitadores son no-op en NODE_ENV=test' }),
          }),
        },
      },
    },
  },
});

registry.registerPath({
  method: 'get',
  path: '/api/v1/ratelimit/test',
  tags: ['Rate Limits'],
  summary: 'Demo de rate limiting (3 req/min)',
  description: 'Endpoint con un limitador muy estricto (3 req/min) para demostrar el comportamiento de rate limiting y las cabeceras `RateLimit-*`.',
  responses: {
    200: {
      description: 'Request permitido',
      content: { 'application/json': { schema: z.object({ mensaje: z.string(), requestNumber: z.number() }) } },
    },
    429: {
      description: 'Rate limit excedido — ver cabeceras `RateLimit-*` y `Retry-After`',
      content: { 'application/json': { schema: ErrorSchema } },
    },
  },
});

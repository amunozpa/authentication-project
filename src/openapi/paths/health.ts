import { z } from 'zod';
import { registry } from '../registry';

registry.registerPath({
  method: 'get',
  path: '/api/v1/health',
  tags: ['Health'],
  summary: 'Estado del servidor',
  description: 'Endpoint de health check para Docker, load balancers y monitoreo externo.',
  responses: {
    200: {
      description: 'Servidor activo',
      content: {
        'application/json': {
          schema: z.object({
            estado: z.literal('activo').openapi({ example: 'activo' }),
            timestamp: z.string().openapi({ example: '2025-01-15T10:30:00.000Z' }),
            version: z.string().openapi({ example: '1.0.0' }),
          }),
        },
      },
    },
  },
});
